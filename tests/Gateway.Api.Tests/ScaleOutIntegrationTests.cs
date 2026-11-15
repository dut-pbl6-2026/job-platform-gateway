using System.Net;
using Gateway.Api.RateLimiting;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Gateway.Api.Tests;

/// <summary>Rate-limit store that records keys and can be told to fail, wrapping the in-memory counter.</summary>
internal sealed class RecordingRateLimitStore : IRateLimitStore
{
    private readonly InMemoryRateLimitStore _inner = new();
    private readonly List<string> _keys = [];

    public Exception? FailWith { get; set; }

    public IReadOnlyList<string> Keys
    {
        get { lock (_keys) return _keys.ToList(); }
    }

    public Task<RateLimitCounter> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default)
    {
        lock (_keys) _keys.Add(key);
        if (FailWith is not null)
            throw FailWith;
        return _inner.IncrementAsync(key, window, ct);
    }
}

public class ScaleOutIntegrationTests
{
    private const string ProxyPeer = "10.0.0.5";

    private static WebApplicationFactory<Program> WithStore(WebApplicationFactory<Program> factory, IRateLimitStore store) =>
        factory.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
        {
            s.RemoveAll<IRateLimitStore>();
            s.AddSingleton(store);
        }));

    private static Task SendFrom(WebApplicationFactory<Program> factory, string peer, string? forwardedFor)
    {
        return factory.Server.SendAsync(ctx =>
        {
            ctx.Connection.RemoteIpAddress = IPAddress.Parse(peer);
            ctx.Request.Method = HttpMethods.Get;
            ctx.Request.Path = "/";
            if (forwardedFor is not null)
                ctx.Request.Headers["X-Forwarded-For"] = forwardedFor;
        });
    }

    [Fact]
    public async Task UntrustedPeer_ForwardedForIsIgnored()
    {
        var store = new RecordingRateLimitStore();
        using var factory = WithStore(new GatewayTestFactory(), store);

        await SendFrom(factory, peer: ProxyPeer, forwardedFor: "203.0.113.7");

        // ForwardedHeaders is not configured, so the framework trusts only loopback: the peer is the client.
        Assert.Equal([ProxyPeer], store.Keys);
    }

    [Fact]
    public async Task TrustedProxy_ForwardedClientAddressIsCounted()
    {
        var store = new RecordingRateLimitStore();
        using var factory = WithStore(
            new GatewayTestFactory().WithWebHostBuilder(b => b.UseSetting("ForwardedHeaders:KnownNetworks", "10.0.0.0/8")),
            store);

        // The proxy appends the real client as the right-most entry; a client-supplied prefix must not count.
        await SendFrom(factory, peer: ProxyPeer, forwardedFor: "1.2.3.4, 203.0.113.7");

        Assert.Equal(["203.0.113.7"], store.Keys);
    }

    [Fact]
    public async Task TrustedProxyNetwork_DoesNotTrustOtherPeers()
    {
        var store = new RecordingRateLimitStore();
        using var factory = WithStore(
            new GatewayTestFactory().WithWebHostBuilder(b => b.UseSetting("ForwardedHeaders:KnownNetworks", "192.168.50.0/24")),
            store);

        await SendFrom(factory, peer: ProxyPeer, forwardedFor: "203.0.113.7");

        Assert.Equal([ProxyPeer], store.Keys);
    }

    [Fact]
    public async Task TwoInstances_ShareOneLimit()
    {
        var shared = new InMemoryRateLimitStore();
        var settings = new Dictionary<string, string?> { ["GATEWAY_RATE_LIMIT_PER_MINUTE"] = "2" };

        using var replicaA = WithStore(new GatewayTestFactory().WithWebHostBuilder(b => ApplySettings(b, settings)), shared);
        using var replicaB = WithStore(new GatewayTestFactory().WithWebHostBuilder(b => ApplySettings(b, settings)), shared);
        var clientA = replicaA.CreateClient();
        var clientB = replicaB.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await clientA.GetAsync("/")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await clientB.GetAsync("/")).StatusCode);

        var blocked = await clientA.GetAsync("/");

        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.True(blocked.Headers.Contains("Retry-After"));
    }

    [Fact]
    public async Task StoreFailure_FailsOpenWithOkResponse()
    {
        var store = new RecordingRateLimitStore { FailWith = new TimeoutException("redis down") };
        using var factory = WithStore(new GatewayTestFactory(), store);

        var response = await factory.CreateClient().GetAsync("/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Hsts_MatchesEdge_OnHttps()
    {
        using var factory = new GatewayTestFactory().WithWebHostBuilder(b => b.UseEnvironment("Staging"));
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://gateway.test") });

        var response = await client.GetAsync("/");

        Assert.Equal("max-age=31536000; includeSubDomains", response.Headers.GetValues("Strict-Transport-Security").Single());
    }

    [Fact]
    public async Task Hsts_NotSentOverPlainHttp()
    {
        using var factory = new GatewayTestFactory().WithWebHostBuilder(b => b.UseEnvironment("Staging"));

        var response = await factory.CreateClient().GetAsync("/");

        Assert.False(response.Headers.Contains("Strict-Transport-Security"));
    }

    private static void ApplySettings(IWebHostBuilder builder, Dictionary<string, string?> settings)
    {
        foreach (var (key, value) in settings)
            builder.UseSetting(key, value);
    }
}
