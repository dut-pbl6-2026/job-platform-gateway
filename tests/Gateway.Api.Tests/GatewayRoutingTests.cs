using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Yarp.ReverseProxy.Configuration;

namespace Gateway.Api.Tests;

/// <summary>
/// End-to-end tests for the gateway HTTP pipeline (YARP routing, JWT validation and
/// the claim -> X-User-Id/X-User-Role request transform).
///
/// A lightweight Kestrel "downstream" stub is started on a random port and injected
/// through the GATEWAY_UPSTREAM_PROFILE / GATEWAY_UPSTREAM_APP environment variables,
/// so requests that pass auth are actually forwarded and their injected headers can
/// be asserted. Tests in this class run sequentially (single class = single collection).
/// </summary>
public sealed class GatewayRoutingTests : IAsyncLifetime
{
    private const string Issuer = "job-platform";
    private const string Audience = "job-platform";
    private const string Secret = "dev-jwt-secret-change-me-32chars-min";

    private WebApplication _stub = null!;
    private string _stubAddress = null!;
    private WebApplicationFactory<Program> _factory = null!;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        _stub = builder.Build();
        _stub.Run(async ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status200OK;
            await ctx.Response.WriteAsJsonAsync(new
            {
                path = ctx.Request.Path.Value,
                userId = ctx.Request.Headers["X-User-Id"].ToString(),
                userRole = ctx.Request.Headers["X-User-Role"].ToString()
            });
        });
        await _stub.StartAsync();
        _stubAddress = _stub.Urls.First();

        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_PROFILE", _stubAddress);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_APP", _stubAddress);

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(b => b.UseEnvironment("Development"));
    }

    public async Task DisposeAsync()
    {
        _factory.Dispose();
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_PROFILE", null);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_APP", null);
        await _stub.DisposeAsync();
    }

    private HttpClient CreateClient() => _factory.CreateClient();

    private static string CreateToken(
        string sub = "user-123",
        string role = "User",
        string issuer = Issuer,
        string audience = Audience,
        TimeSpan? lifetime = null,
        TimeSpan? notBefore = null)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, sub),
            new(ClaimTypes.Role, role),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: DateTime.UtcNow.Add(notBefore ?? TimeSpan.FromMinutes(-1)),
            expires: DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromMinutes(30)),
            signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    [Fact]
    public async Task Health_ReturnsOk()
    {
        using var client = CreateClient();

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("/api/profiles/me")]
    [InlineData("/api/applications/me")]
    public async Task ProtectedRoute_WithoutToken_Returns401(string path)
    {
        using var client = CreateClient();

        var response = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("/api/auth/login")]
    [InlineData("/api/applications/status-flow")]
    public async Task AnonymousRoute_PassesAuthorization(string path)
    {
        using var client = CreateClient();

        var response = await client.GetAsync(path);

        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedRoute_WithValidToken_ForwardsAndInjectsUserHeaders()
    {
        using var client = CreateClient();
        var token = CreateToken(sub: "user-abc", role: "Recruiter");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync("/api/profiles/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"userId\":\"user-abc\"", body);
        Assert.Contains("\"userRole\":\"Recruiter\"", body);
    }

    [Fact]
    public async Task ProtectedRoute_WithExpiredToken_Returns401()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", CreateToken(
                lifetime: TimeSpan.FromMinutes(-5),
                notBefore: TimeSpan.FromMinutes(-10)));

        var response = await client.GetAsync("/api/profiles/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedRoute_WithWrongIssuer_Returns401()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", CreateToken(issuer: "not-job-platform"));

        var response = await client.GetAsync("/api/profiles/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public void RouteConfig_RoutesApplicationsAndProfilesWithPolicies()
    {
        var provider = _factory.Services.GetRequiredService<IProxyConfigProvider>();
        var config = provider.GetConfig();

        var routes = config.Routes.ToDictionary(r => r.RouteId);
        Assert.Equal("app", routes["apps"].ClusterId);
        Assert.Equal("Authenticated", routes["apps"].AuthorizationPolicy);
        Assert.Equal("profile", routes["profiles"].ClusterId);
        Assert.Equal("Authenticated", routes["profiles"].AuthorizationPolicy);

        // status-flow must stay anonymous (exact match, no policy) while the
        // apps catch-all stays protected.
        Assert.Null(routes["app-status-flow"].AuthorizationPolicy);

        var clusters = config.Clusters.ToDictionary(c => c.ClusterId);
        Assert.True(clusters.ContainsKey("app"));
        Assert.True(clusters.ContainsKey("profile"));
        Assert.Contains(clusters["app"].Destinations!, d => d.Value.Address == _stubAddress);
        Assert.Contains(clusters["profile"].Destinations!, d => d.Value.Address == _stubAddress);
    }
}
