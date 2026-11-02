using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Gateway.Api.Tests;

public class GatewayEndpointsTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public GatewayEndpointsTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task HealthEndpoint_ReturnsAggregatedStatus()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act
        var response = await client.GetAsync("/api/health");

        // Assert
        Assert.True(response.StatusCode == HttpStatusCode.OK || (int)response.StatusCode == 207);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.True(json.RootElement.TryGetProperty("status", out var statusProp));
        var status = statusProp.GetString();
        Assert.True(status == "UP" || status == "DEGRADED");

        Assert.True(json.RootElement.TryGetProperty("services", out var servicesProp));
        Assert.Equal(JsonValueKind.Array, servicesProp.ValueKind);
        Assert.True(servicesProp.GetArrayLength() > 0);
    }

    [Fact]
    public async Task SecurityHeaders_ArePresent()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act
        var response = await client.GetAsync("/");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        Assert.True(response.Headers.Contains("X-Content-Type-Options"));
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").First());

        Assert.True(response.Headers.Contains("X-Frame-Options"));
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").First());

        Assert.True(response.Headers.Contains("Referrer-Policy"));
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").First());
    }

    [Fact]
    public async Task MetricsEndpoint_ReturnsPrometheusTextFormat()
    {
        // Arrange
        var client = _factory.CreateClient();
        await client.GetAsync("/"); // record one request so HTTP metrics are exported

        // Act
        var response = await client.GetAsync("/metrics");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        var contentType = response.Content.Headers.ContentType?.ToString();
        Assert.NotNull(contentType);
        Assert.Contains("text/plain", contentType);

        // The value of the endpoint is the metrics, not just a 200. Assert the
        // instrumentation actually wired up: runtime + ASP.NET Core meters.
        Assert.Contains("dotnet_gc_last_collection_heap_size_bytes", content);
        Assert.Contains("http_server_request_duration_seconds_count", content);
    }

    [Fact]
    public async Task MetricsEndpoint_WhenDisabled_ReturnsNotFound()
    {
        // Arrange: /metrics must be switchable off (the gateway is internet-facing).
        using var factory = _factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["METRICS_ENABLED"] = "false"
                })));
        var client = factory.CreateClient();

        // Act
        var response = await client.GetAsync("/metrics");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Health_KeepsExistingContract()
    {
        var response = await _factory.CreateClient().GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(json.RootElement.TryGetProperty("status", out _));
        Assert.True(json.RootElement.TryGetProperty("version", out _));
        Assert.True(json.RootElement.TryGetProperty("uptimeSeconds", out _));
        Assert.Equal(JsonValueKind.Array, json.RootElement.GetProperty("services").ValueKind);
    }

    [Fact]
    public async Task Ready_ReportsProxyConfigHealthy_WithoutTouchingUpstreams()
    {
        var response = await _factory.CreateClient().GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Healthy", json.RootElement.GetProperty("status").GetString());
        var checks = json.RootElement.GetProperty("checks").EnumerateArray().ToList();
        var check = Assert.Single(checks);
        Assert.Equal("proxy-config", check.GetProperty("name").GetString());
    }

    [Fact]
    public async Task Ready_WithUnreachableUpstreams_IsDegradedButStill200()
    {
        using var factory = _factory.WithWebHostBuilder(b => b.UseSetting("HEALTH_READY_CHECK_UPSTREAMS", "true"));

        var response = await factory.CreateClient().GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Contains(json.RootElement.GetProperty("checks").EnumerateArray(),
            c => c.GetProperty("name").GetString() == "upstreams");
    }

    [Fact]
    public async Task CorrelationId_IsGeneratedWhenAbsent()
    {
        var response = await _factory.CreateClient().GetAsync("/");

        var id = Assert.Single(response.Headers.GetValues("X-Correlation-Id"));
        Assert.False(string.IsNullOrWhiteSpace(id));
    }

    [Fact]
    public async Task CorrelationId_IsEchoedWhenProvided()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.Add("X-Correlation-Id", "abc-123");

        var response = await _factory.CreateClient().SendAsync(request);

        Assert.Equal("abc-123", Assert.Single(response.Headers.GetValues("X-Correlation-Id")));
    }

    [Fact]
    public async Task CorrelationId_UnsafeValueIsReplaced()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.TryAddWithoutValidation("X-Correlation-Id", new string('x', 200));

        var response = await _factory.CreateClient().SendAsync(request);

        Assert.NotEqual(new string('x', 200), Assert.Single(response.Headers.GetValues("X-Correlation-Id")));
    }
}
