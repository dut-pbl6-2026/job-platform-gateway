using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gateway.Tests;

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
}
