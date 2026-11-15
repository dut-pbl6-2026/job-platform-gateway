using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gateway.Api.Tests;

public class RedisConfigurationTests
{
    [Fact]
    public void Production_WithoutRedisUrl_FailsFast()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Jwt:Secret", GatewayTestFactory.TestJwtSecret);
            builder.UseSetting("ForwardedHeaders:KnownNetworks", "10.0.0.0/8");
            builder.UseSetting("REDIS_URL", string.Empty);
        });

        var ex = Record.Exception(() => factory.CreateClient());

        Assert.NotNull(ex);
        Assert.Contains("REDIS_URL", ex.ToString());
    }
}
