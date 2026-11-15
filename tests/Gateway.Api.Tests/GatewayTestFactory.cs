using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Gateway.Api.Tests;

/// <summary>
/// Test host for the gateway. The JWT signing key is supplied here as configuration, the same way
/// deployments supply it, because the gateway refuses to start without one.
/// </summary>
public sealed class GatewayTestFactory : WebApplicationFactory<Program>
{
    public const string TestJwtSecret = "test-only-jwt-signing-key-0123456789abcdef";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.UseSetting("Jwt:Secret", TestJwtSecret);
    }
}
