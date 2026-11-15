using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Gateway.Api.Tests;

/// <summary>
/// Test host for the gateway. Validation keys come from a stub auth-svc discovery document and JWKS
/// (<see cref="JwksStubHandler"/>), the same path a deployment uses, so the gateway runs with no key of its own.
/// </summary>
public sealed class GatewayTestFactory : WebApplicationFactory<Program>
{
    private bool _jwksHealthy = true;

    /// <summary>A host whose auth-svc JWKS answers 503, so no token can be validated.</summary>
    public static GatewayTestFactory WithUnavailableJwks()
    {
        var factory = new GatewayTestFactory();
        factory._jwksHealthy = false;
        return factory;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.UseSetting("Jwt:MetadataAddress", TestSigningKeys.MetadataAddress);
        // Empty REDIS_URL keeps the revocation store in memory even if the developer's shell sets it.
        builder.UseSetting("REDIS_URL", string.Empty);
        var handler = new JwksStubHandler(_jwksHealthy);
        builder.ConfigureTestServices(services =>
        {
            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme,
                o => o.ConfigurationManager = handler.CreateConfigurationManager());
        });
    }
}
