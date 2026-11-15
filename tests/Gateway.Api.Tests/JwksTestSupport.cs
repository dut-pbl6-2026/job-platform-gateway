using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Gateway.Api.Tests;

/// <summary>RSA keys generated per test process. Nothing is committed.</summary>
public static class TestSigningKeys
{
    public const string Kid = "gateway-test-kid";
    public const string MetadataAddress = "http://auth.test/.well-known/openid-configuration";
    public const string JwksAddress = "http://auth.test/.well-known/jwks.json";

    /// <summary>The key auth-svc would sign with. Published in the stub JWKS.</summary>
    public static RSA Current { get; } = RSA.Create(2048);

    /// <summary>A key nobody publishes. Tokens from it must be rejected.</summary>
    public static RSA Foreign { get; } = RSA.Create(2048);

    public static string JwksJson { get; } = BuildJwks(Current);

    private static string BuildJwks(RSA rsa)
    {
        var p = rsa.ExportParameters(includePrivateParameters: false);
        return JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new { kty = "RSA", use = "sig", alg = "RS256", kid = Kid, n = Base64Url(p.Modulus!), e = Base64Url(p.Exponent!) }
            }
        });
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>
/// Stands in for auth-svc on the validator's backchannel: serves the discovery document and the JWKS.
/// A failing instance answers 503 to everything, which must make the gateway refuse every token.
/// </summary>
public sealed class JwksStubHandler(bool healthy) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!healthy)
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

        var path = request.RequestUri?.AbsolutePath;
        var body = path switch
        {
            "/.well-known/openid-configuration" => JsonSerializer.Serialize(new { issuer = "job-platform", jwks_uri = TestSigningKeys.JwksAddress }),
            "/.well-known/jwks.json" => TestSigningKeys.JwksJson,
            _ => null,
        };
        if (body is null)
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        });
    }

    /// <summary>Configuration manager that fetches through the stub, as a validator would fetch from auth-svc.</summary>
    public ConfigurationManager<OpenIdConnectConfiguration> CreateConfigurationManager() =>
        new(TestSigningKeys.MetadataAddress,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(new HttpClient(this)) { RequireHttps = false });
}
