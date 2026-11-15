using SharedKernel;

namespace SharedContract.Tests;

public class GatewaySharedContractTests
{
    [Fact]
    public void JwtOptions_PreservesGatewayConfigurationContract()
    {
        var options = new JwtOptions
        {
            Issuer = "gateway-contract-issuer",
            Audience = "gateway-contract-audience",
            ExpiresMinutes = 60
        };

        Assert.Equal("Jwt", JwtOptions.SectionName);

        Assert.Equal("gateway-contract-issuer", options.Issuer);
        Assert.Equal("gateway-contract-audience", options.Audience);
        Assert.Equal(60, options.ExpiresMinutes);
    }
}