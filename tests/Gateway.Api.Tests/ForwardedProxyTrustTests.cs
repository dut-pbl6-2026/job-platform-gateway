using System.Net;
using Gateway.Api.Network;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using IPNetwork = System.Net.IPNetwork;

namespace Gateway.Api.Tests;

public class ForwardedProxyTrustTests
{
    private static IConfiguration Config(params (string Key, string? Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build();

    [Fact]
    public void ReadNetworks_Unset_NonProduction_ReturnsEmpty()
    {
        Assert.Empty(ForwardedProxyTrust.ReadNetworks(Config(), isProduction: false));
    }

    [Fact]
    public void ReadNetworks_Unset_Production_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ForwardedProxyTrust.ReadNetworks(Config(), isProduction: true));
        Assert.Contains("ForwardedHeaders:KnownNetworks", ex.Message);
    }

    [Fact]
    public void ReadNetworks_CommaSeparatedValue_IsParsed()
    {
        var networks = ForwardedProxyTrust.ReadNetworks(
            Config(("ForwardedHeaders:KnownNetworks", "10.0.0.0/8, 192.168.1.5")), isProduction: true);

        Assert.Equal(2, networks.Count);
        Assert.Equal(8, networks[0].PrefixLength);
        Assert.Equal(32, networks[1].PrefixLength);
    }

    [Fact]
    public void ReadNetworks_IndexedChildren_AreParsed()
    {
        var networks = ForwardedProxyTrust.ReadNetworks(
            Config(("ForwardedHeaders:KnownNetworks:0", "10.0.0.0/8"), ("ForwardedHeaders:KnownNetworks:1", "172.16.0.0/12")),
            isProduction: true);

        Assert.Equal(2, networks.Count);
    }

    [Fact]
    public void Parse_BareAddress_BecomesHostNetwork()
    {
        var network = Assert.Single(ForwardedProxyTrust.Parse(["10.0.0.5"]));

        Assert.Equal(IPAddress.Parse("10.0.0.5"), network.BaseAddress);
        Assert.Equal(32, network.PrefixLength);
    }

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("::/0")]
    public void Parse_CatchAllRange_Throws(string entry)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ForwardedProxyTrust.Parse([entry]));
        Assert.Contains("trusts every peer", ex.Message);
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("10.0.0.0/99")]
    public void Parse_InvalidEntry_Throws(string entry)
    {
        Assert.Throws<InvalidOperationException>(() => ForwardedProxyTrust.Parse([entry]));
    }

    [Fact]
    public void Apply_EmptyList_KeepsFrameworkLoopbackDefault()
    {
        var options = new ForwardedHeadersOptions();
        var defaults = options.KnownIPNetworks.Count;

        ForwardedProxyTrust.Apply(options, []);

        Assert.Equal(defaults, options.KnownIPNetworks.Count);
        Assert.True(defaults > 0);
    }

    [Fact]
    public void Apply_Networks_ReplacesDefaults()
    {
        var options = new ForwardedHeadersOptions();
        var networks = new List<IPNetwork> { new(IPAddress.Parse("10.0.0.0"), 8) };

        ForwardedProxyTrust.Apply(options, networks);

        Assert.Single(options.KnownIPNetworks);
        Assert.Empty(options.KnownProxies);
    }
}
