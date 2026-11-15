using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.HttpOverrides;
using IPNetwork = System.Net.IPNetwork;

namespace Gateway.Api.Network;

/// <summary>
/// Decides which peers may set X-Forwarded-For and X-Forwarded-Proto. Only the proxy network
/// configured in ForwardedHeaders:KnownNetworks is trusted; any other peer's headers are ignored.
/// </summary>
public static class ForwardedProxyTrust
{
    public const string KnownNetworksKey = "ForwardedHeaders:KnownNetworks";

    /// <summary>
    /// Reads the configured proxy networks. Accepts a comma-separated value
    /// (ForwardedHeaders__KnownNetworks=10.0.0.0/8,192.168.1.5) or indexed entries
    /// (ForwardedHeaders__KnownNetworks__0=...). Returns an empty list when unset.
    /// </summary>
    public static IReadOnlyList<IPNetwork> ReadNetworks(IConfiguration configuration, bool isProduction)
    {
        var entries = new List<string>();
        var raw = configuration[KnownNetworksKey];
        if (!string.IsNullOrWhiteSpace(raw))
            entries.AddRange(raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        entries.AddRange(configuration.GetSection(KnownNetworksKey).GetChildren()
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v!.Trim()));

        if (entries.Count == 0)
        {
            if (isProduction)
                throw new InvalidOperationException(
                    "ForwardedHeaders:KnownNetworks must list the proxy network in front of the gateway in Production " +
                    "(set ForwardedHeaders__KnownNetworks). Without it every client shares the proxy's rate-limit bucket.");
            return [];
        }

        return Parse(entries);
    }

    /// <summary>Parses CIDR ranges or single addresses. Rejects invalid entries and catch-all ranges.</summary>
    public static IReadOnlyList<IPNetwork> Parse(IEnumerable<string> entries)
    {
        var networks = new List<IPNetwork>();
        foreach (var entry in entries)
        {
            IPNetwork network;
            if (entry.Contains('/'))
            {
                if (!IPNetwork.TryParse(entry, out network))
                    throw new InvalidOperationException($"ForwardedHeaders:KnownNetworks entry '{entry}' is not a valid CIDR range.");
            }
            else
            {
                if (!IPAddress.TryParse(entry, out var address))
                    throw new InvalidOperationException($"ForwardedHeaders:KnownNetworks entry '{entry}' is not a valid IP address.");
                var prefix = address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
                network = new IPNetwork(address, prefix);
            }

            if (network.PrefixLength == 0)
                throw new InvalidOperationException(
                    $"ForwardedHeaders:KnownNetworks entry '{entry}' trusts every peer. Use the proxy's address or subnet.");

            networks.Add(network);
        }

        return networks;
    }

    /// <summary>
    /// Replaces the framework defaults with the configured networks. When the list is empty
    /// (non-Production only) the framework default of loopback-only trust is kept.
    /// </summary>
    public static void Apply(ForwardedHeadersOptions options, IReadOnlyList<IPNetwork> networks)
    {
        if (networks.Count == 0)
            return;

        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        foreach (var network in networks)
            options.KnownIPNetworks.Add(network);
    }
}
