using System.Globalization;
using Microsoft.Extensions.Caching.Distributed;

namespace Gateway.Api.Auth;

/// <summary>
/// Read side of the access-token revocation store. Must stay byte-compatible with auth-svc's
/// TokenRevocationStore: same key prefix and unix-seconds value.
/// </summary>
public sealed class TokenRevocationStore(IDistributedCache cache) : ITokenRevocationStore
{
    // Shared with auth-svc — must stay in sync across services.
    private const string KeyPrefix = "job-platform:auth:revoked-after:";

    public async Task<DateTimeOffset?> GetRevokedAfterAsync(Guid userId, CancellationToken ct = default)
    {
        var raw = await cache.GetStringAsync(KeyFor(userId), ct);
        return long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
    }

    public static string KeyFor(Guid userId) => $"{KeyPrefix}{userId:D}";
}
