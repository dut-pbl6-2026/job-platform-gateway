using System.Globalization;
using Microsoft.Extensions.Caching.Distributed;

namespace Gateway.Api.TokenRevocation;

public sealed class RedisTokenRevocationStore : ITokenRevocationStore
{
    // Shared with auth-svc — must stay in sync across services.
    private const string KeyPrefix = "job-platform:auth:revoked-after:";

    private readonly IDistributedCache _cache;

    public RedisTokenRevocationStore(IDistributedCache cache) => _cache = cache;

    public async Task<DateTimeOffset?> GetRevokedAfterAsync(Guid userId, CancellationToken ct = default)
    {
        var raw = await _cache.GetStringAsync($"{KeyPrefix}{userId:D}", ct);
        return long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
    }
}
