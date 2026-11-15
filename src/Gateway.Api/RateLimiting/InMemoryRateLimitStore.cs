namespace Gateway.Api.RateLimiting;

/// <summary>
/// Process-local counter store. Used only outside Production when REDIS_URL is unset (local runs and
/// tests). Production requires Redis, so the limit is shared across replicas there.
/// </summary>
public sealed class InMemoryRateLimitStore(TimeProvider? clock = null) : IRateLimitStore
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, (long Count, DateTimeOffset ExpiresAt)> _counters = [];

    public Task<RateLimitCounter> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var now = _clock.GetUtcNow();
            if (!_counters.TryGetValue(key, out var entry) || entry.ExpiresAt <= now)
                entry = (0, now + window);

            entry = (entry.Count + 1, entry.ExpiresAt);
            _counters[key] = entry;
            return Task.FromResult(new RateLimitCounter(entry.Count, entry.ExpiresAt - now));
        }
    }
}
