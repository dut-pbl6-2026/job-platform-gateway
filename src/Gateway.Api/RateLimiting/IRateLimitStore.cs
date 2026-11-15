namespace Gateway.Api.RateLimiting;

/// <summary>
/// Shared counter store for the per-client fixed-window limiter. Implementations must keep the
/// counter outside the process (Redis in deployed environments) so the limit holds across replicas.
/// </summary>
public interface IRateLimitStore
{
    /// <summary>
    /// Increments the counter for <paramref name="key"/>. The window starts at the first hit and
    /// lasts <paramref name="window"/>; the returned TTL is the time left in that window.
    /// </summary>
    Task<RateLimitCounter> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default);
}

public readonly record struct RateLimitCounter(long Count, TimeSpan TimeToLive);
