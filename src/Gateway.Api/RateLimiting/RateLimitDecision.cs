namespace Gateway.Api.RateLimiting;

/// <summary>Pure rate-limit rules, kept separate from I/O so they can be unit tested.</summary>
public static class RateLimitDecision
{
    /// <summary>A request is allowed while the count for its window is within the permit limit.</summary>
    public static bool IsAllowed(long count, int permitLimit) => count <= permitLimit;

    /// <summary>Retry-After in whole seconds, rounded up, never below one second.</summary>
    public static int RetryAfterSeconds(TimeSpan timeToLive) =>
        Math.Max(1, (int)Math.Ceiling(timeToLive.TotalSeconds));
}
