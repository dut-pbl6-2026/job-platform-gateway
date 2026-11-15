namespace Gateway.Api.RateLimiting;

public sealed class RateLimitOptions
{
    /// <summary>Requests allowed per client per window (GATEWAY_RATE_LIMIT_PER_MINUTE).</summary>
    public int PermitLimit { get; set; } = 600;

    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
}
