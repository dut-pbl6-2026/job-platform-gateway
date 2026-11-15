using StackExchange.Redis;

namespace Gateway.Api.RateLimiting;

/// <summary>
/// Redis-backed fixed-window counter. INCR, the TTL set and the TTL read run in one Lua script, so
/// a key can never be left without an expiry. Every call has a short time budget: during a Redis
/// outage the caller gets an exception quickly and can fail open instead of stalling the request.
/// </summary>
public sealed class RedisRateLimitStore(Lazy<Task<IConnectionMultiplexer>> connection) : IRateLimitStore
{
    internal const string KeyPrefix = "job-platform:gateway:ratelimit:";
    internal static readonly TimeSpan OperationBudget = TimeSpan.FromMilliseconds(500);

    // KEYS[1] = counter key, ARGV[1] = window in milliseconds.
    private const string IncrementScript = """
        local count = redis.call('INCR', KEYS[1])
        local ttl = redis.call('PTTL', KEYS[1])
        if count == 1 or ttl < 0 then
            redis.call('PEXPIRE', KEYS[1], ARGV[1])
            ttl = tonumber(ARGV[1])
        end
        return {count, ttl}
        """;

    public async Task<RateLimitCounter> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default)
    {
        var multiplexer = await connection.Value.WaitAsync(OperationBudget, ct);
        var database = multiplexer.GetDatabase();
        var result = (RedisResult[])(await database.ScriptEvaluateAsync(
                IncrementScript,
                [new RedisKey(KeyPrefix + key)],
                [(long)window.TotalMilliseconds])
            .WaitAsync(OperationBudget, ct))!;

        return new RateLimitCounter((long)result[0], TimeSpan.FromMilliseconds((long)result[1]));
    }
}
