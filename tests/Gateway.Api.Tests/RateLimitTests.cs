using System.Net;
using Gateway.Api.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Gateway.Api.Tests;

public class RateLimitTests
{
    private sealed class FakeStore(long count = 1, Exception? error = null, TimeSpan? ttl = null) : IRateLimitStore
    {
        public List<string> Keys { get; } = [];

        public Task<RateLimitCounter> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default)
        {
            Keys.Add(key);
            if (error is not null)
                throw error;
            return Task.FromResult(new RateLimitCounter(count, ttl ?? window));
        }
    }

    private sealed class ListLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, Exception? Error)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Entries.Add((logLevel, exception));
    }

    private sealed class ManualClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static (RateLimitMiddleware Middleware, bool[] Called, ListLogger<RateLimitMiddleware> Logger) Build(IRateLimitStore store, int permitLimit = 2)
    {
        var called = new bool[1];
        RequestDelegate next = _ => { called[0] = true; return Task.CompletedTask; };
        var logger = new ListLogger<RateLimitMiddleware>();
        var middleware = new RateLimitMiddleware(next, store,
            Options.Create(new RateLimitOptions { PermitLimit = permitLimit, Window = TimeSpan.FromMinutes(1) }), logger);
        return (middleware, called, logger);
    }

    private static DefaultHttpContext Context(string? ip = "203.0.113.7")
    {
        var context = new DefaultHttpContext();
        if (ip is not null)
            context.Connection.RemoteIpAddress = IPAddress.Parse(ip);
        return context;
    }

    [Theory]
    [InlineData(1, 2, true)]
    [InlineData(2, 2, true)]
    [InlineData(3, 2, false)]
    public void IsAllowed_WithinLimitOnly(long count, int limit, bool expected)
    {
        Assert.Equal(expected, RateLimitDecision.IsAllowed(count, limit));
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1200, 2)]
    [InlineData(60000, 60)]
    public void RetryAfterSeconds_RoundsUpAndNeverBelowOne(int milliseconds, int expected)
    {
        Assert.Equal(expected, RateLimitDecision.RetryAfterSeconds(TimeSpan.FromMilliseconds(milliseconds)));
    }

    [Fact]
    public async Task Middleware_AllowedRequest_PassesThrough()
    {
        var (middleware, called, _) = Build(new FakeStore(count: 2));
        var context = Context();

        await middleware.InvokeAsync(context);

        Assert.True(called[0]);
        Assert.Equal(200, context.Response.StatusCode);
    }

    [Fact]
    public async Task Middleware_BlockedRequest_Returns429WithRetryAfter()
    {
        var (middleware, called, _) = Build(new FakeStore(count: 3, ttl: TimeSpan.FromSeconds(42)));
        var context = Context();

        await middleware.InvokeAsync(context);

        Assert.False(called[0]);
        Assert.Equal(429, context.Response.StatusCode);
        Assert.Equal("42", context.Response.Headers.RetryAfter.ToString());
    }

    [Fact]
    public async Task Middleware_StoreError_FailsOpenAndLogsWarning()
    {
        var (middleware, called, logger) = Build(new FakeStore(error: new TimeoutException("redis down")));
        var context = Context();

        await middleware.InvokeAsync(context);

        Assert.True(called[0]);
        Assert.Equal(200, context.Response.StatusCode);
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.IsType<TimeoutException>(entry.Error);
    }

    [Fact]
    public async Task Middleware_NoRemoteAddress_UsesUnknownPartition()
    {
        var store = new FakeStore(count: 1);
        var (middleware, _, _) = Build(store);

        await middleware.InvokeAsync(Context(ip: null));

        Assert.Equal(["unknown"], store.Keys);
    }

    [Fact]
    public async Task Middleware_KeysByResolvedClientAddress()
    {
        var store = new FakeStore(count: 1);
        var (middleware, _, _) = Build(store);

        await middleware.InvokeAsync(Context("198.51.100.9"));

        Assert.Equal(["198.51.100.9"], store.Keys);
    }

    [Fact]
    public async Task InMemoryStore_CountsWithinWindowAndResetsAfterIt()
    {
        var clock = new ManualClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var store = new InMemoryRateLimitStore(clock);
        var window = TimeSpan.FromMinutes(1);

        var first = await store.IncrementAsync("ip", window);
        clock.Now = clock.Now.AddSeconds(20);
        var second = await store.IncrementAsync("ip", window);
        Assert.Equal(1, first.Count);
        Assert.Equal(2, second.Count);
        Assert.Equal(TimeSpan.FromSeconds(40), second.TimeToLive);

        clock.Now = clock.Now.AddSeconds(41);
        var afterWindow = await store.IncrementAsync("ip", window);
        Assert.Equal(1, afterWindow.Count);
    }
}
