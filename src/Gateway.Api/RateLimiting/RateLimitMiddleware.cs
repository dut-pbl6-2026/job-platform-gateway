using Microsoft.Extensions.Options;

namespace Gateway.Api.RateLimiting;

/// <summary>
/// Coarse per-client limiter for every request (including proxied ones), keyed by the client IP
/// after forwarded-header resolution. Store errors fail open with a logged warning.
/// </summary>
public sealed class RateLimitMiddleware(
    RequestDelegate next,
    IRateLimitStore store,
    IOptions<RateLimitOptions> options,
    ILogger<RateLimitMiddleware> logger)
{
    private readonly RateLimitOptions _options = options.Value;

    public async Task InvokeAsync(HttpContext context)
    {
        var key = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        RateLimitCounter counter;
        try
        {
            counter = await store.IncrementAsync(key, _options.Window, context.RequestAborted);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Rate-limit store unavailable; allowing request (fail open).");
            await next(context);
            return;
        }

        if (RateLimitDecision.IsAllowed(counter.Count, _options.PermitLimit))
        {
            await next(context);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.Response.Headers.RetryAfter =
            RateLimitDecision.RetryAfterSeconds(counter.TimeToLive).ToString();
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new
        {
            status = 429,
            title = "Too Many Requests",
            detail = "Quota exceeded. Please wait before retrying."
        }, context.RequestAborted);
    }
}
