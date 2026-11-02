using Serilog.Context;

namespace Gateway.Api.Observability;

/// <summary>
/// Reads X-Correlation-Id (generated when absent or unsafe), echoes it in the response
/// and pushes it onto the Serilog LogContext so every log line of the request carries it.
/// </summary>
public sealed class CorrelationIdMiddleware(RequestDelegate next)
{
    public const string HeaderName = "X-Correlation-Id";
    public const string ItemKey = "CorrelationId";
    private const int MaxLength = 64;

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = Resolve(context.Request.Headers[HeaderName].FirstOrDefault());
        context.Items[ItemKey] = correlationId;
        context.Response.OnStarting(() =>
        {
            context.Response.Headers[HeaderName] = correlationId;
            return Task.CompletedTask;
        });

        using (LogContext.PushProperty("CorrelationId", correlationId))
        {
            await next(context);
        }
    }

    // Accept only short, header/log-safe values; anything else is replaced (prevents log injection).
    internal static string Resolve(string? incoming)
    {
        if (!string.IsNullOrWhiteSpace(incoming) &&
            incoming.Length <= MaxLength &&
            incoming.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ':'))
        {
            return incoming;
        }

        return Guid.NewGuid().ToString("N");
    }
}
