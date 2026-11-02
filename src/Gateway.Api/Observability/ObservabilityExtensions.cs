using Serilog;
using Serilog.Events;
using Serilog.Formatting.Compact;

namespace Gateway.Api.Observability;

public static class ObservabilityExtensions
{
    public const string ServiceName = "gateway";

    /// <summary>
    /// Serilog: compact JSON on console outside Development, readable text in Development.
    /// Request logging records method, path (no query string), status and elapsed only;
    /// headers (Authorization, cookies) and bodies are never logged.
    /// </summary>
    public static WebApplicationBuilder AddObservability(this WebApplicationBuilder builder)
    {
        builder.Host.UseSerilog((context, services, configuration) =>
        {
            configuration
                .MinimumLevel.Information()
                .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning)
                .ReadFrom.Configuration(context.Configuration)
                .Enrich.FromLogContext()
                .Enrich.WithProperty("Service", ServiceName);

            if (context.HostingEnvironment.IsDevelopment())
                configuration.WriteTo.Console();
            else
                configuration.WriteTo.Console(new CompactJsonFormatter());
        });

        return builder;
    }

    public static WebApplication UseObservability(this WebApplication app)
    {
        app.UseMiddleware<CorrelationIdMiddleware>();
        app.UseSerilogRequestLogging(o =>
        {
            // Liveness/readiness probes are high-frequency noise.
            o.GetLevel = (ctx, _, ex) =>
                ex is not null || ctx.Response.StatusCode >= 500 ? LogEventLevel.Error
                : ctx.Request.Path.StartsWithSegments("/health") ? LogEventLevel.Verbose
                : LogEventLevel.Information;
        });
        return app;
    }
}
