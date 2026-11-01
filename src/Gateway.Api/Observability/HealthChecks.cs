using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Yarp.ReverseProxy.Configuration;

namespace Gateway.Api.Observability;

public static class HealthCheckTags
{
    public const string Ready = "ready";
}

/// <summary>Gateway can route: proxy config is loaded with at least one route and cluster. In-process, non-flaky.</summary>
public sealed class ProxyConfigHealthCheck(IProxyConfigProvider provider) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var config = provider.GetConfig();
        return Task.FromResult(config.Routes.Count > 0 && config.Clusters.Count > 0
            ? HealthCheckResult.Healthy()
            : HealthCheckResult.Unhealthy("no routes/clusters loaded"));
    }
}

/// <summary>
/// Opt-in (HEALTH_READY_CHECK_UPSTREAMS=true) upstream probe. Cold Render free-tier upstreams are
/// expected to be slow/down, so failures only report Degraded and never fail readiness.
/// </summary>
public sealed class UpstreamsHealthCheck(IProxyConfigProvider provider, IHttpClientFactory clientFactory) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var addresses = provider.GetConfig().Clusters
            .SelectMany(c => c.Destinations?.Values ?? [])
            .Select(d => d.Address.TrimEnd('/'))
            .Distinct()
            .ToList();

        var client = clientFactory.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(2);

        var results = await Task.WhenAll(addresses.Select(async address =>
        {
            try
            {
                using var res = await client.GetAsync($"{address}/health", cancellationToken);
                return res.IsSuccessStatusCode;
            }
            catch (Exception)
            {
                return false;
            }
        }));

        var down = results.Count(r => !r);
        return down == 0
            ? HealthCheckResult.Healthy($"{results.Length} upstreams up")
            : HealthCheckResult.Degraded($"{down}/{results.Length} upstreams unreachable");
    }
}

public static class HealthCheckResponseWriter
{
    public static Task WriteAsync(HttpContext context, HealthReport report)
    {
        context.Response.ContentType = "application/json";
        var payload = new
        {
            status = report.Status.ToString(),
            service = ObservabilityExtensions.ServiceName,
            totalDurationMs = (long)report.TotalDuration.TotalMilliseconds,
            checks = report.Entries.Select(e => new
            {
                name = e.Key,
                status = e.Value.Status.ToString(),
                durationMs = (long)e.Value.Duration.TotalMilliseconds,
                description = e.Value.Description
            })
        };
        return context.Response.WriteAsync(JsonSerializer.Serialize(payload, JsonSerializerOptions.Web));
    }
}
