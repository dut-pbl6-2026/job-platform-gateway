using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;
using Gateway.Api.Observability;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using SharedKernel;
using Yarp.ReverseProxy.Transforms;
using System.Security.Claims;
using OpenTelemetry.Metrics;
using Gateway.Api.Auth;
using Gateway.Api.Network;
using Gateway.Api.RateLimiting;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);
builder.AddObservability();

// JWT: RS256 only. Public keys come from auth-svc's discovery document (Jwt:MetadataAddress); the gateway
// holds no signing key. Checked on the effective value after all configuration sources merge (fail fast).
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
var jwt = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>() ?? new JwtOptions();
var jwtMetadataAddress = builder.Configuration["Jwt:MetadataAddress"];
if (string.IsNullOrWhiteSpace(jwtMetadataAddress))
    throw new InvalidOperationException("Jwt:MetadataAddress is required (env Jwt__MetadataAddress: auth-svc discovery URL, e.g. http://auth-svc:5001/.well-known/openid-configuration).");

// Allow override via env GATEWAY_UPSTREAM_* for prod Render public URLs
var upstreamAuth = builder.Configuration["GATEWAY_UPSTREAM_AUTH"];
if (!string.IsNullOrEmpty(upstreamAuth))
{
    // override cluster destination at runtime via config binding
    builder.Configuration["ReverseProxy:Clusters:auth:Destinations:auth1:Address"] = upstreamAuth;
}

var upstreamJob = builder.Configuration["GATEWAY_UPSTREAM_JOB"];
if (!string.IsNullOrEmpty(upstreamJob))
{
    builder.Configuration["ReverseProxy:Clusters:job:Destinations:job1:Address"] = upstreamJob;
}

var upstreamSearch = builder.Configuration["GATEWAY_UPSTREAM_SEARCH"];
if (!string.IsNullOrEmpty(upstreamSearch))
{
    builder.Configuration["ReverseProxy:Clusters:search:Destinations:search1:Address"] = upstreamSearch;
}

var upstreamApp = builder.Configuration["GATEWAY_UPSTREAM_APP"];
if (!string.IsNullOrEmpty(upstreamApp))
{
    builder.Configuration["ReverseProxy:Clusters:app:Destinations:app1:Address"] = upstreamApp;
}

var upstreamProfile = builder.Configuration["GATEWAY_UPSTREAM_PROFILE"];
if (!string.IsNullOrEmpty(upstreamProfile))
{
    builder.Configuration["ReverseProxy:Clusters:profile:Destinations:profile1:Address"] = upstreamProfile;
}

var upstreamNotif = builder.Configuration["GATEWAY_UPSTREAM_NOTIF"];
if (!string.IsNullOrEmpty(upstreamNotif))
{
    builder.Configuration["ReverseProxy:Clusters:notif:Destinations:notif1:Address"] = upstreamNotif;
}

var upstreamAi = builder.Configuration["GATEWAY_UPSTREAM_AI"];
if (!string.IsNullOrEmpty(upstreamAi))
{
    builder.Configuration["ReverseProxy:Clusters:ai:Destinations:ai1:Address"] = upstreamAi;
}

// CORS
var corsOrigins = builder.Configuration["CORS_ORIGINS"] ?? "http://localhost:5173,http://localhost:3000,https://jp-web.vercel.app,https://job-platform-web.vercel.app";
var origins = corsOrigins.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
builder.Services.AddCors(o => o.AddPolicy("Default", p => p.WithOrigins(origins).AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.MetadataAddress = jwtMetadataAddress;
        o.RequireHttpsMetadata = false; // auth-svc is reached over the private network (plain HTTP), see README
        o.AutomaticRefreshInterval = TimeSpan.FromMinutes(15); // bounded refresh of the JWKS
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwt.Issuer,
            ValidAudience = jwt.Audience,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            TryAllIssuerSigningKeys = false,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
        // Reject access tokens issued before the user's revocation instant (written by auth-svc).
        o.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                if (!JwtClaimChecks.HasKidAndSubject(context.SecurityToken, context.Principal))
                {
                    context.Fail("Access token must carry a kid and a subject");
                    return;
                }
                var store = context.HttpContext.RequestServices.GetRequiredService<ITokenRevocationStore>();
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("TokenRevocation");
                if (await TokenRevocation.IsRevokedAsync(context.Principal, store, logger, context.HttpContext.RequestAborted))
                    context.Fail("Access token revoked");
            }
        };
        // Let gateway authenticate but not require auth globally; YARP will forward 401 as 401
        // Anonymous routes (auth login/register/refresh, job browsing, search) remain accessible.
        // Protected YARP routes opt in via AuthorizationPolicy "Authenticated".
    });
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("Authenticated", policy => policy.RequireAuthenticatedUser())
    .AddPolicy("Admin", policy => policy.RequireClaim(ClaimTypes.Role, "Admin"))
    // Role names mirror auth-svc ("User" = candidate, "Recruiter") and job-svc's own checks.
    .AddPolicy("Recruiter", policy => policy.RequireClaim(ClaimTypes.Role, "Recruiter"))
    .AddPolicy("User", policy => policy.RequireClaim(ClaimTypes.Role, "User"));

// ForwardedHeaders: only the proxy network in ForwardedHeaders:KnownNetworks may set
// X-Forwarded-For / X-Forwarded-Proto. Resolved eagerly so a bad or missing value fails startup.
var forwardedProxyNetworks = ForwardedProxyTrust.ReadNetworks(builder.Configuration, builder.Environment.IsProduction());
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.ForwardLimit = 1; // Right-most entry only: the entry our trusted proxy appended.
    ForwardedProxyTrust.Apply(o, forwardedProxyNetworks);
});

// Coarse DDoS/bot layer: per-client fixed window on every request (incl. YARP). Counters live in Redis
// (see RedisRateLimitStore) so the limit holds across replicas.
var rateLimitPerMinute = builder.Configuration.GetValue("GATEWAY_RATE_LIMIT_PER_MINUTE", 600);
if (rateLimitPerMinute <= 0)
    throw new InvalidOperationException("GATEWAY_RATE_LIMIT_PER_MINUTE must be a positive integer.");
builder.Services.Configure<RateLimitOptions>(o => o.PermitLimit = rateLimitPerMinute);

// Shared Redis connection (revocation cache and rate-limit counters). Created lazily on first use so a
// Redis outage does not block startup; Redis is required in Production (checked below).
var redisUrl = builder.Configuration["REDIS_URL"];
if (!string.IsNullOrWhiteSpace(redisUrl))
{
    var redisOptions = ConfigurationOptions.Parse(redisUrl);
    var redisPassword = builder.Configuration["REDIS_PASSWORD"];
    if (!string.IsNullOrWhiteSpace(redisPassword))
        redisOptions.Password = redisPassword;
    if (int.TryParse(builder.Configuration["REDIS_DB"], out var redisDb))
        redisOptions.DefaultDatabase = redisDb;
    redisOptions.AbortOnConnectFail = false;

    var redisConnection = new Lazy<Task<IConnectionMultiplexer>>(async () => await ConnectionMultiplexer.ConnectAsync(redisOptions));
    builder.Services.AddStackExchangeRedisCache(o => o.ConnectionMultiplexerFactory = () => redisConnection.Value);
    builder.Services.AddSingleton<IRateLimitStore>(_ => new RedisRateLimitStore(redisConnection));
}
else
{
    if (builder.Environment.IsProduction())
        throw new InvalidOperationException("REDIS_URL must be set in Production (required for access-token revocation and rate limiting).");

    builder.Services.AddDistributedMemoryCache();
    builder.Services.AddSingleton<IRateLimitStore, InMemoryRateLimitStore>();
}
builder.Services.AddSingleton<ITokenRevocationStore, TokenRevocationStore>();

// YARP
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(transformContext =>
    {
        transformContext.AddRequestTransform(utc =>
        {
            var user = utc.HttpContext.User;

            utc.ProxyRequest.Headers.Remove("X-User-Id");
            utc.ProxyRequest.Headers.Remove("X-User-Role");
            utc.ProxyRequest.Headers.Remove("X-User-Company");

            // Propagate the (validated/generated) correlation id to upstream services.
            utc.ProxyRequest.Headers.Remove(CorrelationIdMiddleware.HeaderName);
            if (utc.HttpContext.Items[CorrelationIdMiddleware.ItemKey] is string correlationId)
            {
                utc.ProxyRequest.Headers.TryAddWithoutValidation(CorrelationIdMiddleware.HeaderName, correlationId);
            }

            if (user.Identity?.IsAuthenticated == true)
            {
                var sub = user.FindFirst("sub")?.Value
                       ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var role = user.FindFirst(ClaimTypes.Role)?.Value
                        ?? user.FindFirst("role")?.Value;

                if (!string.IsNullOrEmpty(sub))
                {
                    utc.ProxyRequest.Headers.TryAddWithoutValidation("X-User-Id", sub);
                }

                if (!string.IsNullOrEmpty(role))
                {
                    utc.ProxyRequest.Headers.TryAddWithoutValidation("X-User-Role", role);
                }

                // Recruiter's company (JWT company_id). Dev-auth services read it for ownership checks.
                var company = user.FindFirst("company_id")?.Value;
                if (!string.IsNullOrEmpty(company))
                {
                    utc.ProxyRequest.Headers.TryAddWithoutValidation("X-User-Company", company);
                }
            }

            return ValueTask.CompletedTask;
        });
    });

// Monitoring: expose OpenTelemetry metrics on /metrics (Prometheus scrape target).
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddRuntimeInstrumentation()
            .AddPrometheusExporter();
    });

// /health = existing liveness/upstream summary (Render healthCheckPath); /health/ready = readiness checks.
var healthChecks = builder.Services.AddHealthChecks()
    .AddCheck<ProxyConfigHealthCheck>("proxy-config", tags: [HealthCheckTags.Ready]);
if (string.Equals(builder.Configuration["HEALTH_READY_CHECK_UPSTREAMS"], "true", StringComparison.OrdinalIgnoreCase))
    healthChecks.AddCheck<UpstreamsHealthCheck>("upstreams", tags: [HealthCheckTags.Ready]);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddHttpClient();

var app = builder.Build();

app.UseObservability();
app.UseForwardedHeaders();

// Security Headers Middleware - Centralized security response headers
app.Use(async (context, next) =>
{
    // Authoritative indexer assignment to avoid duplicate headers from downstream YARP proxies
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";

    // HSTS matches the edge (Caddy): one year, includeSubDomains. Sent only over HTTPS outside Development.
    if (!app.Environment.IsDevelopment() && context.Request.IsHttps)
    {
        context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
    }

    await next();
});

app.UseCors("Default");
app.UseMiddleware<RateLimitMiddleware>();
app.UseAuthentication();
app.UseAuthorization();

var StartTime = DateTime.UtcNow;

var healthHandler = async (IConfiguration config, IHttpClientFactory clientFactory) =>
{
    var upstreams = new Dictionary<string, string>
    {
        { "auth", config["GATEWAY_UPSTREAM_AUTH"] ?? "http://localhost:5001" },
        { "job", config["GATEWAY_UPSTREAM_JOB"] ?? "http://localhost:5002" },
        { "search", config["GATEWAY_UPSTREAM_SEARCH"] ?? "http://localhost:5003" },
        { "app", config["GATEWAY_UPSTREAM_APP"] ?? "http://localhost:5004" },
        { "profile", config["GATEWAY_UPSTREAM_PROFILE"] ?? "http://localhost:5005" },
        { "notif", config["GATEWAY_UPSTREAM_NOTIF"] ?? "http://localhost:5006" },
        { "ai", config["GATEWAY_UPSTREAM_AI"] ?? "http://localhost:6000" }
    };

    var client = clientFactory.CreateClient();
    client.Timeout = TimeSpan.FromSeconds(3);

    var tasks = upstreams.Select(async u =>
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        string status = "DOWN";
        try
        {
            var response = await client.GetAsync($"{u.Value}/health");
            if (response.IsSuccessStatusCode)
            {
                status = "UP";
            }
        }
        catch { }
        sw.Stop();

        return new { name = u.Key, status, latencyMs = sw.ElapsedMilliseconds, url = u.Value };
    }).ToList();

    var results = await Task.WhenAll(tasks);
    bool allUp = results.All(r => r.status == "UP");

    return Results.Ok(new
    {
        status = allUp ? "UP" : "DEGRADED",
        version = "0.1.0",
        uptimeSeconds = (long)(DateTime.UtcNow - StartTime).TotalSeconds,
        services = results
    });
};

// Monitoring: /metrics is meant for the internal scrape network. The gateway is the
// public entry point, so it stays off in Production unless METRICS_ENABLED=true.
if (app.Configuration.GetValue("METRICS_ENABLED", !app.Environment.IsProduction()))
{
    app.MapPrometheusScrapingEndpoint();
}

app.MapGet("/health", healthHandler);
app.MapGet("/api/health", healthHandler);
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = r => r.Tags.Contains(HealthCheckTags.Ready),
    ResponseWriter = HealthCheckResponseWriter.WriteAsync
});
app.MapGet("/", () => Results.Ok(new { service = "gateway", version = "0.1.0" }));

app.MapReverseProxy();

app.Run();

public partial class Program { }
