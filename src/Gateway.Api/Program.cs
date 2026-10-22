using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
using Gateway.Api.TokenRevocation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;
using SharedKernel;
using StackExchange.Redis;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

// JWT
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
var jwt = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>() ?? new JwtOptions();
if (string.IsNullOrEmpty(jwt.Secret) || jwt.Secret.Length < 32)
{
    if (builder.Environment.IsProduction())
        throw new InvalidOperationException("JWT Secret must be >=32 chars via JWT__Secret / Jwt:Secret (PORT-05 fail-fast)");
    jwt.Secret = "dev-jwt-secret-change-me-32chars-min";
}

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

// CORS
var corsOrigins = builder.Configuration["CORS_ORIGINS"] ?? "http://localhost:5173,http://localhost:3000,https://jp-web.vercel.app,https://job-platform-web.vercel.app";
var origins = corsOrigins.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
builder.Services.AddCors(o => o.AddPolicy("Default", p => p.WithOrigins(origins).AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

// Access-token revocation store (Redis when configured). Without REDIS_URL the
// gateway cannot detect revoked tokens; that is only acceptable outside Production.
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

    builder.Services.AddStackExchangeRedisCache(o => o.ConfigurationOptions = redisOptions);
    builder.Services.AddSingleton<ITokenRevocationStore, RedisTokenRevocationStore>();
}
else
{
    if (builder.Environment.IsProduction())
        throw new InvalidOperationException("REDIS_URL missing — required for access-token revocation (PORT-05 fail-fast)");

    builder.Services.AddSingleton<ITokenRevocationStore, NoopTokenRevocationStore>();
}

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwt.Issuer,
            ValidAudience = jwt.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Secret)),
            ClockSkew = TimeSpan.FromSeconds(30)
        };
        // Let gateway authenticate but not require auth globally; YARP will forward 401 as 401
        // Anonymous routes (auth login/register/refresh, job browsing, search) remain accessible.
        // Protected YARP routes opt in via AuthorizationPolicy "Authenticated".
        o.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var principal = context.Principal;
                var subject = principal?.FindFirstValue(ClaimTypes.NameIdentifier)
                              ?? principal?.FindFirstValue(JwtRegisteredClaimNames.Sub);
                if (principal is null || !Guid.TryParse(subject, out var userId))
                    return;

                var issuedAt = GetIssuedAt(principal);
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("TokenRevocation");

                try
                {
                    var store = context.HttpContext.RequestServices
                        .GetRequiredService<ITokenRevocationStore>();
                    var revokedAfter = await store.GetRevokedAfterAsync(
                        userId, context.HttpContext.RequestAborted);

                    if (revokedAfter is not null && issuedAt <= revokedAfter.Value.ToUnixTimeSeconds())
                    {
                        logger.LogWarning(
                            "Rejected revoked access token for user {UserId} (iat={IssuedAt}, revokedAfter={RevokedAfter})",
                            userId,
                            issuedAt,
                            revokedAfter.Value.ToUnixTimeSeconds());
                        context.Fail("Access token revoked");
                    }
                }
                catch (Exception ex)
                {
                    // Fail open on revocation-store outage: signature/lifetime were already validated.
                    logger.LogWarning(ex, "Token revocation check failed for user {UserId}", userId);
                }
            }
        };
    });
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("Authenticated", policy => policy.RequireAuthenticatedUser());

// ForwardedHeaders — behind Render edge so RemoteIpAddress reflects the real
// client IP (required for the per-IP limiter below to partition correctly).
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Clear();
    o.ForwardLimit = 1; // Cloud
});

// Coarse DDoS/bot layer: per-IP 600/min fixed window on every request (incl. YARP).
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, token) =>
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter =
                ((int)Math.Max(1, retryAfter.TotalSeconds)).ToString();
        }

        context.HttpContext.Response.ContentType = "application/json";
        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            status = 429,
            title = "Too Many Requests",
            detail = "Quota exceeded. Please wait before retrying."
        }, cancellationToken: token);
    };

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 600,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
});

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
            }

            return ValueTask.CompletedTask;
        });
    });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddHttpClient();

var app = builder.Build();

app.UseForwardedHeaders();

// Security Headers Middleware - Centralized security response headers
app.Use(async (context, next) =>
{
    // Authoritative indexer assignment to avoid duplicate headers from downstream YARP proxies
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";

    // Enforce HSTS (30 days) per RFC 6797: only over HTTPS connections in non-Development environments
    if (!app.Environment.IsDevelopment() && context.Request.IsHttps)
    {
        context.Response.Headers["Strict-Transport-Security"] = "max-age=2592000";
    }

    await next();
});

app.UseCors("Default");
app.UseRateLimiter();
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
        { "notif", config["GATEWAY_UPSTREAM_NOTIF"] ?? "http://localhost:5006" }
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

app.MapGet("/health", healthHandler);
app.MapGet("/api/health", healthHandler);
app.MapGet("/", () => Results.Ok(new { service = "gateway", version = "0.1.0" }));

app.MapReverseProxy();

app.Run();

static long GetIssuedAt(ClaimsPrincipal principal)
{
    var raw = principal.FindFirst(JwtRegisteredClaimNames.Iat)?.Value;
    if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var issuedAt))
        return issuedAt;

    // Missing iat is treated as epoch 0 so an existing revocation entry still rejects the token.
    return 0;
}

public partial class Program { }
