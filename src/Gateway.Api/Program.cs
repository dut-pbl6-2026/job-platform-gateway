using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;
using SharedKernel;
using Yarp.ReverseProxy.Transforms;
using System.Security.Claims;

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

// CORS
var corsOrigins = builder.Configuration["CORS_ORIGINS"] ?? "http://localhost:5173,http://localhost:3000,https://jp-web.vercel.app,https://job-platform-web.vercel.app";
var origins = corsOrigins.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
builder.Services.AddCors(o => o.AddPolicy("Default", p => p.WithOrigins(origins).AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

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

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "gateway" }));
app.MapGet("/", () => Results.Ok(new { service = "gateway", version = "0.1.0" }));

app.MapReverseProxy();

app.Run();

public partial class Program { }
