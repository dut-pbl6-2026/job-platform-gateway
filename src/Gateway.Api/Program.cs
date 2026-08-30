using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SharedKernel;

var builder = WebApplication.CreateBuilder(args);

// JWT
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
var jwt = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>() ?? new JwtOptions();
if (string.IsNullOrEmpty(jwt.Secret) || jwt.Secret.Length < 32)
    jwt.Secret = "dev-jwt-secret-change-me-32chars-min";

// Allow override via env GATEWAY_UPSTREAM_AUTH for prod Render public URL
var upstreamAuth = builder.Configuration["GATEWAY_UPSTREAM_AUTH"] ?? "http://localhost:5001";
if (!string.IsNullOrEmpty(upstreamAuth))
{
    // override cluster destination at runtime via config binding
    builder.Configuration["ReverseProxy:Clusters:auth:Destinations:auth1:Address"] = upstreamAuth;
}

// CORS
var corsOrigins = builder.Configuration["CORS_ORIGINS"] ?? "http://localhost:5173,http://localhost:3000,https://job-platform-web.vercel.app,https://job-platform-web-*.vercel.app";
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
            ClockSkew = TimeSpan.Zero
        };
        // Let gateway authenticate but not require auth globally; YARP will forward 401 as 401
        // Anonymous routes (login/register/refresh) remain accessible.
    });
builder.Services.AddAuthorization();

// YARP
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

app.UseCors("Default");
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "gateway" }));
app.MapGet("/", () => Results.Ok(new { service = "gateway", version = "0.1.0", upstreamAuth }));

app.MapReverseProxy(proxyPipeline =>
{
    // Optional: forward User claims as headers GW-01 X-User-Id/Role for downstream (future)
    proxyPipeline.Use((context, next) =>
    {
        if (context.User.Identity?.IsAuthenticated == true)
        {
            var sub = context.User.FindFirst("sub")?.Value ?? context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var role = context.User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value ?? context.User.FindFirst("role")?.Value;
            if (!string.IsNullOrEmpty(sub)) context.Request.Headers["X-User-Id"] = sub;
            if (!string.IsNullOrEmpty(role)) context.Request.Headers["X-User-Role"] = role;
        }
        return next();
    });
});

app.Run();

public partial class Program { }
