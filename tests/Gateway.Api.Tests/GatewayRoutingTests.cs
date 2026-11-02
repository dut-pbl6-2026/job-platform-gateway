using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Yarp.ReverseProxy.Configuration;

namespace Gateway.Api.Tests;

/// <summary>
/// End-to-end tests for the gateway HTTP pipeline (YARP routing, JWT validation and
/// the claim -> X-User-Id/X-User-Role request transform).
///
/// A lightweight Kestrel "downstream" stub is started on a random port and injected
/// through the GATEWAY_UPSTREAM_PROFILE / GATEWAY_UPSTREAM_APP environment variables,
/// so requests that pass auth are actually forwarded and their injected headers can
/// be asserted. Tests in this class run sequentially (single class = single collection).
/// </summary>
public sealed class GatewayRoutingTests : IAsyncLifetime
{
    private const string Issuer = "job-platform";
    private const string Audience = "job-platform";
    private const string Secret = "dev-jwt-secret-change-me-32chars-min";

    private WebApplication _stub = null!;
    private string _stubAddress = null!;
    private WebApplicationFactory<Program> _factory = null!;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        _stub = builder.Build();
        _stub.Run(async ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status200OK;
            await ctx.Response.WriteAsJsonAsync(new
            {
                path = ctx.Request.Path.Value,
                userId = ctx.Request.Headers["X-User-Id"].ToString(),
                userRole = ctx.Request.Headers["X-User-Role"].ToString()
            });
        });
        await _stub.StartAsync();
        _stubAddress = _stub.Urls.First();

        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_PROFILE", _stubAddress);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_APP", _stubAddress);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_NOTIF", _stubAddress);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_JOB", _stubAddress);

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(b => b.UseEnvironment("Development"));
    }

    public async Task DisposeAsync()
    {
        _factory.Dispose();
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_PROFILE", null);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_APP", null);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_NOTIF", null);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_JOB", null);
        await _stub.DisposeAsync();
    }

    private HttpClient CreateClient() => _factory.CreateClient();

    private static string CreateToken(
        string sub = "user-123",
        string role = "User",
        string issuer = Issuer,
        string audience = Audience,
        TimeSpan? lifetime = null,
        TimeSpan? notBefore = null)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, sub),
            new(ClaimTypes.Role, role),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: DateTime.UtcNow.Add(notBefore ?? TimeSpan.FromMinutes(-1)),
            expires: DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromMinutes(30)),
            signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    [Fact]
    public async Task Health_ReturnsOk()
    {
        using var client = CreateClient();

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("/api/profiles/me")]
    [InlineData("/api/applications/me")]
    [InlineData("/api/notifications/history?page=1&size=5")]
    public async Task ProtectedRoute_WithoutToken_Returns401(string path)
    {
        using var client = CreateClient();

        var response = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("/api/auth/login")]
    [InlineData("/api/applications/status-flow")]
    public async Task AnonymousRoute_PassesAuthorization(string path)
    {
        using var client = CreateClient();

        var response = await client.GetAsync(path);

        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task PublicProfileRoute_WithoutToken_ForwardsToProfileCluster()
    {
        using var client = CreateClient();
        var userId = Guid.NewGuid();

        // PROFILE-01-06: GET /api/profiles/{userId:guid} is public (no PII).
        var response = await client.GetAsync($"/api/profiles/{userId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains($"/api/profiles/{userId}", body);
    }

    [Theory]
    [InlineData("/api/profiles/me")]
    [InlineData("/api/notifications/history")]
    public async Task ProtectedRoute_WithValidToken_ForwardsAndInjectsUserHeaders(string path)
    {
        using var client = CreateClient();
        var token = CreateToken(sub: "user-abc", role: "Recruiter");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains($"\"path\":\"{path}\"", body);
        Assert.Contains("\"userId\":\"user-abc\"", body);
        Assert.Contains("\"userRole\":\"Recruiter\"", body);
    }

    [Fact]
    public async Task ProtectedRoute_WithExpiredToken_Returns401()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", CreateToken(
                lifetime: TimeSpan.FromMinutes(-5),
                notBefore: TimeSpan.FromMinutes(-10)));

        var response = await client.GetAsync("/api/profiles/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedRoute_WithWrongIssuer_Returns401()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", CreateToken(issuer: "not-job-platform"));

        var response = await client.GetAsync("/api/profiles/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public void RouteConfig_RoutesApplicationsAndProfilesWithPolicies()
    {
        var provider = _factory.Services.GetRequiredService<IProxyConfigProvider>();
        var config = provider.GetConfig();

        var routes = config.Routes.ToDictionary(r => r.RouteId);
        Assert.Equal("app", routes["apps"].ClusterId);
        Assert.Equal("Authenticated", routes["apps"].AuthorizationPolicy);
        Assert.Equal("profile", routes["profiles"].ClusterId);
        Assert.Equal("Authenticated", routes["profiles"].AuthorizationPolicy);
        Assert.Equal("notif", routes["notifications"].ClusterId);
        Assert.Equal("Authenticated", routes["notifications"].AuthorizationPolicy);

        // status-flow must stay anonymous (exact match, no policy) while the
        // apps catch-all stays protected.
        Assert.Null(routes["app-status-flow"].AuthorizationPolicy);

        // PROFILE-01-06: GET /api/profiles/{userId:guid} stays anonymous while
        // the profiles catch-all (/me, skills, experiences, ...) stays protected.
        Assert.Equal("profile", routes["public-profile"].ClusterId);
        Assert.Null(routes["public-profile"].AuthorizationPolicy);
        Assert.Equal("/api/profiles/{userId:guid}", routes["public-profile"].Match.Path);

        var clusters = config.Clusters.ToDictionary(c => c.ClusterId);
        Assert.True(clusters.ContainsKey("app"));
        Assert.True(clusters.ContainsKey("profile"));
        Assert.True(clusters.ContainsKey("notif"));
        Assert.Contains(clusters["app"].Destinations!, d => d.Value.Address == _stubAddress);
        Assert.Contains(clusters["profile"].Destinations!, d => d.Value.Address == _stubAddress);
        Assert.Contains(clusters["notif"].Destinations!, d => d.Value.Address == _stubAddress);
    }

    // ---- PBL6-44: role policies -------------------------------------------------

    private static HttpRequestMessage Request(string method, string path, string? role)
    {
        var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (role is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken(role: role));
        }

        return request;
    }

    public static TheoryData<string, string> RecruiterRoutes => new()
    {
        { "POST", "/api/jobs" },
        { "GET", "/api/jobs/recruiter" },
        { "PUT", "/api/jobs/6f1b2c3d-0000-4000-8000-000000000001" },
        { "DELETE", "/api/jobs/6f1b2c3d-0000-4000-8000-000000000001" },
        { "POST", "/api/companies" },
        { "PUT", "/api/companies/6f1b2c3d-0000-4000-8000-000000000002" },
    };

    public static TheoryData<string, string> CandidateRoutes => new()
    {
        { "POST", "/api/applications" },
        { "GET", "/api/applications/me" },
    };

    [Theory]
    [MemberData(nameof(RecruiterRoutes))]
    public async Task RecruiterRoute_Anonymous_Returns401(string method, string path)
    {
        using var client = CreateClient();
        var response = await client.SendAsync(Request(method, path, role: null));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(RecruiterRoutes))]
    public async Task RecruiterRoute_WrongRole_Returns403(string method, string path)
    {
        using var client = CreateClient();
        foreach (var role in new[] { "User", "Admin" })
        {
            var response = await client.SendAsync(Request(method, path, role));
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
    }

    [Theory]
    [MemberData(nameof(RecruiterRoutes))]
    public async Task RecruiterRoute_RecruiterRole_IsForwarded(string method, string path)
    {
        using var client = CreateClient();
        var response = await client.SendAsync(Request(method, path, "Recruiter"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"userRole\":\"Recruiter\"", body);
    }

    [Theory]
    [MemberData(nameof(CandidateRoutes))]
    public async Task CandidateRoute_Anonymous_Returns401(string method, string path)
    {
        using var client = CreateClient();
        var response = await client.SendAsync(Request(method, path, role: null));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(CandidateRoutes))]
    public async Task CandidateRoute_WrongRole_Returns403(string method, string path)
    {
        using var client = CreateClient();
        var response = await client.SendAsync(Request(method, path, "Recruiter"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(CandidateRoutes))]
    public async Task CandidateRoute_UserRole_IsForwarded(string method, string path)
    {
        using var client = CreateClient();
        var response = await client.SendAsync(Request(method, path, "User"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"userRole\":\"User\"", body);
    }

    [Theory]
    [InlineData("GET", "/api/jobs")]
    [InlineData("GET", "/api/jobs/6f1b2c3d-0000-4000-8000-000000000001")]
    [InlineData("GET", "/api/companies")]
    [InlineData("GET", "/api/companies/6f1b2c3d-0000-4000-8000-000000000002")]
    public async Task PublicJobRoutes_Anonymous_StayOpen(string method, string path)
    {
        using var client = CreateClient();
        var response = await client.SendAsync(Request(method, path, role: null));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("User")]
    [InlineData("Recruiter")]
    [InlineData("Admin")]
    public async Task AmbiguousApplicationRoutes_StayOnAuthenticated_AnyRoleForwarded(string role)
    {
        using var client = CreateClient();
        var response = await client.SendAsync(Request("PUT",
            "/api/applications/6f1b2c3d-0000-4000-8000-000000000003/status", role));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public void RouteConfig_RolePoliciesAreAssigned()
    {
        var routes = _factory.Services.GetRequiredService<IProxyConfigProvider>()
            .GetConfig().Routes.ToDictionary(r => r.RouteId);
        foreach (var id in new[] { "jobs-create", "jobs-recruiter", "jobs-write", "companies-create", "companies-update" })
            Assert.Equal("Recruiter", routes[id].AuthorizationPolicy);
        foreach (var id in new[] { "apps-apply", "apps-me" })
            Assert.Equal("User", routes[id].AuthorizationPolicy);
        // Catch-alls stay as before.
        Assert.Null(routes["jobs"].AuthorizationPolicy);
        Assert.Equal("Authenticated", routes["apps"].AuthorizationPolicy);
    }
}
