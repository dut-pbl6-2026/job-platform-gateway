using System.Collections.Concurrent;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
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
    // The shared HMAC secret that HS256 used to rely on. Tokens signed with it must be rejected.
    private const string RetiredHmacSecret = "dev-jwt-secret-change-me-32chars-min";

    private WebApplication _stub = null!;
    private string _stubAddress = null!;
    private GatewayTestFactory _factory = null!;
    // Held open after the first SSE frame so a test can prove the gateway forwarded it instead of buffering.
    private TaskCompletionSource _sseGate = null!;
    // "METHOD /path" for every request the downstream stub receives, so tests can prove a request was not forwarded.
    private readonly ConcurrentQueue<string> _forwarded = new();

    public async Task InitializeAsync()
    {
        _sseGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        _stub = builder.Build();
        var forwarded = _forwarded;
        _stub.Run(async ctx =>
        {
            forwarded.Enqueue($"{ctx.Request.Method} {ctx.Request.Path}");
            if (ctx.Request.Path == "/api/ai/chat")
            {
                // ai-svc's SSE shape: text/event-stream, no Content-Length, no-cache, one block per event.
                ctx.Response.StatusCode = StatusCodes.Status200OK;
                ctx.Response.ContentType = "text/event-stream";
                ctx.Response.Headers.CacheControl = "no-cache";
                ctx.Response.Headers["X-Accel-Buffering"] = "no";
                await ctx.Response.WriteAsync("event: token\ndata: {\"delta\":\"Một\"}\n\n");
                await ctx.Response.Body.FlushAsync();
                await _sseGate.Task.WaitAsync(TimeSpan.FromSeconds(10)); // 10 s cap so a failure cannot hang the suite
                await ctx.Response.WriteAsync("event: done\ndata: {\"sessionId\":\"s-1\",\"done\":true}\n\n");
                return;
            }
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
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_AI", _stubAddress);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_SEARCH", _stubAddress);

        _factory = new GatewayTestFactory();
    }

    public async Task DisposeAsync()
    {
        _factory.Dispose();
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_PROFILE", null);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_APP", null);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_NOTIF", null);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_JOB", null);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_AI", null);
        Environment.SetEnvironmentVariable("GATEWAY_UPSTREAM_SEARCH", null);
        await _stub.DisposeAsync();
    }

    private HttpClient CreateClient() => _factory.CreateClient();

    private static string CreateToken(
        string sub = "user-123",
        string role = "User",
        string issuer = Issuer,
        string audience = Audience,
        TimeSpan? lifetime = null,
        TimeSpan? notBefore = null,
        DateTimeOffset? issuedAt = null,
        RSA? signingKey = null,
        string? kid = TestSigningKeys.Kid)
    {
        var key = new RsaSecurityKey(signingKey ?? TestSigningKeys.Current) { KeyId = kid };
        var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
        return WriteToken(credentials, sub, role, issuer, audience, lifetime, notBefore, issuedAt);
    }

    private static string CreateHs256Token(string sub = "user-123", string role = "User") =>
        WriteToken(
            new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(RetiredHmacSecret)), SecurityAlgorithms.HmacSha256),
            sub, role, Issuer, Audience, lifetime: null, notBefore: null, issuedAt: null);

    private static string WriteToken(
        SigningCredentials credentials,
        string sub,
        string role,
        string issuer,
        string audience,
        TimeSpan? lifetime,
        TimeSpan? notBefore,
        DateTimeOffset? issuedAt)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, sub),
            new(ClaimTypes.Role, role),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        if (issuedAt is { } iat)
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, iat.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));
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
    [InlineData("/api/ai/health")]
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

    [Theory]
    [InlineData("/api/auth/register-company")]
    [InlineData("/api/auth/verify-email")]
    public async Task AnonymousAuthSignupRoutes_PassWithoutToken(string path)
    {
        // Auth upstream is not stubbed in this class, so the request may fail upstream (502); it must not be refused by the gateway.
        using var client = CreateClient();
        var response = await client.PostAsync(path, new StringContent("{}", Encoding.UTF8, "application/json"));
        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.NotEqual(HttpStatusCode.Forbidden, response.StatusCode);
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
    [InlineData("/api/ai/health")]
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
    public async Task ProtectedRoute_Hs256Token_Returns401()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", CreateHs256Token(role: "Admin"));

        var response = await client.GetAsync("/api/admin/stats");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedRoute_Rs256TokenFromUnknownKey_Returns401()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", CreateToken(role: "Admin", signingKey: TestSigningKeys.Foreign));

        var response = await client.GetAsync("/api/admin/stats");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedRoute_Rs256TokenWithoutKid_Returns401()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", CreateToken(role: "Admin", kid: null));

        var response = await client.GetAsync("/api/admin/stats");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedRoute_Rs256TokenWithUnpublishedKid_Returns401()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", CreateToken(role: "Admin", kid: "not-published"));

        var response = await client.GetAsync("/api/admin/stats");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedRoute_ValidRs256TokenFromJwks_IsForwarded()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", CreateToken(sub: "cand-jwks", role: "User"));

        var response = await client.GetAsync("/api/applications/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedRoute_ValidTokenWhileJwksUnavailable_Returns401()
    {
        // Fail closed: with no key set loaded, even a correctly signed token must be refused.
        using var unavailable = GatewayTestFactory.WithUnavailableJwks();
        using var client = unavailable.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", CreateToken(role: "User"));

        var response = await client.GetAsync("/api/applications/me");

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

    [Fact]
    public void RouteConfig_RoutesAiToAiClusterWithAuthenticatedPolicy()
    {
        var config = _factory.Services.GetRequiredService<IProxyConfigProvider>().GetConfig();

        var routes = config.Routes.ToDictionary(r => r.RouteId);
        Assert.Equal("ai", routes["ai"].ClusterId);
        Assert.Equal("Authenticated", routes["ai"].AuthorizationPolicy);
        Assert.Equal("/api/ai/{**catch-all}", routes["ai"].Match.Path);

        var clusters = config.Clusters.ToDictionary(c => c.ClusterId);
        Assert.Contains(clusters["ai"].Destinations!, d => d.Value.Address == _stubAddress);

        // SSE: response buffering must stay off and the idle window must outlast YARP's 100 s default.
        var aiRequest = clusters["ai"].HttpRequest;
        Assert.NotNull(aiRequest);
        Assert.False(aiRequest.AllowResponseBuffering);
        Assert.Equal(TimeSpan.FromMinutes(5), aiRequest.ActivityTimeout);
    }

    [Fact]
    public async Task AiScoreResume_WithToken_ForwardsMultipartPathUnchanged()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", CreateToken(sub: "cand-1", role: "User"));
        using var form = new MultipartFormDataContent
        {
            { new ByteArrayContent(new byte[1024]), "cv_file", "cv.pdf" },
            { new StringContent(Guid.NewGuid().ToString()), "job_id" }
        };

        var response = await client.PostAsync("/api/ai/score-resume", form);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"path\":\"/api/ai/score-resume\"", body);
        Assert.Contains("\"userId\":\"cand-1\"", body);
    }

    [Fact]
    public async Task AiChat_StreamsSseThroughTheGatewayWithoutBuffering()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", CreateToken(sub: "cand-sse", role: "User"));
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/ai/chat")
        {
            Content = JsonContent.Create(new { message = "tìm việc Java ở Hà Nội", stream = true })
        };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType?.MediaType);
        Assert.Null(response.Content.Headers.ContentLength); // chunked: SSE has no length up front
        Assert.Contains("no-cache", response.Headers.CacheControl?.ToString() ?? string.Empty);
        Assert.Equal("no", Assert.Single(response.Headers.GetValues("X-Accel-Buffering")));

        await using var stream = await response.Content.ReadAsStreamAsync(cts.Token);
        using var reader = new StreamReader(stream);
        Assert.Equal("event: token", await reader.ReadLineAsync(cts.Token));
        Assert.Equal("data: {\"delta\":\"Một\"}", await reader.ReadLineAsync(cts.Token));

        // The stub is still holding the stream open, so the first frame can only be here now if the
        // gateway forwarded it as it arrived instead of buffering the whole response.
        Assert.False(_sseGate.Task.IsCompleted);
        Assert.Contains("POST /api/ai/chat", _forwarded);

        _sseGate.SetResult();
        var rest = await reader.ReadToEndAsync(cts.Token);
        Assert.Contains("event: done", rest);
        Assert.Contains("\"sessionId\":\"s-1\"", rest);
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
        { "POST", "/api/companies/6f1b2c3d-0000-4000-8000-000000000002/invite-codes" },
        { "GET", "/api/companies/6f1b2c3d-0000-4000-8000-000000000002/join-requests" },
        { "POST", "/api/companies/6f1b2c3d-0000-4000-8000-000000000002/join-requests/6f1b2c3d-0000-4000-8000-000000000008/approve" },
        { "POST", "/api/companies/6f1b2c3d-0000-4000-8000-000000000002/join-requests/6f1b2c3d-0000-4000-8000-000000000008/reject" },
    };

    public static TheoryData<string, string> CandidateRoutes => new()
    {
        { "POST", "/api/applications" },
        { "GET", "/api/applications/me" },
        { "GET", "/api/jobs/recommended" },
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

    [Fact]
    public async Task JobsRecommended_AdminRole_Returns403()
    {
        using var client = CreateClient();
        var response = await client.SendAsync(Request("GET", "/api/jobs/recommended", "Admin"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task JobsRecommended_PostIsNotForwardedAnonymously()
    {
        // Only GET is restricted to job seekers. The anonymous `jobs` catch-all is GET/HEAD only,
        // so POST to this path must not reach job-svc without a token.
        using var client = CreateClient();
        var response = await client.SendAsync(Request("POST", "/api/jobs/recommended", role: null));
        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
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
        foreach (var id in new[] { "jobs-create", "jobs-recruiter", "jobs-write", "companies-create", "companies-update", "companies-join-requests", "companies-join-requests-decide" })
            Assert.Equal("Recruiter", routes[id].AuthorizationPolicy);
        foreach (var id in new[] { "companies-me-join-request", "companies-me-join-request-escalate" })
            Assert.Equal("Authenticated", routes[id].AuthorizationPolicy);
        foreach (var id in new[] { "apps-apply", "apps-me", "jobs-recommended" })
            Assert.Equal("User", routes[id].AuthorizationPolicy);
        // Catch-alls stay as before.
        Assert.Null(routes["jobs"].AuthorizationPolicy);
        Assert.Equal("Authenticated", routes["apps"].AuthorizationPolicy);
    }

    [Theory]
    [InlineData("PATCH", "/api/jobs/6f1b2c3d-0000-4000-8000-000000000001")]
    [InlineData("DELETE", "/api/companies/6f1b2c3d-0000-4000-8000-000000000002")]
    [InlineData("PATCH", "/api/companies/6f1b2c3d-0000-4000-8000-000000000002")]
    [InlineData("POST", "/api/jobs/6f1b2c3d-0000-4000-8000-000000000001")]
    [InlineData("DELETE", "/api/categories/6f1b2c3d-0000-4000-8000-000000000004")]
    [InlineData("POST", "/api/categories")]
    public async Task CatalogRoutes_UnsupportedWriteVerbs_AreNotForwarded(string method, string path)
    {
        // job-svc has no such endpoint, and the anonymous catch-all is GET/HEAD only. YARP answers 405
        // for a matched path with a disallowed method, so nothing is forwarded, with or without a token.
        using var client = CreateClient();

        var anonymous = await client.SendAsync(Request(method, path, role: null));
        Assert.Equal(HttpStatusCode.MethodNotAllowed, anonymous.StatusCode);

        var recruiter = await client.SendAsync(Request(method, path, "Recruiter"));
        Assert.Equal(HttpStatusCode.MethodNotAllowed, recruiter.StatusCode);
    }

    [Theory]
    [InlineData("HEAD", "/api/jobs")]
    [InlineData("GET", "/api/categories")]
    public async Task CatalogRoutes_ReadMethods_StayOpen(string method, string path)
    {
        using var client = CreateClient();
        var response = await client.SendAsync(Request(method, path, role: null));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task TelegramWebhook_IsAnonymousAndForwarded_WhileNotificationsStayProtected()
    {
        using var client = CreateClient();

        // Telegram calls the webhook without a JWT; the notif service validates its own secret header.
        var webhook = await client.SendAsync(Request("POST", "/api/notifications/telegram/webhook", role: null));
        Assert.Equal(HttpStatusCode.OK, webhook.StatusCode);

        // Every other notifications path still requires a JWT.
        var history = await client.SendAsync(Request("GET", "/api/notifications/history", role: null));
        Assert.Equal(HttpStatusCode.Unauthorized, history.StatusCode);
    }

    [Fact]
    public void RouteConfig_TelegramWebhookIsAnonymousAndOrderedFirst()
    {
        var routes = _factory.Services.GetRequiredService<IProxyConfigProvider>()
            .GetConfig().Routes.ToDictionary(r => r.RouteId);
        Assert.Null(routes["notifications-telegram-webhook"].AuthorizationPolicy);
        Assert.Equal("notif", routes["notifications-telegram-webhook"].ClusterId);
        Assert.Equal("Authenticated", routes["notifications"].AuthorizationPolicy);
        // Unset Order sorts last in YARP, so the webhook (Order -1) must beat the unordered catch-all.
        Assert.True(routes["notifications-telegram-webhook"].Order < (routes["notifications"].Order ?? int.MaxValue));
    }

    // ---- Company join requests (AUTH-01-12..14): requester routes are Authenticated, admin routes are Recruiter ----

    public static TheoryData<string, string> RequesterRoutes => new()
    {
        { "GET", "/api/companies/me/join-request" },
        { "HEAD", "/api/companies/me/join-request" },
        { "POST", "/api/companies/me/join-request" },
        { "POST", "/api/companies/me/join-request/escalate" },
        { "GET", "/api/companies/me/join-request/escalate" },
        { "HEAD", "/api/companies/me/join-request/escalate" },
    };

    [Theory]
    [MemberData(nameof(RequesterRoutes))]
    public async Task RequesterRoute_Anonymous_Returns401AndIsNotForwarded(string method, string path)
    {
        // The anonymous `companies` catch-all (GET/HEAD) must not capture these paths.
        using var client = CreateClient();
        var response = await client.SendAsync(Request(method, path, role: null));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain($"{method} {path}", _forwarded);
    }

    [Theory]
    [InlineData("User")]
    [InlineData("Recruiter")]
    [InlineData("Admin")]
    public async Task RequesterRoute_AnyRole_IsForwarded(string role)
    {
        using var client = CreateClient();
        var response = await client.SendAsync(Request("GET", "/api/companies/me/join-request", role));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("GET /api/companies/me/join-request", _forwarded);

        var escalate = await client.SendAsync(Request("POST", "/api/companies/me/join-request/escalate", role));
        Assert.Equal(HttpStatusCode.OK, escalate.StatusCode);
        Assert.Contains("POST /api/companies/me/join-request/escalate", _forwarded);
    }

    [Theory]
    [InlineData("GET", "/api/companies/6f1b2c3d-0000-4000-8000-000000000002/join-requests")]
    [InlineData("HEAD", "/api/companies/6f1b2c3d-0000-4000-8000-000000000002/join-requests")]
    [InlineData("POST", "/api/companies/6f1b2c3d-0000-4000-8000-000000000002/join-requests/6f1b2c3d-0000-4000-8000-000000000008/approve")]
    [InlineData("GET", "/api/companies/6f1b2c3d-0000-4000-8000-000000000002/join-requests/6f1b2c3d-0000-4000-8000-000000000008/reject")]
    public async Task JoinRequestAdminRoute_Anonymous_Returns401AndIsNotForwarded(string method, string path)
    {
        using var client = CreateClient();
        var response = await client.SendAsync(Request(method, path, role: null));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain($"{method} {path}", _forwarded);
    }

    [Fact]
    public void RouteConfig_CompanyRoutesAreNotOnTheAnonymousCatchAll()
    {
        var routes = _factory.Services.GetRequiredService<IProxyConfigProvider>()
            .GetConfig().Routes.ToDictionary(r => r.RouteId);
        Assert.Null(routes["companies"].AuthorizationPolicy);
        Assert.Equal(new[] { "GET", "HEAD" }, routes["companies"].Match.Methods!.OrderBy(m => m, StringComparer.Ordinal));
    }

    // ---- Invite codes: issue is a Recruiter write on the job cluster; auth-svc's internal endpoints are never public ----

    [Fact]
    public async Task IssueInviteCode_RecruiterToken_ForwardsToJobCluster()
    {
        var companyId = "6f1b2c3d-0000-4000-8000-000000000006";
        var path = $"/api/companies/{companyId}/invite-codes";
        using var client = CreateClient();

        var response = await client.SendAsync(Request("POST", path, "Recruiter"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains($"POST {path}", _forwarded);
    }

    [Fact]
    public async Task IssueInviteCode_Anonymous_IsRejectedAndNotForwarded()
    {
        var path = "/api/companies/6f1b2c3d-0000-4000-8000-000000000006/invite-codes";
        using var client = CreateClient();

        var response = await client.SendAsync(Request("POST", path, role: null));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain($"POST {path}", _forwarded);
    }

    [Theory]
    [InlineData("POST", "/api/internal/invite-codes/check")]
    [InlineData("POST", "/api/internal/invite-codes/redeem")]
    [InlineData("POST", "/api/internal/invite-codes/6f1b2c3d-0000-4000-8000-000000000007/release")]
    [InlineData("POST", "/api/internal/companies")]
    [InlineData("POST", "/api/internal/companies/domain-match")]
    [InlineData("GET", "/api/internal/companies/availability?companyName=Acme")]
    [InlineData("POST", "/api/internal/company-join-requests")]
    [InlineData("POST", "/api/internal/company-join-requests/6f1b2c3d-0000-4000-8000-000000000008/support-decision")]
    [InlineData("POST", "/api/internal/users/6f1b2c3d-0000-4000-8000-000000000009/link-company")]
    public async Task InternalInviteCodeEndpoints_AreNotRouted_WithOrWithoutToken(string method, string path)
    {
        using var client = CreateClient();

        var anonymous = await client.SendAsync(Request(method, path, role: null));
        var admin = await client.SendAsync(Request(method, path, "Admin"));

        Assert.Equal(HttpStatusCode.NotFound, anonymous.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, admin.StatusCode);
        Assert.DoesNotContain($"{method} {path}", _forwarded);
    }

    [Fact]
    public void RouteConfig_NoRouteMatchesInternalPaths()
    {
        var config = _factory.Services.GetRequiredService<IProxyConfigProvider>().GetConfig();

        Assert.DoesNotContain(config.Routes, r => r.Match.Path?.StartsWith("/api/internal", StringComparison.Ordinal) == true);
    }

    // ---- Search: index writes are internal-only and must not be routed through the public gateway ----

    [Theory]
    [InlineData("POST", "/api/search/index")]
    [InlineData("POST", "/api/search/bulk-index")]
    [InlineData("DELETE", "/api/search/index/6f1b2c3d-0000-4000-8000-000000000005")]
    public async Task SearchIndexWrites_AreNotForwarded_WithOrWithoutToken(string method, string path)
    {
        // The search catch-all is GET/HEAD only, so YARP answers 405 and nothing reaches search-svc.
        using var client = CreateClient();

        var anonymous = await client.SendAsync(Request(method, path, role: null));
        Assert.Equal(HttpStatusCode.MethodNotAllowed, anonymous.StatusCode);

        var admin = await client.SendAsync(Request(method, path, "Admin"));
        Assert.Equal(HttpStatusCode.MethodNotAllowed, admin.StatusCode);

        Assert.DoesNotContain($"{method} {path}", _forwarded);
    }

    [Theory]
    [InlineData("GET", "/api/search/jobs")]
    [InlineData("HEAD", "/api/search/suggest")]
    public async Task SearchReads_StayOpenAndAreForwarded(string method, string path)
    {
        // Positive control for the test above: read methods on the same route still reach search-svc.
        using var client = CreateClient();
        var response = await client.SendAsync(Request(method, path, role: null));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains($"{method} {path}", _forwarded);
    }

    [Fact]
    public void RouteConfig_SearchRouteIsAnonymousReadOnly()
    {
        var config = _factory.Services.GetRequiredService<IProxyConfigProvider>().GetConfig();

        var searchRoutes = config.Routes.Where(r => r.Match.Path?.StartsWith("/api/search", StringComparison.Ordinal) == true).ToList();
        var route = Assert.Single(searchRoutes);
        Assert.Equal("search", route.ClusterId);
        Assert.Null(route.AuthorizationPolicy);
        Assert.NotNull(route.Match.Methods);
        Assert.Equal(new[] { "GET", "HEAD" }, route.Match.Methods.OrderBy(m => m, StringComparer.Ordinal));
    }

    private static string RevocationKey(Guid userId) => $"job-platform:auth:revoked-after:{userId:D}";

    [Fact]
    public async Task RevokedUser_TokenIssuedBeforeRevocation_Returns401()
    {
        var userId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var cache = _factory.Services.GetRequiredService<IDistributedCache>();
        await cache.SetStringAsync(RevocationKey(userId), now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));

        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            CreateToken(sub: userId.ToString(), issuedAt: now.AddHours(-1)));

        var response = await client.GetAsync("/api/profiles/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RevokedUser_TokenIssuedAfterRevocation_Returns200()
    {
        // Proves the iat claim is read: the same revocation entry does not reject a newer token.
        var userId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var cache = _factory.Services.GetRequiredService<IDistributedCache>();
        await cache.SetStringAsync(RevocationKey(userId), now.AddHours(-1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));

        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            CreateToken(sub: userId.ToString(), issuedAt: now));

        var response = await client.GetAsync("/api/profiles/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task OtherUsersToken_IsNotAffectedByRevocation_Returns200()
    {
        var revokedUser = Guid.NewGuid();
        var otherUser = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var cache = _factory.Services.GetRequiredService<IDistributedCache>();
        await cache.SetStringAsync(RevocationKey(revokedUser), now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));

        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            CreateToken(sub: otherUser.ToString(), issuedAt: now.AddHours(-1)));

        var response = await client.GetAsync("/api/profiles/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
