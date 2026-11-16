using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Configuration;

namespace Gateway.Api.Tests;

/// <summary>
/// Contract: the public route table is part of the gateway's external behaviour. Each line is
/// RouteId|ClusterId|Path|Methods|AuthorizationPolicy|Order. Changing a route is a deliberate edit here.
/// </summary>
public class RouteContractTests : IClassFixture<GatewayTestFactory>
{
    private static readonly string[] ExpectedRoutes =
    [
            "admin-jobs|job|/api/admin/jobs/{**catch-all}||Admin|",
            "admin-stats|auth|/api/admin/stats||Admin|",
            "admin-users|auth|/api/admin/users/{**catch-all}||Admin|",
            "ai|ai|/api/ai/{**catch-all}||Authenticated|",
            "app-status-flow|app|/api/applications/status-flow|||",
            "apps|app|/api/applications/{**catch-all}||Authenticated|",
            "apps-apply|app|/api/applications|POST|User|",
            "apps-me|app|/api/applications/me|GET|User|",
            "auth|auth|/api/auth/{**catch-all}|||",
            "categories|job|/api/categories/{**catch-all}|GET|HEAD||",
            "companies|job|/api/companies/{**catch-all}|GET|HEAD||",
            "companies-create|job|/api/companies|POST|Recruiter|",
            "companies-invite-codes|job|/api/companies/{id:guid}/invite-codes|POST|Recruiter|",
            "companies-join-requests|job|/api/companies/{id:guid}/join-requests||Recruiter|",
            "companies-join-requests-decide|job|/api/companies/{id:guid}/join-requests/{**catch-all}||Recruiter|",
            "companies-me-join-request|job|/api/companies/me/join-request||Authenticated|",
            "companies-me-join-request-escalate|job|/api/companies/me/join-request/escalate||Authenticated|",
            "companies-mine|job|/api/companies/mine|GET|Recruiter|",
            "companies-update|job|/api/companies/{id:guid}|PUT|Recruiter|",
            "health-auth|auth|/health/auth|||",
            "jobs|job|/api/jobs/{**catch-all}|GET|HEAD||",
            "jobs-create|job|/api/jobs|POST|Recruiter|",
            "jobs-recommended|job|/api/jobs/recommended|GET|User|",
            "jobs-recruiter|job|/api/jobs/recruiter|GET|Recruiter|",
            "jobs-write|job|/api/jobs/{id:guid}|PUT|DELETE|Recruiter|",
            "notifications|notif|/api/notifications/{**catch-all}||Authenticated|",
            "notifications-telegram-webhook|notif|/api/notifications/telegram/webhook|||-1",
            "profiles|profile|/api/profiles/{**catch-all}||Authenticated|",
            "public-profile|profile|/api/profiles/{userId:guid}|GET||",
            "search|search|/api/search/{**catch-all}|GET|HEAD||",
    ];

    private readonly GatewayTestFactory _factory;

    public RouteContractTests(GatewayTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public void RouteTable_MatchesContract()
    {
        var config = _factory.Services.GetRequiredService<IProxyConfigProvider>().GetConfig();

        var actual = config.Routes
            .OrderBy(r => r.RouteId, StringComparer.Ordinal)
            .Select(r => string.Join('|',
                r.RouteId,
                r.ClusterId,
                r.Match.Path,
                r.Match.Methods is null ? string.Empty : string.Join('|', r.Match.Methods),
                r.AuthorizationPolicy ?? string.Empty,
                r.Order?.ToString() ?? string.Empty))
            .ToArray();

        Assert.Equal(ExpectedRoutes, actual);
    }
}
