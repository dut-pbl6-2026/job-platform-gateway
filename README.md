# job-platform-gateway
.NET YARP Gateway — part of **Vietnam Job Platform** (`pbl6`) under [`dut-pbl6-2026`](https://github.com/dut-pbl6-2026).
- Tech: .NET YARP Gateway
- Configuration: the gateway holds no signing key. It validates RS256 access tokens against the public keys that auth-svc publishes. `Jwt__MetadataAddress` is required (auth-svc discovery URL, for example `http://auth-svc:5001/.well-known/openid-configuration`); the gateway will not start without it. Keys are refreshed at most every 15 minutes and on an unknown `kid`; without a loaded key set every token is refused (401).
- Access-token revocation and rate limiting: `REDIS_URL` (required in Production; same Redis as the auth service), optional `REDIS_PASSWORD` and `REDIS_DB`. Outside Production, without `REDIS_URL`, in-memory stores are used (single instance only). Redis errors fail open with a logged warning.
 `REDIS_URL` (required in Production; same Redis as the auth service), optional `REDIS_PASSWORD` and `REDIS_DB`. Outside Production, without `REDIS_URL`, an in-memory store is used. Redis errors fail open with a logged warning.
- Forwarded client IPs: `ForwardedHeaders__KnownNetworks` (required in Production) lists the proxy network(s) in front of the gateway, comma-separated CIDRs or addresses, e.g. `10.0.0.0/8`. Only those peers may set `X-Forwarded-For` and `X-Forwarded-Proto`; every other peer's headers are ignored. Outside Production, unset means loopback only.
- Branch flow: `feature/* → main` (see job-platform-docs/.github/git-strategy.md)
- Jira PBL6 skid.atlassian.net, Master plan docs/master-plan.md
- TM: TM1 Hoai, TM2 Thanh, TM3 Chi Bao, TM4 Khoa

## Health, logging, quality

- `GET /health` (and `/api/health`) — existing aggregated upstream status JSON.
- `GET /health/ready` — readiness: proxy routes/clusters loaded. Set `HEALTH_READY_CHECK_UPSTREAMS=true` to also probe upstream `/health` endpoints (reported as `Degraded`, never fails readiness).
- Logging: Serilog, compact JSON on console outside Development. Every request gets an `X-Correlation-Id` (taken from the request if safe, generated otherwise, echoed in the response, attached to log lines). Authorization headers/tokens are never logged.
- SonarCloud (optional): CI runs `dotnet-sonarscanner` only when the `SONAR_TOKEN` secret is available (skipped on fork PRs). Optional repo variables `SONAR_ORGANIZATION` (default `dut-pbl6-2026`) and `SONAR_PROJECT_KEY` (default `dut-pbl6-2026_job-platform-gateway`).
