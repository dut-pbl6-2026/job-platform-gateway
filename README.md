# job-platform-gateway
.NET YARP Gateway — part of **Vietnam Job Platform** (`pbl6`) under [`dut-pbl6-2026`](https://github.com/dut-pbl6-2026).
- Tech: .NET YARP Gateway
- Branch flow: `feature/* → main` (see job-platform-docs/.github/git-strategy.md)
- Jira PBL6 skid.atlassian.net, Master plan docs/master-plan.md
- TM: TM1 Hoai, TM2 Thanh, TM3 Chi Bao, TM4 Khoa

## Health, logging, quality

- `GET /health` (and `/api/health`) — existing aggregated upstream status JSON.
- `GET /health/ready` — readiness: proxy routes/clusters loaded. Set `HEALTH_READY_CHECK_UPSTREAMS=true` to also probe upstream `/health` endpoints (reported as `Degraded`, never fails readiness).
- Logging: Serilog, compact JSON on console outside Development. Every request gets an `X-Correlation-Id` (taken from the request if safe, generated otherwise, echoed in the response, attached to log lines). Authorization headers/tokens are never logged.
- SonarCloud (optional): CI runs `dotnet-sonarscanner` only when the `SONAR_TOKEN` secret is available (skipped on fork PRs). Optional repo variables `SONAR_ORGANIZATION` (default `dut-pbl6-2026`) and `SONAR_PROJECT_KEY` (default `dut-pbl6-2026_job-platform-gateway`).
