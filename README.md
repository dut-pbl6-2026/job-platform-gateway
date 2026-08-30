# job-platform-gateway
.NET YARP Gateway — part of **Vietnam Job Platform** (`pbl6`) under [`dut-pbl6-2026`](https://github.com/dut-pbl6-2026).
- Tech: .NET YARP Gateway
- Branch flow: `feature/* → main` (see job-platform-docs/.github/git-strategy.md)
- Jira PBL6 skid.atlassian.net, Master plan docs/master-plan.md
- TM: TM1 Hoai, TM2 Thanh, TM3 Chi Bao, TM4 Khoa

## Deploy (Render Free jp-gateway — TM1 Hoai)
- Service: `jp-gateway` `https://jp-gateway.onrender.com` `5000` YARP `GATEWAY_UPSTREAM_AUTH=https://jp-auth.onrender.com` + `jp-job/search/app/profile/notif` via `https://jp-*.onrender.com` (Free no private network)
- Env: `JWT_SECRET` `CORS_ORIGINS=https://jp-web.vercel.app` `GATEWAY_UPSTREAM_*`
- Hook: `RENDER_DEPLOY_HOOK_GATEWAY` → `push main` auto
