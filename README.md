# WFX Phantom Detector

Real-time GitHub webhook detector for the **WFX Phantom / wfx-loot** supply chain campaign (November 2026).

## Campaign Summary

| Metric | Value |
|--------|-------|
| Compromised accounts | 4,837 |
| Probe PRs opened | 63,000+ |
| Repositories with payload | 8,093+ |
| Campaign start | 2026-11-10 12:45 UTC |
| Current mode | Telegram-only exfiltration (since 2026-11-12 05:30 UTC) |

## Detected IOCs

- **Probe PR**: Title `"docs: dependency audit notes"`, branch `wfx-docs`, file `docs/wfx-audit.md`
- **Probe commits**: `ci: refresh build cache`, `chore: add ci helper`, `chore: add dependency audit workflow`, `ci: restore`, `ci: cleanup`
- **Payload branches**: `chore/<8-alnum>`, `ci-check-<4-digit>`
- **Payload files**: `.ci-<6-alnum>.sh`, `.github/workflows/build-audit-<6-alnum>.yml`, `package.json` (postinstall)
- **C2 IPs**: `194.150.166.244:8080`, `18.143.168.96:8080`, `153.75.82.159:8080`, `193.32.204.199:8080`
- **Exfiltration**: Telegram Bot API, `/exfil` endpoint
- **Malicious packages**: `digitalelvis/neuronai-studio@3.14.3`, `onuragtas/docker-env@v1.0.278/v1.0.280`, `vkuznet/gocurl@v0.0.0-20261111095532-8d5aad0cb0da`

## Quick Start

### 1. Create GitHub App

1. Go to GitHub Settings → Developer settings → GitHub Apps → New GitHub App
2. Use `github-app-manifest.json` as template (update `url` to your deployment)
3. Install on target organizations/repositories
4. Generate private key and note App ID

### 2. Configure Secrets

```bash
# Required
export GITHUB_WEBHOOK_SECRET="your-webhook-secret-from-github-app"
export GITHUB_APP_ID="123456"
export GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."

# Optional alerting (Slack/Discord/PagerDuty webhook)
export ALERT_WEBHOOK_URL="https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

### 3. Deploy with Docker Compose

```bash
cp .env.example .env
# Edit .env: set GITHUB_WEBHOOK_SECRET, API_ALERT_TOKEN, REDIS_PASSWORD
docker compose up -d
# Verify: curl http://localhost:8080/ready  -> {"status":"ready"}
```

Docker Compose requires all three secrets and does not publish the Redis port.
The app fails at startup if Redis is unreachable — it never silently degrades to
volatile storage. For local dev without Redis, run the Flask app directly with
`REDIS_URL` unset (in-memory dev mode).

### 4. Configure Webhook URL

Set the GitHub App webhook URL to: `https://your-domain/webhook`

## API Endpoints

Admin endpoints (`/alerts`, `/metrics`, `/scan/*`) require both a configured
`API_ALERT_TOKEN` and the `X-API-Token: <token>` header; they return 401 otherwise.
All endpoints are rate-limited (default 100 requests/minute per client).

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/webhook` | POST | HMAC signature | GitHub webhook receiver |
| `/health` | GET | none | Liveness check |
| `/ready` | GET | none | Readiness (503 if storage unavailable) |
| `/alerts` | GET | `X-API-Token` | Retrieve recent alerts (last 100) |
| `/alerts` | DELETE | `X-API-Token` | Clear alert queue |
| `/metrics` | GET | `X-API-Token` | Storage metrics |
| `/scan/content` | POST | `X-API-Token` | Scan file content for IOCs |
| `/scan/package` | POST | `X-API-Token` | Scan package manifest |

## Detection Coverage

| Event Type | Detections |
|------------|------------|
| `pull_request` | Probe PR titles, branch names (wfx-docs, chore/*, ci-check-*), compromised actors |
| `push` | Probe commit messages, malicious file additions (.ci-*.sh, build-audit-*.yml, GhostAction font) |
| `workflow_run` | Run number gaps (deleted workflow runs) |
| `create` | Suspicious branch creation |
| `delete` | Attacker cleanup (branch deletion) |
| Content scan | 5 known script hashes, 4 C2 IPs, campaign markers, exfil endpoints, malicious packages |
| Package scan | Known malicious package versions |

## Architecture

```
GitHub Events → Webhook → Flask App → Detector → Alert Webhook (Slack/Discord/PagerDuty)
                                    ↓
                              Alert Queue (in-memory/Redis)
                                    ↓
                              Dashboard / API polling
```

## Production Hardening

1. **Use Redis** for persistent alert queue and run-number tracking (see `docker-compose.yml`)
2. **TLS termination** at load balancer (nginx/Traefik/Cloudflare)
3. **Rate limiting** on webhook endpoint
4. **Structured logging** to ELK/Datadog/CloudWatch
5. **Metrics** via Prometheus (`/metrics` endpoint - add prometheus-client)
6. **Secret rotation** for webhook secret and alert webhook URL

## Response Playbook

When alerts fire:

1. **CRITICAL** (probe PR/payload commit): 
   - Revoke compromised account's tokens immediately
   - Block actor IP at network level
   - Check if payload executed (run number gaps)
   
2. **HIGH** (suspicious branch/file/workflow gap):
   - Audit repository for malicious changes
   - Check cloud persistence (AWS/Azure/GCP/Vault)

3. **MEDIUM/LOW** (cleanup, package.json changes):
   - Review manually, correlate with other signals

## References

- [Ostorlab Analysis](https://blog.ostorlab.co/wfx-phantom-github-actions-secret-stealer.html)
- [Semgrep Blog](https://semgrep.dev/blog/2026/seconds-from-disaster-wfx-phantom-and-the-ci-pipeline-nobody-was-watching/)
- [Aikido Research](https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories)
- [Corgea Report](https://corgea.com/research/wfx-phantom-wfx-loot-github-actions-secret-stealer-neuronai-studio-gocurl-redock-november-2026)
- [Endor Labs](https://www.endorlabs.com/learn/github-actions-supply-chain-attack-targeting-ci-secrets-at-scale)

## License

WFX Software License and Patent Non-Appropriation Addendum - see LICENSE. Use to defend against this campaign.