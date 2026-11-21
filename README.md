# WFX Phantom Detector


**Open-source software supply-chain threat detection and GitHub repository security monitoring.**

WFX Phantom Detector is a defensive security application developed to identify suspicious activity associated with the WFX Phantom / wfx-loot supply-chain campaign.

It monitors GitHub events, repository changes, CI/CD workflows, dependency manifests, and known indicators of compromise to identify activity consistent with repository exploitation and credential-theft campaigns.

The project is developed by **REDΣ Ecosystems Research Collective**.

It operates as a real-time GitHub webhook detector for the **WFX Phantom / wfx-loot** supply-chain campaign (November 2026).

## Campaign Summary

| Metric | Value |
|---|---|
| Compromised accounts | 4,837 |
| Probe PRs opened | 63,000+ |
| Repositories with payload | 8,093+ |
| Campaign start | 2026-11-10 12:45 UTC |
| Reported mode | Telegram-only exfiltration (since 2026-11-12 05:30 UTC) |

### Detected Indicators of Compromise (IOCs)

- **Probe pull request:** Title `docs: dependency audit notes`, branch `wfx-docs`, file `docs/wfx-audit.md`.
- **Probe commit messages:** `ci: refresh build cache`, `chore: add ci helper`, `chore: add dependency audit workflow`, `ci: restore`, `ci: cleanup`.
- **Payload branches:** `chore/<8-alnum>` and `ci-check-<4-digit>`.
- **Payload files:** `.ci-<6-alnum>.sh`, `.github/workflows/build-audit-<6-alnum>.yml`, and `package.json` postinstall entries.
- **Command-and-control endpoints:** `194.150.166.244:8080`, `18.143.168.96:8080`, `153.75.82.159:8080`, `193.32.204.199:8080`.
- **Exfiltration:** Telegram Bot API and `/exfil` endpoint.
- **Known malicious package versions:** `digitalelvis/neuronai-studio@3.14.3`, `onuragtas/docker-env@v1.0.278` and `v1.0.280`, `vkuznet/gocurl@v0.0.0-20261111095532-8d5aad0cb0da`.

## Purpose

Software supply-chain attacks exploit the relationships between developers, repositories, build systems, dependencies, and deployment infrastructure.

WFX Phantom Detector provides an independent detection layer to help organizations identify suspicious activity within those relationships.

Its primary objectives are:

- Detect known indicators of supply-chain compromise.
- Identify suspicious repository and workflow activity.
- Monitor GitHub events through authenticated webhooks.
- Correlate activity associated with known attack patterns.
- Preserve detection findings for investigation.
- Support independent defensive research and incident response.

## Detection Capabilities

### GitHub Repository Monitoring

The detector processes GitHub webhook events to identify suspicious repository activity.

Supported event categories include:

| Event | Detection coverage |
|---|---|
| Pull requests | Known probe titles, suspicious branches, and associated actors |
| Push events | Suspicious commits, scripts, workflow files, and payload indicators |
| Workflow runs | Unexpected gaps in workflow-run numbering |
| Branch creation | Known suspicious branch naming patterns |
| Branch deletion | Activity consistent with attacker cleanup |

### Software Supply-Chain Analysis

Detection includes indicators associated with:

- Malicious dependency versions.
- Suspicious package installation scripts.
- Known malicious file hashes.
- Unauthorized CI/CD workflow modifications.
- Credential-exfiltration mechanisms.
- Known command-and-control endpoints.
- Campaign-specific file and branch patterns.

### Detection Coverage by Event

| Event type | Specific detections |
|---|---|
| `pull_request` | Probe PR titles, branch names (`wfx-docs`, `chore/*`, `ci-check-*`), compromised actors |
| `push` | Probe commit messages, malicious file additions (`.ci-*.sh`, `build-audit-*.yml`, GhostAction font) |
| `workflow_run` | Run-number gaps (potentially deleted workflow runs) |
| `create` | Suspicious branch creation |
| `delete` | Branch deletion consistent with attacker cleanup |
| Content scan | Five known script hashes, four C2 IPs, campaign markers, exfiltration endpoints, malicious packages |
| Package scan | Known malicious package versions |

### Content and Package Scanning

The application provides scanning endpoints for examining content and package metadata against its detection rules.

These capabilities support investigation outside the normal GitHub webhook event stream.

### Alert Generation

Detection findings can be recorded and delivered through configured alert webhooks.

Findings include information about the detected activity, associated indicators, and severity.

## System Architecture

```text
                  GitHub
                    |
              Webhook Events
                    |
                    v
             WFX Detector API
                    |
             Event Validation
                    |
                    v
              Detection Engine
                    |
          +---------+---------+
          |                   |
          v                   v
    Detection Rules     Event Correlation
          |                   |
          +---------+---------+
                    |
                    v
               Findings
                    |
          +---------+---------+
          |                   |
          v                   v
     Alert Storage       Alert Webhooks
          |                   |
          v                   v
      Query API         External Systems
```

The application uses Python, Flask, Gunicorn, and Redis.

## Repository Structure

The project source is organized as follows:

```text
wfx-detector/
├── app/
│   ├── __init__.py
│   ├── detector.py
│   └── server.py
├── tests/
│   ├── test_detector.py
│   ├── test_edge_cases.py
│   └── test_edge_cases_round2.py
├── .github/
│   └── workflows/
│       └── ci.yml
├── scripts/
│   └── quickstart.sh
├── infra/
├── Dockerfile
├── docker-compose.yml
├── github-app-manifest.json
├── pyproject.toml
├── requirements.txt
├── .env.example
├── DEPLOYMENT.md
├── LICENSE
└── README.md
```

## Requirements

The application is designed around:

- Python 3.11 or later.
- GitHub App integration.
- GitHub webhook signing secret.
- Redis for persistent storage.
- Docker and Docker Compose for container-based deployment.

## Quick Start

### 1. Create and install the GitHub App

1. Go to GitHub Settings → Developer settings → GitHub Apps → New GitHub App.
2. Use `github-app-manifest.json` as the template, updating its `url` to the deployment.
3. Install the App on target organizations or repositories.
4. Generate a private key and record the App ID.

### 2. Configure secrets

Example shell environment values (substitute real secrets):

```bash
export GITHUB_WEBHOOK_SECRET="your-webhook-secret-from-github-app"
export GITHUB_APP_ID="123456"
export GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\\n..."
export ALERT_WEBHOOK_URL="https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

The external alert destination is optional and may be a Slack, Discord, or PagerDuty webhook.

### 3. Deploy with Docker Compose

```bash
cp .env.example .env
# Edit .env: set GITHUB_WEBHOOK_SECRET, API_ALERT_TOKEN, REDIS_PASSWORD
docker compose up -d
curl http://localhost:8080/ready
```

A successful readiness response is `{"status":"ready"}`. Docker Compose requires the three listed secrets and does not publish the Redis port. The application fails startup when a configured Redis backend is unreachable rather than silently falling back to volatile storage. To develop locally without Redis, run the Flask application directly with `REDIS_URL` unset for in-memory development mode.

### 4. Set the webhook URL

Configure the GitHub App webhook URL as `https://your-domain/webhook`.

## Configuration

Environment-based configuration supports:

| Variable | Purpose |
|---|---|
| `GITHUB_WEBHOOK_SECRET` | Authenticate GitHub webhook payloads |
| `GITHUB_APP_ID` | GitHub App identification |
| `GITHUB_PRIVATE_KEY` | GitHub App private-key credentials |
| `API_ALERT_TOKEN` | Authentication for administrative API access |
| `REDIS_URL` | Redis connection |
| `REDIS_PASSWORD` | Redis server password in Docker Compose |
| `ALERT_WEBHOOK_URL` | Optional external alert destination |
| `DEDUP_WINDOW` | Finding deduplication window |
| `LOG_LEVEL` | Application logging level |
| `PORT` | Application listening port |

The repository includes `.env.example` as a configuration reference.

## API

Administrative endpoints (`/alerts`, `/metrics`, and `/scan/*`) require `API_ALERT_TOKEN` to be configured and the request header `X-API-Token: <token>`. Requests without required authorization return HTTP 401. All endpoints are rate-limited; the documented default is 100 requests per minute per client.

| Endpoint | Method | Authentication | Function |
|---|---|---|---|
| `/webhook` | POST | GitHub HMAC signature | Receive GitHub webhook events |
| `/health` | GET | None | Application liveness |
| `/ready` | GET | None | Readiness; HTTP 503 if storage is unavailable |
| `/alerts` | GET | `X-API-Token` | Retrieve recent detection findings (last 100) |
| `/alerts` | DELETE | `X-API-Token` | Clear stored alerts |
| `/metrics` | GET | `X-API-Token` | Retrieve storage / detector metrics |
| `/scan/content` | POST | `X-API-Token` | Analyze supplied file content for IOCs |
| `/scan/package` | POST | `X-API-Token` | Analyze package manifests and metadata |

## GitHub Integration

WFX Phantom Detector uses a GitHub App to receive repository events.

The supplied GitHub App manifest defines read-only access for repository contents, metadata, pull requests, workflows, actions, and repository hooks.

The detector does not require repository write access to process its supported webhook events.

## Testing

The repository includes automated tests covering detector functionality and edge cases.

The Python project defines test and development dependencies through `pyproject.toml`.

```bash
python -m pytest tests/
```

The GitHub Actions configuration includes automated testing and code-quality checks.

## Deployment

The project includes configuration and documentation for containerized deployment.

Deployment environments described in `DEPLOYMENT.md` include:

- Docker Compose
- Fly.io
- Render
- Kubernetes
- Self-hosted infrastructure

Detailed configuration, hosting examples, and operational information are maintained in [DEPLOYMENT.md](DEPLOYMENT.md).

## Production Hardening

1. **Redis:** Use Redis for persistent alert queues and workflow-run number tracking; see `docker-compose.yml`.
2. **TLS:** Terminate TLS at a load balancer such as nginx, Traefik, or Cloudflare.
3. **Rate limiting:** Apply rate limiting to the webhook endpoint.
4. **Structured logs:** Forward application logs to ELK, Datadog, or CloudWatch.
5. **Monitoring:** The `/metrics` endpoint provides detector metrics; Prometheus integration can be implemented with `prometheus-client`.
6. **Secret rotation:** Rotate webhook secrets and alert webhook destination credentials.

## Response Playbook

When a finding triggers:

1. **CRITICAL — probe PR or payload commit**
   - Revoke compromised account tokens.
   - Block the actor IP at the network level.
   - Check whether a payload executed, including workflow-run number gaps.
2. **HIGH — suspicious branch, file, or workflow gap**
   - Audit the repository for malicious changes.
   - Check cloud persistence in AWS, Azure, GCP, or Vault.
3. **MEDIUM/LOW — cleanup activity or `package.json` changes**
   - Review manually and correlate with other signals.

## Detection and Response

WFX Phantom Detector identifies suspicious activity and produces findings for investigation.

Detection alone does not establish that a repository, dependency, or account has been compromised. Findings support security investigation and incident-response decisions.

The detector is intended to operate as part of an organization's wider defensive security infrastructure.

## Development

The project supports continued development of detection rules, event correlation, repository monitoring, and integration capabilities.

Contributions may include additional indicators, detection tests, integrations, documentation, and improvements to operational reliability.

## Campaign Research References

- [Ostorlab Analysis](https://blog.ostorlab.co/wfx-phantom-github-actions-secret-stealer.html)
- [Semgrep Blog](https://semgrep.dev/blog/2026/seconds-from-disaster-wfx-phantom-and-the-ci-pipeline-nobody-was-watching/)
- [Aikido Research](https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories)
- [Corgea Report](https://corgea.com/research/wfx-phantom-wfx-loot-github-actions-secret-stealer-neuronai-studio-gocurl-redock-november-2026)
- [Endor Labs](https://www.endorlabs.com/learn/github-actions-supply-chain-attack-targeting-ci-secrets-at-scale)

## License

Copyright © 2026 REDΣ Ecosystems Research Collective.

WFX Phantom Detector is distributed under the **WFX Software License and Patent Non-Appropriation Addendum**.

The license permits research, modification, distribution, and commercial implementation subject to its terms.

It includes provisions covering patent non-appropriation, defensive use, protection of affected parties, and preservation of lawful remedies.

Defensive Patent License 1.1 is referenced as a separate patent licensing framework.

See [LICENSE](LICENSE) for the complete terms.

## Project

**WFX Phantom Detector**  
REDΣ Ecosystems Research Collective

Repository: https://github.com/chadcoulter/wfx-detector

**Defensive technology for protecting the integrity of software development and deployment infrastructure.**
