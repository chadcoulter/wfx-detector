# WFX Phantom Detector

**Open-source software supply-chain threat detection and GitHub repository security monitoring.**

WFX Phantom Detector is a defensive security application developed to identify suspicious activity associated with the WFX Phantom / wfx-loot supply-chain campaign.

It monitors GitHub events, repository changes, CI/CD workflows, dependency manifests, and known indicators of compromise to identify activity consistent with repository exploitation and credential-theft campaigns.

The project is developed by **REDΣ Ecosystems Research Collective**.

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

| Endpoint | Method | Function |
|---|---|---|
| `/webhook` | POST | Receive GitHub webhook events |
| `/health` | GET | Application health reporting |
| `/ready` | GET | Application readiness reporting |
| `/alerts` | GET | Retrieve detection findings |
| `/alerts` | DELETE | Clear stored alerts |
| `/metrics` | GET | Retrieve detector metrics |
| `/scan/content` | POST | Analyze supplied content |
| `/scan/package` | POST | Analyze package metadata |

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

## Detection and Response

WFX Phantom Detector identifies suspicious activity and produces findings for investigation.

Detection alone does not establish that a repository, dependency, or account has been compromised. Findings support security investigation and incident-response decisions.

The detector is intended to operate as part of an organization's wider defensive security infrastructure.

## Development

The project supports continued development of detection rules, event correlation, repository monitoring, and integration capabilities.

Contributions may include additional indicators, detection tests, integrations, documentation, and improvements to operational reliability.

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
