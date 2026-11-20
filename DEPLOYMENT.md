# Deployment Guide

## Platform Options

### 1. Fly.io (Recommended - Free tier available)

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login
flyctl auth login

# Create app
flyctl apps create wfx-detector --org personal

# Set secrets
flyctl secrets set GITHUB_WEBHOOK_SECRET="your-secret" \
  GITHUB_APP_ID="123456" \
  GITHUB_PRIVATE_KEY="$(cat private-key.pem)" \
  ALERT_WEBHOOK_URL="https://hooks.slack.com/..."

# Deploy
flyctl deploy --image ghcr.io/your-org/wfx-detector:latest

# Get URL
flyctl info --app wfx-detector
# Use the hostname for GitHub App webhook URL
```

**fly.toml** (create in project root):
```toml
app = "wfx-detector"
primary_region = "iad"

[build]
  image = "ghcr.io/your-org/wfx-detector:latest"

[env]
  PORT = "8080"
  LOG_LEVEL = "INFO"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 1
  processes = ["app"]

[[vm]]
  memory = "256mb"
  cpu_kind = "shared"
  cpus = 1
```

### 2. Render.com

```yaml
# render.yaml
services:
  - type: web
    name: wfx-detector
    env: docker
    dockerfilePath: ./Dockerfile
    plan: free
    envVars:
      - key: GITHUB_WEBHOOK_SECRET
        sync: false
      - key: GITHUB_APP_ID
        sync: false
      - key: GITHUB_PRIVATE_KEY
        sync: false
      - key: ALERT_WEBHOOK_URL
        sync: false
    healthCheckPath: /health
    autoDeploy: true
```

### 3. Kubernetes (Generic)

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wfx-detector
  labels:
    app: wfx-detector
spec:
  replicas: 2
  selector:
    matchLabels:
      app: wfx-detector
  template:
    metadata:
      labels:
        app: wfx-detector
    spec:
      containers:
      - name: detector
        image: ghcr.io/your-org/wfx-detector:latest
        ports:
        - containerPort: 8080
        envFrom:
        - secretRef:
            name: wfx-detector-secrets
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"

---
apiVersion: v1
kind: Service
metadata:
  name: wfx-detector
spec:
  selector:
    app: wfx-detector
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: wfx-detector
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - wfx-detector.your-domain.com
    secretName: wfx-detector-tls
  rules:
  - host: wfx-detector.your-domain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: wfx-detector
            port:
              number: 80
```

```bash
# Create secrets
kubectl create secret generic wfx-detector-secrets \
  --from-literal=GITHUB_WEBHOOK_SECRET="your-secret" \
  --from-literal=GITHUB_APP_ID="123456" \
  --from-file=GITHUB_PRIVATE_KEY=private-key.pem \
  --from-literal=ALERT_WEBHOOK_URL="https://hooks.slack.com/..."

# Deploy
kubectl apply -f k8s/
```

### 4. Docker Compose (Self-hosted VPS)

```bash
# On your server
git clone https://github.com/your-org/wfx-detector
cd wfx-detector
cp .env.example .env
# Edit .env with your secrets

# Start with systemd
sudo tee /etc/systemd/system/wfx-detector.service > /dev/null <<EOF
[Unit]
Description=WFX Phantom Detector
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/wfx-detector
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable wfx-detector
sudo systemctl start wfx-detector

# Nginx reverse proxy
sudo tee /etc/nginx/sites-available/wfx-detector > /dev/null <<EOF
server {
    listen 80;
    server_name wfx-detector.your-domain.com;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name wfx-detector.your-domain.com;

    ssl_certificate /etc/letsencrypt/live/wfx-detector.your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wfx-detector.your-domain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/wfx-detector /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d wfx-detector.your-domain.com
```

### 5. GitHub Actions Self-Hosted Runner (For internal use)

```yaml
# .github/workflows/deploy.yml
name: Deploy to Self-Hosted

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - name: Deploy
        run: |
          cd /opt/wfx-detector
          git pull
          docker-compose build
          docker-compose up -d
```

## GitHub App Configuration

### Required Permissions
| Permission | Access | Reason |
|------------|--------|--------|
| Contents | Read | Scan files for IOCs |
| Metadata | Read | Repository info |
| Pull Requests | Read | Detect probe PRs |
| Workflows | Read | Check workflow runs |
| Actions | Read | Check run numbers |
| Repository Hooks | Read | Webhook management |

### Required Events
- `pull_request` (opened, edited, reopened, synchronize)
- `push`
- `workflow_run` (completed)
- `create` (branch/tag)
- `delete` (branch/tag)

### Webhook URL
```
https://your-domain.com/webhook
```

### Testing the Webhook
```bash
# Generate test signature
PAYLOAD='{"action":"opened","pull_request":{"title":"docs: dependency audit notes","head":{"ref":"wfx-docs"},"html_url":"https://github.com/test/repo/pull/1","user":{"login":"test"}}, "repository":{"full_name":"test/repo"}}'
SECRET="your-webhook-secret"
SIG="sha256=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | cut -d' ' -f2)"

curl -X POST https://your-domain.com/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  -H "X-Hub-Signature-256: $SIG" \
  -d "$PAYLOAD"
```

Expected response: `{"status":"processed","event":"pull_request","findings":2,...}`

## Monitoring & Alerting

### Health Checks
- `/health` - Liveness (load balancer)
- `/ready` - Readiness (traffic routing)

### Metrics to Monitor
- Webhook receive rate (events/sec)
- Finding rate by severity
- Alert delivery latency
- Error rate (signature verification failures)
- Container memory/CPU

### Log Aggregation
```dockerfile
# Add to Dockerfile for structured logging
ENV LOG_FORMAT=json
```

### Prometheus Metrics (add to requirements)
```python
# In server.py
from prometheus_client import Counter, Histogram, generate_latest

WEBHOOK_REQUESTS = Counter('webhook_requests_total', 'Total webhook requests', ['event', 'status'])
FINDINGS_TOTAL = Counter('findings_total', 'Total findings', ['type', 'severity'])
WEBHOOK_LATENCY = Histogram('webhook_latency_seconds', 'Webhook processing latency')

@app.route('/metrics')
def metrics():
    return generate_latest()
```

## Troubleshooting

### Webhook Signature Verification Fails
1. Check `GITHUB_WEBHOOK_SECRET` matches GitHub App settings exactly
2. Ensure no trailing newlines in secret
3. Verify payload is raw body (not parsed JSON re-serialized)
4. Check for double-encoding in reverse proxy

### No Alerts Received
1. Verify `ALERT_WEBHOOK_URL` is correct
2. Check network egress from container
3. Test webhook manually: `curl -X POST "$ALERT_WEBHOOK_URL" -H "Content-Type: application/json" -d '{"text":"test"}'`

### High Memory Usage
1. Alert queue grows unbounded in memory
2. Add Redis for persistence (see docker-compose.yml)
3. Implement alert TTL/cleanup

### Run Number Gaps Not Detected
1. Workflow runs must be `completed` action
2. Only tracks runs after deployment
3. Historical gaps need separate audit (use `Scan-WfxDeep.ps1`)

## Security Hardening

1. **Rotate webhook secret quarterly**
2. **Use separate GitHub App per environment** (staging/prod)
3. **Restrict webhook source IPs** (GitHub meta API: `https://api.github.com/meta`)
4. **Enable mTLS** between reverse proxy and app
5. **Audit logs** for all webhook events

## Incident Response

When CRITICAL alert fires:
1. Identify compromised account from `actor` field
2. **Immediately**: `gh api -X DELETE /applications/{client_id}/token/{token_id}` for all tokens
3. Revoke SSH keys, GPG keys, OAuth apps
4. Check cloud persistence (run cloud scanner)
5. Rotate all secrets the account could access
6. Document timeline and affected repos