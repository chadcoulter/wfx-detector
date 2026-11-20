#!/usr/bin/env bash
# Quick start script for WFX Phantom Detector
# Usage: ./scripts/quickstart.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🔍 WFX Phantom Detector - Quick Start"
echo "====================================="
echo ""

# Check prerequisites
check_cmd() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ $1 not found. Please install it first."
        exit 1
    fi
}

echo "Checking prerequisites..."
check_cmd docker
check_cmd docker-compose
check_cmd gh
echo "✅ All prerequisites found"
echo ""

# Check for .env
if [[ ! -f "$PROJECT_ROOT/.env" ]]; then
    echo "📝 Creating .env from template..."
    cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
    echo "⚠️  Please edit .env with your GitHub App credentials"
    echo ""
fi

# Generate webhook secret if not set
if grep -q "replace-with-github-app-webhook-secret" "$PROJECT_ROOT/.env" 2>/dev/null; then
    echo "🔐 Generating webhook secret..."
    SECRET=$(openssl rand -hex 32)
    sed -i "s|replace-with-github-app-webhook-secret|$SECRET|" "$PROJECT_ROOT/.env"
    echo "✅ Generated webhook secret (stored in .env; not displayed)"
    echo ""
fi

# Create GitHub App (if gh auth'd)
if gh auth status &>/dev/null; then
    echo "📱 GitHub CLI authenticated. Create GitHub App?"
    read -p "Create GitHub App now? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        APP_NAME="WFX Phantom Detector - $(date +%s)"
        echo "Creating GitHub App: $APP_NAME"
        
        # Create app via manifest
        echo "   Using manifest: $PROJECT_ROOT/github-app-manifest.json"
        echo "   Set its webhook_url to your HTTPS public URL before converting."
        
        gh api --method POST -H "Accept: application/vnd.github+json" /user/apps/manifest --field manifest @"$PROJECT_ROOT/github-app-manifest.json" 2>/dev/null || \
        echo "⚠️  Manual creation needed. Go to: https://github.com/settings/apps/new"
        echo "   Use manifest from: $PROJECT_ROOT/github-app-manifest.json"
    fi
else
    echo "⚠️  GitHub CLI not authenticated. Run 'gh auth login' first."
    echo "   Then create GitHub App manually at: https://github.com/settings/apps/new"
    echo "   Use manifest from: $PROJECT_ROOT/github-app-manifest.json"
fi
echo ""

# Build and start
echo "🐳 Building and starting containers..."
cd "$PROJECT_ROOT"
docker-compose build
docker-compose up -d

# Wait for health
echo "⏳ Waiting for service to be healthy..."
for i in {1..30}; do
    if curl -sf http://localhost:8080/health >/dev/null 2>&1; then
        echo "✅ Service is healthy!"
        break
    fi
    sleep 1
done

echo ""
echo "🎉 WFX Phantom Detector is running!"
echo ""
echo "📋 Next steps:"
echo "   1. Configure GitHub App webhook URL (HTTPS via your reverse proxy): https://wfx-detector.your-domain.com/webhook"
echo "   2. Install the GitHub App on target organizations/repositories"
echo "   3. Test with: curl -X POST http://localhost:8080/webhook -H 'X-GitHub-Event: pull_request' -H 'X-Hub-Signature-256: sha256=...' -d '{\"action\":\"opened\",\"pull_request\":{\"title\":\"docs: dependency audit notes\",\"head\":{\"ref\":\"wfx-docs\"},\"html_url\":\"https://github.com/test/repo/pull/1\",\"user\":{\"login\":\"test\"}},\"repository\":{\"full_name\":\"test/repo\"}}'"
echo "   4. View alerts: curl http://localhost:8080/alerts"
echo ""
echo "📚 Logs: docker-compose logs -f detector"
echo "🛑 Stop: docker-compose down"