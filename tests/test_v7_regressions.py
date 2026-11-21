"""Regression tests for all 15 defects from the v7 full technical assessment.
Each test maps 1:1 to a defect number and must pass against the delivered artifact.
"""
import json
import os

os.environ.setdefault("ALLOW_IN_MEMORY", "true")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "v7-secret")
os.environ.setdefault("API_ALERT_TOKEN", "v7-token")

import pytest

from app.detector import WFXDetector

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with open(os.path.join(ROOT, rel)) as f:
        return f.read()


@pytest.fixture
def detector():
    return WFXDetector("v7-secret")


class TestSecurityAndDeployment:
    def test_01_no_raw_xff_trust(self):
        # Defect 1: rate key must not read client-supplied X-Forwarded-For.
        srv = read("app/server.py")
        assert 'request.headers.get("X-Forwarded-For"' not in srv
        assert "TRUSTED_PROXY_HOPS" in srv  # explicit, configurable trust boundary

    def test_02_remote_env_permissions(self):
        # Defect 2: remote .env must be chmod 600.
        dep = read(".github/workflows/deploy.yml")
        assert "chmod 600" in dep and "$DEPLOY_PATH/.env" in dep

    def test_03_pinned_host_key(self):
        # Defect 3: no accept-new; host key pinned via secret.
        dep = read(".github/workflows/deploy.yml")
        assert "accept-new" not in dep
        assert "StrictHostKeyChecking=yes" in dep
        assert "DEPLOY_HOST_KEY" in dep

    def test_04_rate_limiter_limitation_documented(self):
        # Defect 4: process-local limitation must be explicit in source/docs.
        srv = read("app/server.py")
        dep = read("DEPLOYMENT.md") if os.path.exists(os.path.join(ROOT, "DEPLOYMENT.md")) else ""
        assert "process-local" in srv.lower() or "process-local" in dep.lower() or "workers" in dep.lower()


class TestDetectionAccuracy:
    def test_05_no_cross_dependency_version_pairing(self, detector):
        # Defect 5: reproduced v7 failure — pdf-html5-page-flip@9.0.0 +
        # safe-lib@2.0.1 must NOT yield pdf-html5-page-flip@2.0.1.
        content = json.dumps({"dependencies": {
            "pdf-html5-page-flip": "9.0.0",
            "safe-lib": "2.0.1",
        }})
        findings = detector.check_package_manifest("r/r", "package.json", content)
        assert findings == [], f"false positive: {[f.detail for f in findings]}"

    def test_05b_real_malicious_pair_detected(self, detector):
        content = json.dumps({"dependencies": {"pdf-html5-page-flip": "2.0.1"}})
        findings = detector.check_package_manifest("r/r", "package.json", content)
        assert any(f.finding_type == "MALICIOUS_PACKAGE_VERSION" for f in findings)

    def test_06_strict_mode_propagates(self, detector):
        # Defect 6: webhook path must use strict=True so failures aren't acked.
        srv = read("app/server.py")
        assert "strict=True" in srv
        with pytest.raises(Exception):
            detector.process_event("push", None, strict=True)

    def test_07_no_premature_gap(self, detector):
        # Defect 7: a lone gap must not fire until a confirming higher run arrives.
        p = lambda n: {"action": "completed", "workflow_run": {
            "workflow_id": 9, "run_number": n, "name": "CI"},
            "repository": {"full_name": "r/r"}}
        detector.process_event("workflow_run", p(1))
        f = detector.process_event("workflow_run", p(3))
        assert not any(x.finding_type == "WORKFLOW_RUN_GAP" for x in f)
        detector.process_event("workflow_run", p(5))
        g = detector.process_event("workflow_run", p(7))
        # Now 1,3,5,7 are known; gap between 1 and 3 should be reported once confirmed.
        assert any(x.finding_type == "WORKFLOW_RUN_GAP" for x in g)

    def test_08_workflow_job_analyzed(self, detector):
        # Defect 8: workflow_job events must produce findings for suspicious jobs.
        f = detector.process_event("workflow_job", {
            "action": "completed",
            "workflow_job": {"name": "dependency audit", "workflow_name": "CI",
                             "head_branch": "wfx-docs", "conclusion": "cancelled",
                             "html_url": "u"},
            "repository": {"full_name": "r/r"},
        })
        assert any(x.finding_type in ("SUSPICIOUS_WORKFLOW_JOB", "WORKFLOW_JOB_CANCELLED_CLEANUP") for x in f)


class TestOperationalAndPackaging:
    def test_09_quickstart_placeholder_matches_env(self):
        q = read("scripts/quickstart.sh")
        e = read(".env.example")
        placeholder = "replace-with-github-app-webhook-secret"
        assert placeholder in e and placeholder in q
        assert "your-webhook-secret-here" not in q

    def test_10_quickstart_uses_https(self):
        q = read("scripts/quickstart.sh")
        assert "https://wfx-detector.your-domain.com/webhook" in q
        assert 'webhook URL to: http://' not in q

    def test_11_quickstart_correct_api(self):
        q = read("scripts/quickstart.sh")
        assert "marketplace_purchases" not in q
        assert "/user/apps/manifest" in q

    def test_12_deploy_runs_full_quality_gate(self):
        dep = read(".github/workflows/deploy.yml")
        assert "ruff check" in dep and "mypy app/" in dep

    def test_13_license_file_present_and_consistent(self):
        assert os.path.exists(os.path.join(ROOT, "LICENSE"))
        lic = read("LICENSE")
        pt = read("pyproject.toml")
        rm = read("README.md")
        expected = "WFX Software License and Patent Non-Appropriation Addendum"
        assert expected.casefold() in lic.casefold() and expected in pt and expected in rm
        assert "MIT - Use freely" not in rm

    def test_14_deployment_doc_has_correct_workflow_name(self):
        d = read("DEPLOYMENT.md")
        assert "deploy-self-hosted.yml" not in d
        assert ".github/workflows/deploy.yml" in d

    def test_15_alert_retry_present(self):
        srv = read("app/server.py")
        assert "ALERT_MAX_ATTEMPTS" in srv and "backoff" in srv.lower()


class TestPanelFindings:
    """Four defense-in-depth defects found by the independent security panelist."""

    def test_p1_storage_fails_closed_without_redis_or_optin(self):
        # The web app must NOT silently start with volatile storage when neither
        # REDIS_URL nor ALLOW_IN_MEMORY is configured (panel finding 1).
        import app.server as srv
        for k in ("REDIS_URL", "ALLOW_IN_MEMORY"):
            os.environ.pop(k, None)
        with pytest.raises(RuntimeError, match="Refusing to start"):
            srv.create_app()
        os.environ["ALLOW_IN_MEMORY"] = "true"
        assert srv.create_app() is not None

    def test_p2_detector_port_bound_to_loopback(self):
        compose = read("docker-compose.yml")
        assert '127.0.0.1:8080:8080' in compose
        assert '"8080:8080"' not in compose

    def test_p3_gitignore_protects_env(self):
        gi = read(".gitignore")
        assert ".env" in gi and "!.env.example" in gi

    def test_p4_newlines_neutralized_in_deploy_env(self):
        dep = read(".github/workflows/deploy.yml")
        assert "s/\\n/\\\\n/g" in dep or "N' -e '$!ba'" in dep
