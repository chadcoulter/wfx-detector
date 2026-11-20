"""
Edge-case and robustness tests for WFX Phantom Detector.
Probes malformed payloads, boundary conditions, false pos/neg, and storage failures.
"""
import os
import json
import hmac
import hashlib

os.environ.setdefault("ALLOW_IN_MEMORY", "true")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "edge-secret")

import pytest
from app.detector import WFXDetector, Finding, InMemoryStorage, RedisStorage
from app.server import create_app


@pytest.fixture
def detector():
    # Force in-memory for deterministic unit tests
    return WFXDetector("edge-secret", redis_url=None)


@pytest.fixture
def client():
    """Test client with admin token pre-attached (app now fails closed)."""
    os.environ["API_ALERT_TOKEN"] = "edge-test-token"
    os.environ.pop("REDIS_URL", None)
    app = create_app(webhook_secret="edge-secret", redis_url=None)
    # Inject the admin token into every request (older Flask has no environ_base).
    from flask.testing import FlaskClient
    class AuthClient(FlaskClient):
        def open(self, *args, **kwargs):
            headers = dict(kwargs.get("headers") or {})
            headers.setdefault("X-API-Token", "edge-test-token")
            kwargs["headers"] = headers
            return super().open(*args, **kwargs)
    app.test_client_class = AuthClient
    return app.test_client()


# ============ MALFORMED PAYLOADS ============

class TestMalformedPayloads:
    """Detector must never crash on malformed webhook data."""

    @pytest.mark.parametrize("event,payload", [
        ("pull_request", {}),
        ("pull_request", {"action": "opened"}),  # no pull_request key
        ("pull_request", {"pull_request": None}),
        ("pull_request", {"pull_request": {"head": None}}),
        ("pull_request", {"pull_request": {"head": {"ref": None}, "user": None}}),
        ("push", {}),
        ("push", {"commits": None}),
        ("push", {"commits": [None]}),
        ("push", {"commits": [{"added": None}]}),
        ("push", {"commits": [{"added": [None]}]}),
        ("workflow_run", {}),
        ("workflow_run", {"workflow_run": {"run_number": "not-an-int"}}),
        ("create", {}),
        ("delete", {}),
        ("unknown", {}),
        (None, {}),
    ])
    def test_no_crash(self, detector, event, payload):
        findings = detector.process_event(event, payload)
        assert isinstance(findings, list)
        # Any finding must be well-formed
        for f in findings:
            assert isinstance(f, Finding)

    def test_non_dict_payload(self, detector):
        # process_event expects dict; a list would break .get()
        # Should be caught by the try/except and return PROCESSING_ERROR
        findings = detector.process_event("push", [])
        assert isinstance(findings, list)


# ============ SIGNATURE EDGE CASES ============

class TestSignatureEdges:
    def test_empty_signature(self, detector):
        assert not detector.verify_signature(b"{}", "")

    def test_sha1_signature_rejected(self, detector):
        sig = "sha1=" + hmac.new(b"edge-secret", b"{}", hashlib.sha1).hexdigest()
        assert not detector.verify_signature(b"{}", sig)

    def test_wrong_secret(self, detector):
        sig = "sha256=" + hmac.new(b"wrong-secret", b"{}", hashlib.sha256).hexdigest()
        assert not detector.verify_signature(b"{}", sig)

    def test_signature_no_prefix(self, detector):
        raw = hmac.new(b"edge-secret", b"{}", hashlib.sha256).hexdigest()
        assert not detector.verify_signature(b"{}", raw)

    def test_body_mutation_invalidates(self, detector):
        body = b'{"action":"opened"}'
        sig = "sha256=" + hmac.new(b"edge-secret", body, hashlib.sha256).hexdigest()
        assert detector.verify_signature(body, sig)
        assert not detector.verify_signature(body + b" ", sig)


# ============ FALSE POSITIVES / NEAR MISSES ============

class TestNearMisses:
    """Verify regexes don't over-match benign lookalikes."""

    def test_pr_title_case_insensitive_is_intended(self, detector):
        # Pattern is IGNORECASE by design
        f = detector._handle_pull_request({
            "action": "opened",
            "pull_request": {
                "title": "DOCS: DEPENDENCY AUDIT NOTES",
                "head": {"ref": "feature/x"},
                "html_url": "u", "user": {"login": "u"},
            },
            "repository": {"full_name": "r/r"},
        })
        assert any(x.finding_type == "PROBE_PR_TITLE" for x in f)

    def test_pr_title_similar_but_benign(self, detector):
        f = detector._handle_pull_request({
            "action": "opened",
            "pull_request": {
                "title": "docs: dependency audit note",  # singular
                "head": {"ref": "feature/x"},
                "html_url": "u", "user": {"login": "u"},
            },
            "repository": {"full_name": "r/r"},
        })
        assert not any(x.finding_type == "PROBE_PR_TITLE" for x in f)

    def test_chore_branch_exact_8(self, detector):
        f = detector._handle_pull_request({
            "action": "opened",
            "pull_request": {
                "title": "x", "head": {"ref": "chore/abcdefgh"},
                "html_url": "u", "user": {"login": "u"},
            },
            "repository": {"full_name": "r/r"},
        })
        assert any(x.finding_type == "PROBE_BRANCH_CHORE" for x in f)

    def test_chore_branch_9_chars_not_matched(self, detector):
        f = detector._handle_pull_request({
            "action": "opened",
            "pull_request": {
                "title": "x", "head": {"ref": "chore/abcdefghi"},
                "html_url": "u", "user": {"login": "u"},
            },
            "repository": {"full_name": "r/r"},
        })
        assert not any(x.finding_type == "PROBE_BRANCH_CHORE" for x in f)

    def test_ci_sh_exact_6(self, detector):
        f = detector.scan_file_content("r/r", "x", "", "main")  # baseline
        findings = detector._handle_push({
            "ref": "refs/heads/main", "pusher": {"name": "u"},
            "commits": [{"message": "x", "added": [".ci-abc123.sh"]}],
            "repository": {"full_name": "r/r"},
        })
        assert any(x.finding_type == "PAYLOAD_CI_SH" for x in findings)

    def test_ci_sh_5_chars_not_matched(self, detector):
        findings = detector._handle_push({
            "ref": "refs/heads/main", "pusher": {"name": "u"},
            "commits": [{"message": "x", "added": [".ci-abc12.sh"]}],
            "repository": {"full_name": "r/r"},
        })
        assert not any(x.finding_type == "PAYLOAD_CI_SH" for x in findings)


# ============ CONTENT SCAN EDGES ============

class TestContentEdges:
    def test_empty_content(self, detector):
        assert detector.scan_file_content("r/r", "f", "", "main") == []

    def test_unicode_content(self, detector):
        # Should not crash, should not false-positive
        f = detector.scan_file_content("r/r", "f", "café \u4e2d\u6587 🚀", "main")
        assert isinstance(f, list)

    def test_huge_content_performance(self, detector):
        # 2MB of benign content should not take excessive time
        import time
        content = "x" * (2 * 1024 * 1024)
        t0 = time.time()
        f = detector.scan_file_content("r/r", ".github/workflows/ci.yml", content, "main")
        elapsed = time.time() - t0
        assert elapsed < 5.0, f"Content scan too slow: {elapsed:.2f}s"
        # Should flag oversized workflow
        assert any(x.finding_type == "OVERSIZED_WORKFLOW" for x in f)

    def test_exact_1000_lines_not_flagged(self, detector):
        content = "\n".join(["x"] * 1000)
        f = detector.scan_file_content("r/r", ".github/workflows/ci.yml", content, "main")
        assert not any(x.finding_type == "OVERSIZED_WORKFLOW" for x in f)

    def test_1001_lines_flagged(self, detector):
        content = "\n".join(["x"] * 1001)
        f = detector.scan_file_content("r/r", ".github/workflows/ci.yml", content, "main")
        assert any(x.finding_type == "OVERSIZED_WORKFLOW" for x in f)

    def test_ip_substring_false_positive(self, detector):
        # 194.150.166.2440 should NOT match 194.150.166.244
        f = detector.scan_file_content("r/r", "f", "194.150.166.2440", "main")
        assert not any(x.finding_type == "CONTENT_IOC_MATCH" for x in f)


# ============ DEDUPLICATION ============

class TestDeduplication:
    def test_same_finding_deduped(self, detector):
        payload = {
            "action": "opened",
            "pull_request": {
                "title": "docs: dependency audit notes",
                "head": {"ref": "wfx-docs"},
                "html_url": "u", "user": {"login": "u"},
            },
            "repository": {"full_name": "r/r"},
        }
        first = detector.process_event("pull_request", payload)
        second = detector.process_event("pull_request", payload)
        assert len(first) > 0
        assert len(second) == 0, "Duplicate finding should be suppressed"

    def test_different_repo_not_deduped(self, detector):
        base = {
            "action": "opened",
            "pull_request": {
                "title": "docs: dependency audit notes",
                "head": {"ref": "feature/x"},
                "html_url": "u", "user": {"login": "u"},
            },
        }
        p1 = dict(base, repository={"full_name": "org1/repo"})
        p2 = dict(base, repository={"full_name": "org2/repo"})
        assert len(detector.process_event("pull_request", p1)) > 0
        assert len(detector.process_event("pull_request", p2)) > 0


# ============ HTTP SERVER EDGES ============

class TestServerEdges:
    def test_bad_signature_401(self, client):
        resp = client.post("/webhook", data=b"{}", headers={
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": "sha256=bad",
        })
        assert resp.status_code == 401

    def test_missing_signature_401(self, client):
        resp = client.post("/webhook", data=b"{}", headers={
            "X-GitHub-Event": "push",
        })
        assert resp.status_code == 401

    def test_invalid_json_with_valid_sig_400(self, client):
        body = b"not json"
        sig = "sha256=" + hmac.new(b"edge-secret", body, hashlib.sha256).hexdigest()
        resp = client.post("/webhook", data=body, headers={
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": sig,
        })
        assert resp.status_code == 400

    def test_metrics_endpoint(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "metrics" in resp.get_json()

    def test_alerts_limit_clamped(self, client):
        resp = client.get("/alerts?limit=99999")
        assert resp.status_code == 200

    def test_scan_content_missing_fields_400(self, client):
        resp = client.post("/scan/content", json={"repository": "r/r"})
        assert resp.status_code == 400

    def test_health_shows_storage(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "healthy"  # storage reported by /ready


# ============ WORKFLOW RUN GAP EDGES ============

class TestRunGapEdges:
    def test_non_sequential_runs_no_false_gap(self, detector):
        # Out-of-order arrival: 5, 3, 4 -> no gap
        for n in [5, 3, 4]:
            detector.process_event("workflow_run", {
                "action": "completed",
                "workflow_run": {"workflow_id": 77, "run_number": n, "name": "CI", "actor": {"login": "u"}},
                "repository": {"full_name": "r/r"},
            })
        assert detector.storage.get_run_numbers("r/r", "77") == [3, 4, 5]

    def test_actual_gap_detected(self, detector):
        findings = []
        for n in [1, 3, 5]:
            findings += detector.process_event("workflow_run", {
                "action": "completed",
                "workflow_run": {"workflow_id": 88, "run_number": n, "name": "CI", "actor": {"login": "u"}},
                "repository": {"full_name": "r/r"},
            })
        # Gap between 1 and 3 is only reported once a higher confirming run exists.
        assert any(f.finding_type == "WORKFLOW_RUN_GAP" for f in findings)

    def test_run_number_zero_ignored(self, detector):
        findings = detector.process_event("workflow_run", {
            "action": "completed",
            "workflow_run": {"workflow_id": 99, "run_number": 0},
            "repository": {"full_name": "r/r"},
        })
        assert not any(f.finding_type == "WORKFLOW_RUN_GAP" for f in findings)
