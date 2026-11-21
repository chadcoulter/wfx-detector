"""
Round 2 edge cases: API input validation, concurrency, and storage failure modes.
"""
import hashlib
import hmac
import os
import threading

os.environ.setdefault("ALLOW_IN_MEMORY", "true")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "edge2-secret")

import pytest

from app.detector import WFXDetector
from app.server import create_app


@pytest.fixture
def client():
    """Test client with admin token pre-attached (app now fails closed)."""
    os.environ["API_ALERT_TOKEN"] = "edge2-test-token"
    os.environ.pop("REDIS_URL", None)
    app = create_app(webhook_secret="edge2-secret", redis_url=None)
    # Inject the admin token into every request (older Flask has no environ_base).
    from flask.testing import FlaskClient
    class AuthClient(FlaskClient):
        def open(self, *args, **kwargs):
            headers = dict(kwargs.get("headers") or {})
            headers.setdefault("X-API-Token", "edge2-test-token")
            kwargs["headers"] = headers
            return super().open(*args, **kwargs)
    app.test_client_class = AuthClient
    return app.test_client()


def sign(body: bytes) -> dict:
    return {
        "Content-Type": "application/json",
        "X-GitHub-Event": "push",
        "X-Hub-Signature-256": "sha256=" + hmac.new(b"edge2-secret", body, hashlib.sha256).hexdigest(),
    }


class TestAPINputValidation:
    """Internal APIs must validate types, not 500 on bad input."""

    def test_alerts_limit_non_integer(self, client):
        resp = client.get("/alerts?limit=abc")
        assert resp.status_code != 500, "Non-integer limit caused 500"

    def test_alerts_limit_negative(self, client):
        resp = client.get("/alerts?limit=-5")
        assert resp.status_code != 500

    def test_scan_content_non_string_content(self, client):
        resp = client.post("/scan/content", json={
            "repository": "r/r", "path": "f", "content": 12345,
        })
        assert resp.status_code != 500, "Non-string content caused 500"

    def test_scan_content_null_content(self, client):
        resp = client.post("/scan/content", json={
            "repository": "r/r", "path": "f", "content": None,
        })
        assert resp.status_code == 400

    def test_scan_package_non_string(self, client):
        resp = client.post("/scan/package", json={
            "repository": "r/r", "path": "go.mod", "content": {"bad": "type"},
        })
        assert resp.status_code != 500

    def test_webhook_json_not_object(self, client):
        # Valid signature over a JSON array, not a dict
        body = b'[1,2,3]'
        resp = client.post("/webhook", data=body, headers=sign(body))
        assert resp.status_code != 500, "JSON array caused 500"

    def test_webhook_json_null(self, client):
        body = b'null'
        resp = client.post("/webhook", data=body, headers=sign(body))
        assert resp.status_code != 500

    def test_webhook_json_number(self, client):
        body = b'42'
        resp = client.post("/webhook", data=body, headers=sign(body))
        assert resp.status_code != 500


class TestContentTypeRobustness:
    """Detector methods should tolerate wrong types in nested fields."""

    def test_actor_non_string(self):
        d = WFXDetector("s")
        f = d._handle_pull_request({
            "action": "opened",
            "pull_request": {
                "title": "x", "head": {"ref": "x"},
                "html_url": "u", "user": {"login": None},
            },
            "repository": {"full_name": "r/r"},
        })
        assert isinstance(f, list)

    def test_commit_author_null(self):
        d = WFXDetector("s")
        f = d._handle_push({
            "ref": "main", "pusher": {"name": "u"},
            "commits": [{
                "message": "ci: refresh build cache",
                "author": None,
                "added": [],
            }],
            "repository": {"full_name": "r/r"},
        })
        # Bug if author=None causes crash -> PROCESSING_ERROR instead of real finding
        types = {x.finding_type for x in f}
        assert "PROCESSING_ERROR" not in types, "author=None caused processing error"
        assert "PROBE_COMMIT_MSG" in types

    def test_commits_contain_int(self):
        d = WFXDetector("s")
        f = d._handle_push({
            "ref": "main", "pusher": {"name": "u"},
            "commits": [123, {"message": "x", "added": []}],
            "repository": {"full_name": "r/r"},
        })
        assert "PROCESSING_ERROR" not in {x.finding_type for x in f}

    def test_run_number_string_numeric(self):
        d = WFXDetector("s")
        for n in ["1", "3"]:
            f = d._handle_workflow_run({
                "action": "completed",
                "workflow_run": {"workflow_id": 5, "run_number": n, "name": "CI"},
                "repository": {"full_name": "r/r"},
            })
        # Should not crash; may or may not detect gap depending on coercion
        assert isinstance(f, list)


class TestIOCBoundaryCorrectness:
    """IOC matching must be neither over- nor under-broad."""

    def test_ip_with_port_still_matches(self):
        d = WFXDetector("s")
        f = d.scan_file_content("r/r", "f", "http://194.150.166.244:8080/exfil", "main")
        assert any(x.finding_type == "CONTENT_IOC_MATCH" for x in f)

    def test_ip_embedded_in_hostname_not_matched(self):
        d = WFXDetector("s")
        f = d.scan_file_content("r/r", "f", "x194.150.166.244.evil.com", "main")
        assert not any(x.finding_type == "CONTENT_IOC_MATCH" for x in f)

    def test_hash_uppercase_matches(self):
        # Hex hashes are case-insensitive; uppercase must still be detected
        d = WFXDetector("s")
        h = "89695ABB392D5CFD4972672961E644BB46BAA98AA1ED7173C2A2816C762735CF"
        f = d.scan_file_content("r/r", "f", h, "main")
        assert any(x.finding_type == "CONTENT_IOC_MATCH" for x in f)

    def test_telegram_url_matches(self):
        d = WFXDetector("s")
        f = d.scan_file_content("r/r", "f", "https://api.telegram.org/bot123:ABC/sendMessage", "main")
        assert any(x.finding_type == "CONTENT_IOC_MATCH" for x in f)


class TestConcurrency:
    """In-memory storage must be safe under concurrent webhook delivery."""

    def test_concurrent_process_events(self):
        d = WFXDetector("s")
        errors = []

        def worker(i):
            try:
                d.process_event("push", {
                    "ref": "main", "pusher": {"name": f"u{i}"},
                    "commits": [{"message": "ci: refresh build cache", "added": [".ci-abc123.sh"]}],
                    "repository": {"full_name": f"org/repo{i}"},
                })
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert not errors, f"Concurrent processing raised: {errors}"
        # Each push yields 2 findings (probe commit + payload script) × 50 unique repos
        assert d.get_alert_count() == 100

    def test_concurrent_redis_failure_is_loud(self):
        # A configured-but-dead Redis must fail loudly, never silently fall back
        # to volatile storage (defect 5/7 from the v4 review).
        from app.detector import StorageUnavailableError
        with pytest.raises(StorageUnavailableError):
            WFXDetector("s", redis_url="redis://127.0.0.1:1/0")
