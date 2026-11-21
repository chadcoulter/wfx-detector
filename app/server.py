"""Flask webhook server for WFX Phantom detector."""
import hmac
import json
import logging
import os
import threading
import time
from datetime import UTC, datetime
from typing import Any, cast

from flask import Flask, abort, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

from .detector import StorageUnavailableError, WFXDetector

logger = logging.getLogger(__name__)

MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(10 * 1024 * 1024)))  # 1MB default
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "100"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))

# Process-local rate limiter. NOTE: with N gunicorn workers, effective limit is N× this value.
# For cross-worker enforcement use a Redis-backed limiter; documented in DEPLOYMENT.md.
_rate_state: dict[str, list[float]] = {}
_rate_lock = threading.Lock()
_last_sweep: float = 0.0
_SWEEP_INTERVAL = 60.0  # global cleanup cadence (seconds)


def _rate_limit_key() -> str:
    # Use the *trusted* peer address only. ProxyFix rewrites request.remote_addr
    # from X-Forwarded-For based on the configured, trusted proxy count (x_for=1),
    # so we must never read the raw client-supplied header here (defect 6).
    return request.remote_addr or "unknown"


def _sweep_expired(now: float) -> None:
    """Globally drop stale per-client buckets so memory cannot grow unbounded."""
    global _last_sweep
    if now - _last_sweep < _SWEEP_INTERVAL:
        return
    cutoff = now - RATE_LIMIT_WINDOW
    for key in [k for k, hits in _rate_state.items()
                if not hits or hits[-1] <= cutoff]:
        del _rate_state[key]
    _last_sweep = now


def _check_rate_limit(remote_key: str) -> bool:
    now = time.time()
    with _rate_lock:
        _sweep_expired(now)  # defect 7: cleanup is not dependent on the same client returning
        hits = [t for t in _rate_state.get(remote_key, []) if now - t < RATE_LIMIT_WINDOW]
        if len(hits) >= RATE_LIMIT_MAX:
            _rate_state[remote_key] = hits
            return False
        hits.append(now)
        _rate_state[remote_key] = hits
    return True


def _check_alert_token() -> bool:
    """Admin endpoints require API_ALERT_TOKEN. Fails CLOSED when unset."""
    expected = os.environ.get("API_ALERT_TOKEN", "").strip()
    if not expected:
        return False  # never allow admin access without a configured token
    return hmac.compare_digest(request.headers.get("X-API-Token", ""), expected)


def create_app(
    webhook_secret: str | None = None,
    alert_webhook: str | None = None,
    redis_url: str | None = None,
    dedup_window: int = 3600,
) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    # Trust exactly one proxy hop. Docker publishes 8080 to a reverse proxy;
    # the raw X-Forwarded-For header is NEVER read directly (defect 1).
    trusted_proxies = int(os.environ.get("TRUSTED_PROXY_HOPS", "1"))
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=trusted_proxies,
                            x_proto=trusted_proxies, x_host=trusted_proxies, x_prefix=trusted_proxies)

    secret = webhook_secret or os.environ.get("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise ValueError("GITHUB_WEBHOOK_SECRET must be set")

    alert_url = alert_webhook or os.environ.get("ALERT_WEBHOOK_URL")
    redis_url = redis_url or os.environ.get("REDIS_URL")
    redis_password = os.environ.get("REDIS_PASSWORD", "").strip() or None
    allow_in_memory = os.environ.get("ALLOW_IN_MEMORY", "").lower() in ("1", "true", "yes")
    dedup_window = int(os.environ.get("DEDUP_WINDOW", str(dedup_window)))

    # Panel finding 1: never silently run volatile storage in a deployed app.
    # Direct WFXDetector(...) construction stays usable for unit tests, but the
    # web server must be explicitly opted into in-memory mode.
    if not redis_url and not allow_in_memory:
        raise RuntimeError(
            "Refusing to start: REDIS_URL is not set and ALLOW_IN_MEMORY is not enabled. "
            "Production requires Redis; set ALLOW_IN_MEMORY=true only for local dev/testing."
        )

    try:
        detector = WFXDetector(secret, alert_url, redis_url, dedup_window,
                               redis_password=redis_password, allow_in_memory=allow_in_memory)
    except StorageUnavailableError as e:
        # Fail loudly at startup — never run with silently-degraded storage
        raise RuntimeError(f"Detector storage unavailable: {e}") from e

    app.config["DETECTOR"] = detector
    app.config["ALERT_WEBHOOK"] = alert_url

    def admin_guard() -> None:
        key = _rate_limit_key()
        if not _check_alert_token():
            abort(401, "API token required")
        if not _check_rate_limit(key):
            abort(429, "Rate limit exceeded")

    def require_webhook_secret() -> None:
        # All non-webhook admin/scanner endpoints require the token too.
        if not _check_alert_token():
            abort(401, "API token required")

    @app.route("/health", methods=["GET"])
    def health() -> Any:
        return jsonify({"status": "healthy", "timestamp": datetime.now(UTC).isoformat()})

    @app.route("/ready", methods=["GET"])
    def ready() -> Any:
        try:
            detector.storage.get_alert_count()
        except Exception as e:
            logger.error("Storage readiness failed: %s", e)
            return jsonify({"status": "not ready", "storage": "unavailable"}), 503
        return jsonify({"status": "ready", "storage": type(detector.storage).__name__})

    @app.route("/webhook", methods=["POST"])
    def webhook() -> Any:
        payload = request.get_data()
        if not detector.verify_signature(payload, request.headers.get("X-Hub-Signature-256", "")):
            abort(401, "Invalid signature")
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            abort(400, "Invalid JSON")
        if not isinstance(data, dict):
            abort(400, "JSON body must be an object")
        try:
            findings = detector.process_event(request.headers.get("X-GitHub-Event", "unknown"), data,
                                              strict=True)
        except Exception:
            logger.exception("Webhook detection processing failed; returning 500 (no false ack)")
            return jsonify({"status": "error", "detail": "detection processing failed"}), 500
        if findings:
            _send_alerts(findings, alert_url)
        return jsonify({"status": "processed", "findings": len(findings)})

    @app.route("/alerts", methods=["GET"])
    def get_alerts() -> Any:
        admin_guard()
        try:
            limit = max(1, min(int(request.args.get("limit", 100)), 1000))
        except (TypeError, ValueError):
            limit = 100
        findings = detector.get_alerts(limit)
        return jsonify({"alerts": [f.to_dict() for f in findings],
                        "count": len(findings), "total": detector.get_alert_count()})

    @app.route("/alerts", methods=["DELETE"])
    def clear_alerts() -> Any:
        admin_guard()
        detector.clear_alerts()
        return jsonify({"status": "cleared"})

    @app.route("/metrics", methods=["GET"])
    def get_metrics() -> Any:
        admin_guard()
        return jsonify({"metrics": detector.get_metrics(request.args.get("prefix", ""))})

    @app.route("/scan/content", methods=["POST"])
    def scan_content() -> Any:
        require_webhook_secret()
        if not _check_rate_limit(_rate_limit_key()):
            abort(429, "Rate limit exceeded")
        data = request.get_json(silent=True) or {}
        repo, path, content = data.get("repository"), data.get("path"), data.get("content")
        ref = data.get("ref", "main")
        if not all(isinstance(v, str) and v for v in (repo, path, content, ref)):
            abort(400, "repository, path, content, ref must be non-empty strings")
        findings = detector.scan_file_content(cast(str, repo), cast(str, path), cast(str, content), cast(str, ref))
        return jsonify({"findings": [f.to_dict() for f in findings], "count": len(findings)})

    @app.route("/scan/package", methods=["POST"])
    def scan_package() -> Any:
        require_webhook_secret()
        if not _check_rate_limit(_rate_limit_key()):
            abort(429, "Rate limit exceeded")
        data = request.get_json(silent=True) or {}
        repo, path, content = data.get("repository"), data.get("path"), data.get("content")
        if not all(isinstance(v, str) and v for v in (repo, path, content)):
            abort(400, "repository, path, content must be non-empty strings")
        findings = detector.check_package_manifest(cast(str, repo), cast(str, path), cast(str, content))
        return jsonify({"findings": [f.to_dict() for f in findings], "count": len(findings)})

    return app


ALERT_MAX_ATTEMPTS = int(os.environ.get("ALERT_MAX_ATTEMPTS", "3"))
ALERT_RETRY_BASE = float(os.environ.get("ALERT_RETRY_BASE_SECONDS", "1.0"))


def _send_alerts(findings: list[Any], webhook_url: str | None) -> bool:
    """Send findings to the alert webhook with bounded retry/backoff (defect 15).

    Returns True on delivery, False after all attempts fail. Failures remain
    logged; the finding itself is already durably stored, so no data is lost.
    """
    if not webhook_url or not findings:
        return False
    import urllib.request
    blocks = []
    for f in findings:
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f.severity, "⚪")
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text":
            f"{emoji} *{f.finding_type}* ({f.severity})\nRepo: `{f.repository}`\nActor: `{f.actor}`\n"
            f"Detail: {f.detail}\n<{f.url}|View on GitHub>"}})
    body = json.dumps({"blocks": blocks}).encode()
    for attempt in range(1, max(1, ALERT_MAX_ATTEMPTS) + 1):
        try:
            req = urllib.request.Request(webhook_url, data=body,
                                         headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=5)
            return True
        except Exception as e:
            logger.warning("Alert delivery attempt %d/%d failed: %s", attempt, ALERT_MAX_ATTEMPTS, e)
            if attempt < ALERT_MAX_ATTEMPTS:
                time.sleep(ALERT_RETRY_BASE * (2 ** (attempt - 1)))
    logger.error("Alert delivery failed after %d attempts (finding remains in storage)", ALERT_MAX_ATTEMPTS)
    return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_app().run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
