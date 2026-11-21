"""
Core detection logic for WFX Phantom / wfx-loot campaign.
All IOCs sourced from public reporting (Nov 2026).
"""
import hashlib
import hmac
import json
import logging
import re
import threading
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None  # type: ignore[assignment]


class StorageUnavailableError(RuntimeError):
    """Raised when the configured persistent storage cannot be used."""


# ===== Safe accessors for untrusted webhook payloads =====
def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_str(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


def _as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    return default


@dataclass
class Finding:
    finding_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    detail: str
    url: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    repository: str = ""
    actor: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.finding_type,
            "severity": self.severity,
            "detail": self.detail,
            "url": self.url,
            "timestamp": self.timestamp.isoformat(),
            "repository": self.repository,
            "actor": self.actor,
        }

    def to_redis_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_redis_dict(cls, data: dict[str, Any]) -> "Finding":
        data = data.copy()
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


class RedisStorage:
    """Redis-backed persistent storage. No in-memory fallback by design."""

    ALERTS_KEY = "wfx:alerts"
    RUN_NUMBERS_KEY = "wfx:run_numbers"
    DEDUP_KEY = "wfx:dedup"
    METRICS_KEY = "wfx:metrics"

    ALERTS_TTL = 7 * 24 * 3600
    RUN_NUMBERS_TTL = 30 * 24 * 3600
    DEDUP_TTL = 24 * 3600
    METRICS_TTL = 24 * 3600

    def __init__(self, redis_url: str, password: str | None = None):
        if not REDIS_AVAILABLE:
            raise StorageUnavailableError("redis-py not installed. Run: pip install redis")
        self.client = redis.from_url(redis_url, password=password or None, decode_responses=True)  # type: ignore[no-untyped-call]
        try:
            self.client.ping()
        except Exception as e:
            raise StorageUnavailableError(f"Redis connection failed: {e}") from e

    # Alert queue
    def push_alert(self, finding: Finding) -> bool:
        self.client.lpush(self.ALERTS_KEY, json.dumps(finding.to_redis_dict()))
        self.client.ltrim(self.ALERTS_KEY, 0, 9999)
        self.client.expire(self.ALERTS_KEY, self.ALERTS_TTL)
        return True

    def get_alerts(self, limit: int = 100) -> list[Finding]:
        items = self.client.lrange(self.ALERTS_KEY, 0, limit - 1)
        return [Finding.from_redis_dict(json.loads(i)) for i in items]

    def clear_alerts(self) -> bool:
        self.client.delete(self.ALERTS_KEY)
        return True

    def get_alert_count(self) -> int:
        return int(self.client.llen(self.ALERTS_KEY))

    # Run numbers — scoped by repository to avoid cross-repo collisions
    def _run_key(self, repo: str, workflow_id: str) -> str:
        return f"{self.RUN_NUMBERS_KEY}:{repo}:{workflow_id}"

    def add_run_number(self, repo: str, workflow_id: str, run_number: int) -> bool:
        key = self._run_key(repo, workflow_id)
        self.client.zadd(key, {str(run_number): run_number})
        self.client.expire(key, self.RUN_NUMBERS_TTL)
        return True

    def get_run_numbers(self, repo: str, workflow_id: str) -> list[int]:
        items = self.client.zrange(self._run_key(repo, workflow_id), 0, -1)
        return [int(i) for i in items]

    def check_run_gaps(self, repo: str, workflow_id: str, workflow_name: str, actor: str) -> list[Finding]:
        findings = []
        runs = self.get_run_numbers(repo, workflow_id)
        for i in range(1, len(runs)):
            # Only report a gap once a later run exists above its upper bound;
            # otherwise a still-in-flight run may simply have arrived out of order.
            if i + 1 >= len(runs):
                break
            gap = runs[i] - runs[i - 1] - 1
            if gap > 0:
                findings.append(Finding(
                    finding_type="WORKFLOW_RUN_GAP",
                    severity="HIGH",
                    detail=f"Workflow {workflow_name}: {gap} missing run number(s) between #{runs[i-1]} and #{runs[i]}",
                    url=f"https://github.com/{repo}/actions",
                    repository=repo,
                    actor=actor,
                ))
        return findings

    # Dedup — atomic SET NX EX with TTL, so keys expire
    def is_duplicate(self, finding: Finding, window_seconds: int = 3600) -> bool:
        detail_hash = hashlib.md5(finding.detail.encode()).hexdigest()[:16]
        key = f"{self.DEDUP_KEY}:{finding.finding_type}:{finding.repository}:{finding.actor}:{detail_hash}"
        inserted = self.client.set(key, "1", nx=True, ex=window_seconds)
        return not inserted

    # Metrics — expiring counters, no unbounded growth
    def increment_metric(self, metric: str, labels: dict[str, str] | None = None) -> None:
        key = f"{self.METRICS_KEY}:{metric}"
        if labels:
            key += ":" + ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        self.client.incr(key)
        self.client.expire(key, self.METRICS_TTL)

    def get_metrics(self, prefix: str = "") -> dict[str, int]:
        keys = self.client.keys(f"{self.METRICS_KEY}:{prefix}*")
        if not keys:
            return {}
        values = self.client.mget(keys)
        return {k: int(v or 0) for k, v in zip(keys, values, strict=False)}


class InMemoryStorage:
    """Fallback storage ONLY when explicitly allowed (dev mode). Thread-safe, TTL-bounded."""

    def __init__(self) -> None:
        self._alerts: list[Finding] = []
        self._run_numbers: dict[str, list[int]] = defaultdict(list)
        self._dedup: dict[str, float] = {}
        self._metrics: dict[str, int] = defaultdict(int)
        self._max_alerts = 10000
        self._lock = threading.RLock()

    def _purge_expired_dedup(self, now: float) -> None:
        expired = [k for k, exp in self._dedup.items() if exp <= now]
        for k in expired:
            self._dedup.pop(k, None)

    def push_alert(self, finding: Finding) -> bool:
        with self._lock:
            self._alerts.insert(0, finding)
            del self._alerts[self._max_alerts:]
        return True

    def get_alerts(self, limit: int = 100) -> list[Finding]:
        with self._lock:
            return self._alerts[:limit]

    def clear_alerts(self) -> bool:
        with self._lock:
            self._alerts.clear()
        return True

    def get_alert_count(self) -> int:
        with self._lock:
            return len(self._alerts)

    def _run_key(self, repo: str, workflow_id: str) -> str:
        return f"{repo}:{workflow_id}"

    def add_run_number(self, repo: str, workflow_id: str, run_number: int) -> bool:
        with self._lock:
            key = self._run_key(repo, workflow_id)
            if run_number not in self._run_numbers[key]:
                self._run_numbers[key].append(run_number)
        return True

    def get_run_numbers(self, repo: str, workflow_id: str) -> list[int]:
        with self._lock:
            return sorted(set(self._run_numbers[self._run_key(repo, workflow_id)]))

    def check_run_gaps(self, repo: str, workflow_id: str, workflow_name: str, actor: str) -> list[Finding]:
        runs = self.get_run_numbers(repo, workflow_id)
        findings = []
        for i in range(1, len(runs)):
            if i + 1 >= len(runs):  # wait for a confirming higher run (defect 7)
                break
            gap = runs[i] - runs[i - 1] - 1
            if gap > 0:
                findings.append(Finding(
                    finding_type="WORKFLOW_RUN_GAP",
                    severity="HIGH",
                    detail=f"Workflow {workflow_name}: {gap} missing run number(s) between #{runs[i-1]} and #{runs[i]}",
                    url=f"https://github.com/{repo}/actions",
                    repository=repo,
                    actor=actor,
                ))
        return findings

    def is_duplicate(self, finding: Finding, window_seconds: int = 3600) -> bool:
        detail_hash = hashlib.md5(finding.detail.encode()).hexdigest()[:16]
        key = f"{finding.finding_type}:{finding.repository}:{finding.actor}:{detail_hash}"
        now = time.time()
        with self._lock:
            self._purge_expired_dedup(now)
            if key in self._dedup:
                return True
            self._dedup[key] = now + window_seconds
        return False

    def increment_metric(self, metric: str, labels: dict[str, str] | None = None) -> None:
        key = metric
        if labels:
            key += ":" + ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        with self._lock:
            self._metrics[key] += 1

    def get_metrics(self, prefix: str = "") -> dict[str, int]:
        with self._lock:
            return {k: v for k, v in self._metrics.items() if k.startswith(prefix)}


class WFXDetector:
    """Detects WFX Phantom campaign indicators in GitHub webhook events."""

    PROBE_PR_TITLE = re.compile(r'^docs:\s*dependency audit notes$', re.IGNORECASE)
    PROBE_BRANCH_WFX = re.compile(r'^wfx-docs$')
    PROBE_BRANCH_CHORE = re.compile(r'^chore/[a-z0-9]{8}$')
    PROBE_BRANCH_CICHECK = re.compile(r'^ci-check-\d{4}$')
    PROBE_COMMIT_MSG = re.compile(
        r'^(ci: refresh build cache|chore: add ci helper|chore: add dependency audit workflow|ci: restore|ci: cleanup)$'
    )
    PAYLOAD_CI_SH = re.compile(r'^\.ci-[a-z0-9]{6}\.sh$')
    PAYLOAD_BUILD_AUDIT = re.compile(r'^\.github/workflows/build-audit-[a-z0-9]{6}\.ya?ml$')
    PAYLOAD_VSCODE_TASKS = re.compile(r'^\.vscode/tasks\.json$')
    PAYLOAD_FONT_WOFF2 = re.compile(r'^public/fonts/fa-solid-400\.woff2$')

    CONTENT_IOCS = re.compile(
        r'(?:'
        r'89695abb392d5cfd4972672961e644bb46baa98aa1ed7173c2a2816c762735cf|'
        r'6960931e69bbcd70f9d0727c536251fa94167d0b8a988d12c5efe45e54b1d389|'
        r'a45d3ced951d2deaaa76e39c8d20c78cfcb0092b9b6bde2fb8347c98caad2d54|'
        r'73cec6bc7d2306dcf7087c445bc2f57029a1b74ae24b076605e66b1123a7ddee|'
        r'7128295ffbb8470d62932294e859c1208619a9ef34fe92609b4fcd478bbbcb59|'
        r'(?<![\d.])194\.150\.166\.244(?![\d.])|'
        r'(?<![\d.])18\.143\.168\.96(?![\d.])|'
        r'(?<![\d.])153\.75\.82\.159(?![\d.])|'
        r'(?<![\d.])193\.32\.204\.199(?![\d.])|'
        r'#ghc2|wfx-loot|wfx-cache|WFX-BEGIN|wfx-ci-|\.wfx-|/tmp/wfx-scan-|'
        r'RUNNER_TEMP/wfx-|'
        r'WF_(?:CALLBACK|CTOKEN|TG_BOTS|TG_CHAT|MEMSCAN|EXFIL_[A-Z]+|PRIVATE|FALLBACK|MAXFILES|TARBALL)|'
        r'Dependency Audit [a-z0-9]{4}|name: Pass runtime|'
        r'api\.telegram\.org/bot|/exfil\b|'
        r'digitalelvis/neuronai-studio|onuragtas/(?:redock|docker-env)|vkuznet/gocurl'
        r')',
        re.IGNORECASE
    )
    POSTINSTALL_CI_SH = re.compile(r'"postinstall"\s*:\s*"[^"]*\.ci-[a-z0-9]{6}\.sh')
    OVERSIZED_WORKFLOW_BYTES = 60000
    OVERSIZED_WORKFLOW_LINES = 1000
    MALICIOUS_PACKAGES = {
        "digitalelvis/neuronai-studio": {"3.14.3"},
        "github.com/onuragtas/docker-env": {"v1.0.278", "v1.0.280"},
        "github.com/vkuznet/gocurl": {"v0.0.0-20261111095532-8d5aad0cb0da"},
        "github.com/onuragtas/redock": {"v1.0.278", "v1.0.280"},
        "pdf-html5-page-flip": {"2.0.1", "2.0.2"},
    }
    COMPROMISED_ACTORS = {
        "wdio-bot", "drubot", "onuragtas", "digitalelvis", "vkuznet",
        "kellie-brighty", "mattiaparrinello", "alexappsco",
    }
    C2_IPS = {"194.150.166.244", "18.143.168.96", "153.75.82.159", "193.32.204.199"}

    def __init__(self, webhook_secret: str, alert_webhook: str | None = None,
                 redis_url: str | None = None, dedup_window: int = 3600,
                 redis_password: str | None = None, allow_in_memory: bool = False):
        self.webhook_secret = webhook_secret.encode()
        self.alert_webhook = alert_webhook
        self.dedup_window = dedup_window
        # Storage selection:
        # - REDIS_URL configured  -> MUST use Redis; fail loudly, NEVER fall back (defect 5/6/7)
        # - no REDIS_URL          -> InMemoryStorage (dev/test; create_app enforces the
        #   production gate via ALLOW_IN_MEMORY, see panel finding 1)
        self.storage: RedisStorage | InMemoryStorage
        if redis_url:
            self.storage = RedisStorage(redis_url, redis_password)  # raises StorageUnavailableError on failure
            logger.info("Using Redis storage")
        else:
            self.storage = InMemoryStorage()
            logger.warning("In-memory storage (dev/test only; set REDIS_URL for production)")

    def verify_signature(self, payload: bytes, sig_header: str) -> bool:
        if not sig_header or not sig_header.startswith("sha256="):
            return False
        expected = "sha256=" + hmac.new(self.webhook_secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig_header)

    def process_event(self, event_type: str, payload: dict[str, Any], strict: bool = False) -> list[Finding]:
        """Process a webhook event.

        strict=True (used by the webhook handler) re-raises processing failures so
        the caller does NOT acknowledge an event it failed to analyse (defect 6).
        """
        findings: list[Finding] = []
        try:
            if event_type == "pull_request":
                findings = self._handle_pull_request(payload)
            elif event_type == "push":
                findings = self._handle_push(payload)
            elif event_type == "workflow_run":
                findings = self._handle_workflow_run(payload)
            elif event_type == "workflow_job":
                findings = self._handle_workflow_job(payload)
            elif event_type == "create":
                findings = self._handle_create(payload)
            elif event_type == "delete":
                findings = self._handle_delete(payload)
        except Exception as e:
            logger.exception(f"Error processing {event_type}: {e}")
            if strict:
                raise  # do not acknowledge an event whose detection failed
            findings = [Finding("PROCESSING_ERROR", "LOW", f"Failed to process {event_type}: {e}", "")]
        deduped = []
        for f in findings:
            if not self.storage.is_duplicate(f, self.dedup_window):
                deduped.append(f)
                self.storage.push_alert(f)
                self.storage.increment_metric("findings_total", {"type": f.finding_type, "severity": f.severity})
        self.storage.increment_metric("webhook_requests", {"event": str(event_type), "status": "processed"})
        return deduped

    def _handle_pull_request(self, payload: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        pr = _as_dict(payload.get("pull_request"))
        repo = _as_str(_as_dict(payload.get("repository")).get("full_name"))
        actor = _as_str(_as_dict(pr.get("user")).get("login"))
        if payload.get("action") not in ("opened", "edited", "reopened", "synchronize"):
            return findings
        title = _as_str(pr.get("title"))
        head_ref = _as_str(_as_dict(pr.get("head")).get("ref"))
        url = _as_str(pr.get("html_url"))
        if self.PROBE_PR_TITLE.match(title):
            findings.append(Finding("PROBE_PR_TITLE", "CRITICAL", f'Probe PR title: "{title}"', url, repository=repo, actor=actor))
        if self.PROBE_BRANCH_WFX.match(head_ref):
            findings.append(Finding("PROBE_BRANCH_WFX", "CRITICAL", f"Probe branch: {head_ref}", url, repository=repo, actor=actor))
            findings.append(Finding("PROBE_WFX_AUDIT_FILE", "CRITICAL", "wfx-docs branch likely contains docs/wfx-audit.md",
                                    f"https://github.com/{repo}/tree/{head_ref}/docs/wfx-audit.md", repository=repo, actor=actor))
        elif self.PROBE_BRANCH_CHORE.match(head_ref):
            findings.append(Finding("PROBE_BRANCH_CHORE", "HIGH", f"Suspicious chore branch: {head_ref}", url, repository=repo, actor=actor))
        elif self.PROBE_BRANCH_CICHECK.match(head_ref):
            findings.append(Finding("PROBE_BRANCH_CICHECK", "HIGH", f"Suspicious ci-check branch: {head_ref}", url, repository=repo, actor=actor))
        if actor.lower() in self.COMPROMISED_ACTORS:
            findings.append(Finding("COMPROMISED_ACTOR", "CRITICAL", f"Known compromised actor: {actor}", url, repository=repo, actor=actor))
        return findings

    def _handle_push(self, payload: dict[str, Any]) -> list[Finding]:
        findings = []
        repo = _as_str(_as_dict(payload.get("repository")).get("full_name"))
        ref = _as_str(payload.get("ref"))
        pusher = _as_str(_as_dict(payload.get("pusher")).get("name"))
        for commit in _as_list(payload.get("commits")):
            commit = _as_dict(commit)
            msg = _as_str(commit.get("message")).split("\n")[0].strip()
            curl = _as_str(commit.get("url")).replace("api.github.com/repos", "github.com").replace("/commits/", "/commit/")
            author_obj = _as_dict(commit.get("author"))
            if self.PROBE_COMMIT_MSG.match(msg):
                findings.append(Finding("PROBE_COMMIT_MSG", "CRITICAL",
                                        f'Probe commit: "{msg}" by {_as_str(author_obj.get("name"))} <{_as_str(author_obj.get("email"))}>',
                                        curl, repository=repo, actor=pusher))
            for fname in _as_list(commit.get("added")) + _as_list(commit.get("modified")):
                if not isinstance(fname, str):
                    continue
                base = fname.split("/")[-1]
                link = f"https://github.com/{repo}/blob/{ref}/{fname}"
                if self.PAYLOAD_CI_SH.match(fname) or self.PAYLOAD_CI_SH.match(base):
                    findings.append(Finding("PAYLOAD_CI_SH", "CRITICAL", f"Malicious helper script added: {fname}", link, repository=repo, actor=pusher))
                elif self.PAYLOAD_BUILD_AUDIT.match(fname) or self.PAYLOAD_BUILD_AUDIT.match(base):
                    findings.append(Finding("PAYLOAD_BUILD_AUDIT", "CRITICAL", f"Malicious workflow added: {fname}", link, repository=repo, actor=pusher))
                elif self.PAYLOAD_FONT_WOFF2.match(fname):
                    findings.append(Finding("PAYLOAD_GHOSTACTION_FONT", "HIGH", f"GhostAction font path: {fname}", link, repository=repo, actor=pusher))
                elif base == "package.json":
                    findings.append(Finding("SUSPICIOUS_PACKAGE_JSON", "MEDIUM", "package.json modified - check postinstall hook", link, repository=repo, actor=pusher))
                elif self.PAYLOAD_VSCODE_TASKS.match(base):
                    findings.append(Finding("SUSPICIOUS_VSCODE_TASKS", "MEDIUM", ".vscode/tasks.json modified", link, repository=repo, actor=pusher))
        return findings

    def _handle_workflow_run(self, payload: dict[str, Any]) -> list[Finding]:
        findings = []
        run = _as_dict(payload.get("workflow_run"))
        repo = _as_str(_as_dict(payload.get("repository")).get("full_name"))
        workflow_id = str(_as_str(run.get("workflow_id")) or _as_int(run.get("workflow_id")))
        run_number = _as_int(run.get("run_number"))
        if payload.get("action") == "completed" and workflow_id and run_number:
            self.storage.add_run_number(repo, workflow_id, run_number)
            findings.extend(self.storage.check_run_gaps(
                repo, workflow_id, _as_str(run.get("name")) or workflow_id,
                _as_str(_as_dict(run.get("actor")).get("login"))))
        return findings

    def _handle_workflow_job(self, payload: dict[str, Any]) -> list[Finding]:
        """Analyse workflow_job events (defect 8).

        The campaign runs jobs with characteristic names and on throwaway
        branches. We flag suspicious job/workflow names and jobs whose runs were
        later deleted (conclusion cancelled on a probe branch).
        """
        findings: list[Finding] = []
        job = _as_dict(payload.get("workflow_job"))
        repo = _as_str(_as_dict(payload.get("repository")).get("full_name"))
        name = _as_str(job.get("name"))
        workflow_name = _as_str(job.get("workflow_name"))
        branch = _as_str(job.get("head_branch"))
        url = _as_str(job.get("html_url")) or f"https://github.com/{repo}/actions"
        actor = _as_str(_as_dict(job.get("actor")).get("login"))
        suspicious = (self.PROBE_BRANCH_WFX.match(branch) or self.PROBE_BRANCH_CHORE.match(branch)
                      or self.PROBE_BRANCH_CICHECK.match(branch)
                      or bool(re.search(r"dependency audit|wfx|build-audit|ci-check", name + " " + workflow_name, re.I)))
        if suspicious:
            findings.append(Finding(
                "SUSPICIOUS_WORKFLOW_JOB", "HIGH",
                f"Workflow job '{name}' on branch '{branch}' matches campaign naming",
                url, repository=repo, actor=actor))
        if job.get("conclusion") == "cancelled" and suspicious:
            findings.append(Finding(
                "WORKFLOW_JOB_CANCELLED_CLEANUP", "MEDIUM",
                f"Suspicious job '{name}' was cancelled (possible cleanup)",
                url, repository=repo, actor=actor))
        return findings

    def _handle_create(self, payload: dict[str, Any]) -> list[Finding]:
        findings = []
        ref = _as_str(payload.get("ref"))
        repo = _as_str(_as_dict(payload.get("repository")).get("full_name"))
        sender = _as_str(_as_dict(payload.get("sender")).get("login"))
        if payload.get("ref_type") == "branch":
            labels = [(self.PROBE_BRANCH_WFX, "BRANCH_CREATED_WFX", "CRITICAL"),
                      (self.PROBE_BRANCH_CHORE, "BRANCH_CREATED_CHORE", "HIGH"),
                      (self.PROBE_BRANCH_CICHECK, "BRANCH_CREATED_CICHECK", "HIGH")]
            for pat, typ, sev in labels:
                if pat.match(ref):
                    findings.append(Finding(typ, sev, f"Suspicious branch created: {ref}",
                                            f"https://github.com/{repo}/tree/{ref}", repository=repo, actor=sender))
                    break
        return findings

    def _handle_delete(self, payload: dict[str, Any]) -> list[Finding]:
        findings = []
        ref = _as_str(payload.get("ref"))
        repo = _as_str(_as_dict(payload.get("repository")).get("full_name"))
        sender = _as_str(_as_dict(payload.get("sender")).get("login"))
        if payload.get("ref_type") == "branch" and any(
                p.match(ref) for p in (self.PROBE_BRANCH_WFX, self.PROBE_BRANCH_CHORE, self.PROBE_BRANCH_CICHECK)):
            findings.append(Finding("BRANCH_DELETED_CLEANUP", "MEDIUM", f"Attacker cleanup: deleted branch {ref}",
                                    f"https://github.com/{repo}", repository=repo, actor=sender))
        return findings

    def scan_file_content(self, repo: str, path: str, content: str, ref: str = "main") -> list[Finding]:
        repo, path, content, ref = _as_str(repo), _as_str(path), _as_str(content), _as_str(ref)
        findings = []
        url = f"https://github.com/{repo}/blob/{ref}/{path}"
        for match in set(self.CONTENT_IOCS.findall(content)):
            findings.append(Finding("CONTENT_IOC_MATCH", "CRITICAL", f"{path}: contains IOC '{match}'", url, repository=repo))
        if path.endswith("package.json") and self.POSTINSTALL_CI_SH.search(content):
            findings.append(Finding("POSTINSTALL_CI_SH", "CRITICAL", f"{path}: postinstall runs .ci-*.sh", url, repository=repo))
        if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            size, lines = len(content.encode()), content.count("\n") + 1
            if size > self.OVERSIZED_WORKFLOW_BYTES or lines > self.OVERSIZED_WORKFLOW_LINES:
                findings.append(Finding("OVERSIZED_WORKFLOW", "HIGH", f"{path}: {size} bytes / {lines} lines", url, repository=repo))
        if path == ".vscode/tasks.json" and '"runOn": "folderOpen"' in content:
            findings.append(Finding("VSCODE_AUTORUN_TASK", "HIGH", f"{path}: runs on folderOpen", url, repository=repo))
        return findings

    def check_package_manifest(self, repo: str, manifest_path: str, content: str) -> list[Finding]:
        """Match malicious packages to their OWN declared version (defect 5).

        Naive substring matching produced false positives: a malicious name in one
        dependency and a bad-looking version in an unrelated dependency were paired.
        We parse the manifest and only report (name, version) pairs that actually
        occur together.
        """
        findings = []
        url = f"https://github.com/{repo}/blob/{manifest_path}"
        pairs: set[tuple[str, str]] = set()  # (name, version) declared in this manifest

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                deps = {}
                for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "require", "constraint"):
                    if key in node and isinstance(node[key], dict):
                        deps.update(node[key])
                for name, spec in deps.items():
                    if isinstance(name, str) and isinstance(spec, str):
                        pairs.add((name, spec))
                        pairs.add((name.replace("github:", ""), spec))
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        try:
            walk(json.loads(content))
        except (json.JSONDecodeError, TypeError, ValueError):
            # Non-JSON manifest (e.g. go.mod/composer.json): fall back to a
            # line-oriented parse that keeps name and version on the same line.
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                parts = line.replace(":", " ").replace('"', " ").split()
                if len(parts) >= 2:
                    pairs.add((parts[0], parts[1]))
                    pairs.add((parts[-1], parts[0]))

        for pkg, versions in self.MALICIOUS_PACKAGES.items():
            for name, version in pairs:
                if name == pkg and version in versions:
                    findings.append(Finding("MALICIOUS_PACKAGE_VERSION", "CRITICAL",
                                            f"{manifest_path}: malicious {pkg}@{version}", url, repository=repo,
                                            raw_data={"package": pkg, "version": version}))
        return findings

    def get_alerts(self, limit: int = 100) -> list[Finding]:
        return self.storage.get_alerts(limit)

    def clear_alerts(self) -> bool:
        return self.storage.clear_alerts()

    def get_alert_count(self) -> int:
        return self.storage.get_alert_count()

    def get_metrics(self, prefix: str = "") -> dict[str, int]:
        return self.storage.get_metrics(prefix)
