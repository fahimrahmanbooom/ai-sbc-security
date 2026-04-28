"""
File Integrity Monitor (FIM) — AI-powered
Maintains SHA256 baselines of critical system files, detects unauthorized
modifications, and uses ML to classify change patterns as benign vs. malicious.
"""

import asyncio
import hashlib
import json
import logging
import os
import stat
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# Where mutable state lives. Override with AISBC_DATA_DIR for Docker/dev runs.
AISBC_DATA_DIR = os.environ.get("AISBC_DATA_DIR", "/var/lib/ai-sbc-security")

# ── Critical paths to monitor ─────────────────────────────────────────────────
CRITICAL_PATHS: List[str] = [
    # Authentication & users
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    # SSH
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
    "/root/.ssh",
    "/home",          # watched at dir level — individual .ssh dirs
    # PAM
    "/etc/pam.d",
    # Cron
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.hourly",
    "/var/spool/cron",
    # systemd
    "/etc/systemd/system",
    "/lib/systemd/system",
    # Network
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/iptables",
    "/etc/nftables.conf",
    # Boot / kernel
    "/boot",
    "/etc/fstab",
    "/etc/modprobe.d",
    # Shells & profiles
    "/etc/profile",
    "/etc/profile.d",
    "/etc/bash.bashrc",
    "/etc/environment",
    # Package integrity
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
]

# Files to skip (noisy / ephemeral)
SKIP_PATTERNS: Set[str] = {
    ".pyc", ".pyo", ".log", ".pid", ".lock", ".tmp", ".swp",
    "~", ".cache", ".bak",
}

MAX_FILE_SIZE = 50 * 1024 * 1024   # 50 MB — skip larger files
SCAN_DEPTH    = 3                   # max directory recursion depth
RESCAN_INTERVAL = 300               # seconds between full scans


# ── Data structures ────────────────────────────────────────────────────────────
@dataclass
class FileRecord:
    path: str
    sha256: str
    size: int
    mtime: float
    mode: int
    uid: int
    gid: int
    scanned_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FIMEvent:
    event_type: str          # "modified" | "added" | "deleted" | "permissions"
    path: str
    severity: str            # "critical" | "high" | "medium" | "low"
    old_hash: Optional[str]
    new_hash: Optional[str]
    old_meta: Optional[dict]
    new_meta: Optional[dict]
    ml_score: float          # 0-1 suspicion score
    ml_label: str            # "benign" | "suspicious" | "malicious"
    timestamp: float = field(default_factory=time.time)
    description: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp_iso"] = datetime.fromtimestamp(
            self.timestamp, tz=timezone.utc
        ).isoformat()
        return d


# ── ML-based change classifier ─────────────────────────────────────────────────
class ChangeClassifier:
    """
    Lightweight heuristic + statistical classifier for file change events.
    Uses a feature vector and a hand-tuned scoring model (no heavy ML deps).
    Upgrades to IsolationForest-based anomaly detection once enough samples
    are collected.
    """

    # Weights for heuristic scoring
    WEIGHTS = {
        "is_critical_auth":   0.35,
        "is_executable":      0.20,
        "is_suid":            0.40,
        "odd_hour":           0.10,
        "rapid_change":       0.25,
        "size_spike":         0.15,
        "permission_loosen":  0.30,
        "root_owned_change":  0.20,
        "deleted_critical":   0.45,
        "new_executable":     0.30,
    }

    # Paths that are extremely sensitive
    AUTH_CRITICAL = {
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
        "/etc/sudoers",
    }

    def __init__(self):
        self._change_times: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=20)
        )
        self._anomaly_model = None
        self._training_buffer: List[List[float]] = []
        self._model_trained = False

        # Try to import sklearn for anomaly detection
        try:
            from sklearn.ensemble import IsolationForest
            self._IsolationForest = IsolationForest
        except ImportError:
            self._IsolationForest = None

    def _extract_features(
        self,
        event: FIMEvent,
        old: Optional[FileRecord],
        new: Optional[FileRecord],
    ) -> List[float]:
        path = event.path
        now_hour = datetime.fromtimestamp(event.timestamp).hour

        is_critical_auth = float(
            any(path.startswith(p) for p in self.AUTH_CRITICAL)
        )
        is_executable = float(
            new is not None and bool(new.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        )
        is_suid = float(
            new is not None and bool(new.mode & (stat.S_ISUID | stat.S_ISGID))
        )
        odd_hour = float(now_hour < 6 or now_hour >= 22)

        # Rapid successive changes on same file
        times = self._change_times[path]
        rapid_change = 0.0
        if len(times) >= 2:
            interval = times[-1] - times[-2]
            rapid_change = float(interval < 60)

        # Size spike (>50% increase)
        size_spike = 0.0
        if old and new and old.size > 0:
            ratio = (new.size - old.size) / old.size
            size_spike = float(ratio > 0.5)

        # Permissions loosened (e.g. 600 → 644 on shadow)
        permission_loosen = 0.0
        if old and new:
            old_bits = old.mode & 0o777
            new_bits = new.mode & 0o777
            permission_loosen = float(new_bits > old_bits)

        root_owned_change = float(
            new is not None and new.uid == 0
        )
        deleted_critical = float(
            event.event_type == "deleted" and is_critical_auth
        )
        new_executable = float(
            event.event_type == "added" and is_executable
        )

        return [
            is_critical_auth,
            is_executable,
            is_suid,
            odd_hour,
            rapid_change,
            size_spike,
            permission_loosen,
            root_owned_change,
            deleted_critical,
            new_executable,
        ]

    def score(
        self,
        event: FIMEvent,
        old: Optional[FileRecord],
        new: Optional[FileRecord],
    ) -> Tuple[float, str]:
        """Returns (suspicion_score 0-1, label)."""
        self._change_times[event.path].append(event.timestamp)

        features = self._extract_features(event, old, new)
        keys = list(self.WEIGHTS.keys())
        score = sum(
            features[i] * self.WEIGHTS[keys[i]] for i in range(len(keys))
        )
        score = min(1.0, score)

        # Feed training buffer for IsolationForest
        self._training_buffer.append(features)
        if (
            not self._model_trained
            and len(self._training_buffer) >= 200
            and self._IsolationForest
        ):
            self._train_anomaly_model()

        # If anomaly model is available, blend scores
        if self._model_trained and self._anomaly_model:
            try:
                arr = np.array(features).reshape(1, -1)
                iso_score = self._anomaly_model.decision_function(arr)[0]
                # Convert: negative = anomalous, positive = normal
                # Map to [0, 1] where 1 = most suspicious
                iso_norm = max(0.0, min(1.0, (-iso_score + 0.5)))
                score = 0.6 * score + 0.4 * iso_norm
            except Exception:
                pass

        label = (
            "malicious" if score >= 0.65
            else "suspicious" if score >= 0.35
            else "benign"
        )
        return round(score, 3), label

    def _train_anomaly_model(self):
        try:
            X = np.array(self._training_buffer[-2000:])
            model = self._IsolationForest(
                n_estimators=50,
                contamination=0.05,
                random_state=42,
            )
            model.fit(X)
            self._anomaly_model = model
            self._model_trained = True
            logger.info("FIM: IsolationForest model trained on %d samples", len(X))
        except Exception as e:
            logger.warning("FIM: anomaly model training failed: %s", e)


# ── Severity classifier ────────────────────────────────────────────────────────
def classify_severity(event: FIMEvent, ml_label: str) -> str:
    path = event.path

    # Escalate auth files always
    auth_critical = {"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/gshadow"}
    if any(path.startswith(p) for p in auth_critical):
        return "critical"

    if "/etc/ssh" in path or "/root/.ssh" in path:
        return "critical"

    # Boot / kernel modifications
    if path.startswith("/boot/") or "/systemd/" in path:
        if event.event_type in ("modified", "added"):
            return "critical"

    # Binaries
    if path.startswith(("/usr/bin", "/usr/sbin", "/bin", "/sbin")):
        if event.event_type == "modified":
            return "high"
        if event.event_type == "added" and ml_label in ("suspicious", "malicious"):
            return "high"

    if ml_label == "malicious":
        return "high"
    if ml_label == "suspicious":
        return "medium"

    return "low"


# ── Core FIM engine ────────────────────────────────────────────────────────────
class FileIntegrityMonitor:
    def __init__(self, baseline_path: Optional[str] = None):
        if baseline_path is None:
            baseline_path = os.path.join(AISBC_DATA_DIR, "fim_baseline.json")
        self.baseline_path = baseline_path
        self.baseline: Dict[str, FileRecord] = {}
        self.classifier = ChangeClassifier()
        self._callbacks: List[Callable] = []
        self._running = False
        self._scan_task: Optional[asyncio.Task] = None
        self._events: deque = deque(maxlen=500)
        self._stats = {
            "total_files_watched": 0,
            "total_events": 0,
            "last_scan": None,
            "baseline_established": False,
        }

    # ── Public API ─────────────────────────────────────────────────────────────
    def on_event(self, callback: Callable):
        self._callbacks.append(callback)

    async def start(self):
        self._running = True
        self._load_baseline()
        if not self.baseline:
            logger.info("FIM: no baseline found — performing initial scan")
            await self._full_scan(establish_baseline=True)
        else:
            logger.info("FIM: baseline loaded (%d files)", len(self.baseline))
        self._scan_task = asyncio.create_task(self._scan_loop())

    async def stop(self):
        self._running = False
        if self._scan_task:
            self._scan_task.cancel()

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "events_in_memory": len(self._events),
        }

    def get_recent_events(self, limit: int = 50) -> List[dict]:
        return [e.to_dict() for e in list(self._events)[-limit:]]

    def get_baseline_summary(self) -> dict:
        by_dir: Dict[str, int] = defaultdict(int)
        for p in self.baseline:
            top = "/" + p.strip("/").split("/")[1] if "/" in p else p
            by_dir[top] += 1
        return {
            "total_files": len(self.baseline),
            "by_directory": dict(sorted(by_dir.items(), key=lambda x: -x[1])[:15]),
        }

    async def force_rescan(self) -> dict:
        """Trigger an immediate rescan and return new events."""
        before = len(self._events)
        await self._full_scan(establish_baseline=False)
        new_events = list(self._events)[before:]
        return {
            "files_scanned": self._stats["total_files_watched"],
            "new_events": len(new_events),
            "events": [e.to_dict() for e in new_events],
        }

    async def rebaseline(self) -> dict:
        """Re-establish baseline from current state (use after verified clean state)."""
        await self._full_scan(establish_baseline=True)
        return {
            "files_baselined": len(self.baseline),
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }

    # ── Internal scan logic ────────────────────────────────────────────────────
    async def _scan_loop(self):
        while self._running:
            try:
                await asyncio.sleep(RESCAN_INTERVAL)
                await self._full_scan(establish_baseline=False)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("FIM scan loop error: %s", e)

    async def _full_scan(self, establish_baseline: bool = False):
        logger.info("FIM: starting %s scan", "baseline" if establish_baseline else "integrity")
        new_snapshot: Dict[str, FileRecord] = {}
        events: List[FIMEvent] = []

        paths_to_scan = self._gather_paths()

        for fpath in paths_to_scan:
            try:
                rec = self._hash_file(fpath)
                if rec:
                    new_snapshot[fpath] = rec
            except (PermissionError, FileNotFoundError):
                pass
            except Exception as e:
                logger.debug("FIM: error scanning %s: %s", fpath, e)
            # Yield control periodically
            await asyncio.sleep(0)

        self._stats["total_files_watched"] = len(new_snapshot)
        self._stats["last_scan"] = datetime.now(tz=timezone.utc).isoformat()

        if establish_baseline:
            self.baseline = new_snapshot
            self._save_baseline()
            self._stats["baseline_established"] = True
            logger.info("FIM: baseline established with %d files", len(self.baseline))
            return

        # Compare against baseline
        all_paths = set(self.baseline) | set(new_snapshot)
        for path in all_paths:
            old = self.baseline.get(path)
            new = new_snapshot.get(path)

            event = self._compare(path, old, new)
            if event:
                ml_score, ml_label = self.classifier.score(event, old, new)
                event.ml_score = ml_score
                event.ml_label = ml_label
                event.severity = classify_severity(event, ml_label)
                event.description = self._describe(event, old, new)
                events.append(event)
                self._events.append(event)
                self._stats["total_events"] += 1

        # Update baseline for non-suspicious changes (keep baseline fresh for benign)
        for ev in events:
            if ev.ml_label == "benign" and ev.event_type != "deleted":
                if ev.path in new_snapshot:
                    self.baseline[ev.path] = new_snapshot[ev.path]
            elif ev.event_type == "deleted" and ev.ml_label == "benign":
                self.baseline.pop(ev.path, None)

        # Add new benign files to baseline
        for path, rec in new_snapshot.items():
            if path not in self.baseline:
                self.baseline[path] = rec

        self._save_baseline()

        # Fire callbacks for non-benign events
        significant = [e for e in events if e.ml_label != "benign" or e.severity in ("critical", "high")]
        for ev in significant:
            for cb in self._callbacks:
                try:
                    if asyncio.iscoroutinefunction(cb):
                        await cb(ev)
                    else:
                        cb(ev)
                except Exception as e:
                    logger.error("FIM callback error: %s", e)

        if events:
            logger.info(
                "FIM: scan complete — %d changes detected (%d significant)",
                len(events), len(significant)
            )

    def _gather_paths(self) -> List[str]:
        """Recursively collect file paths under CRITICAL_PATHS."""
        result: List[str] = []
        seen: Set[str] = set()

        def recurse(path: str, depth: int):
            if depth > SCAN_DEPTH or path in seen:
                return
            seen.add(path)

            try:
                st = os.lstat(path)
            except (PermissionError, FileNotFoundError, OSError):
                return

            if stat.S_ISLNK(st.st_mode):
                return  # skip symlinks to avoid loops

            if stat.S_ISREG(st.st_mode):
                ext = Path(path).suffix.lower()
                name = Path(path).name
                if not any(name.endswith(p) for p in SKIP_PATTERNS):
                    if st.st_size <= MAX_FILE_SIZE:
                        result.append(path)
                return

            if stat.S_ISDIR(st.st_mode):
                try:
                    for entry in os.scandir(path):
                        recurse(entry.path, depth + 1)
                except PermissionError:
                    pass

        for base in CRITICAL_PATHS:
            recurse(base, 0)

        return result

    def _hash_file(self, path: str) -> Optional[FileRecord]:
        try:
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode):
                return None

            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)

            return FileRecord(
                path=path,
                sha256=h.hexdigest(),
                size=st.st_size,
                mtime=st.st_mtime,
                mode=st.st_mode,
                uid=st.st_uid,
                gid=st.st_gid,
            )
        except (PermissionError, FileNotFoundError, OSError):
            return None

    def _compare(
        self, path: str, old: Optional[FileRecord], new: Optional[FileRecord]
    ) -> Optional[FIMEvent]:
        if old is None and new is not None:
            return FIMEvent(
                event_type="added", path=path, severity="low",
                old_hash=None, new_hash=new.sha256,
                old_meta=None, new_meta={"size": new.size, "mode": oct(new.mode), "uid": new.uid},
                ml_score=0.0, ml_label="benign",
            )

        if old is not None and new is None:
            return FIMEvent(
                event_type="deleted", path=path, severity="low",
                old_hash=old.sha256, new_hash=None,
                old_meta={"size": old.size, "mode": oct(old.mode), "uid": old.uid},
                new_meta=None,
                ml_score=0.0, ml_label="benign",
            )

        if old and new:
            changes = []
            if old.sha256 != new.sha256:
                changes.append("content")
            if (old.mode & 0o7777) != (new.mode & 0o7777):
                changes.append("permissions")
            if old.uid != new.uid or old.gid != new.gid:
                changes.append("ownership")

            if not changes:
                return None

            event_type = "modified" if "content" in changes else "permissions"
            return FIMEvent(
                event_type=event_type, path=path, severity="low",
                old_hash=old.sha256, new_hash=new.sha256,
                old_meta={"size": old.size, "mode": oct(old.mode), "uid": old.uid, "gid": old.gid},
                new_meta={"size": new.size, "mode": oct(new.mode), "uid": new.uid, "gid": new.gid},
                ml_score=0.0, ml_label="benign",
                description=f"Changes: {', '.join(changes)}",
            )

        return None

    def _describe(
        self, event: FIMEvent, old: Optional[FileRecord], new: Optional[FileRecord]
    ) -> str:
        parts = [f"[{event.event_type.upper()}] {event.path}"]

        if event.event_type == "modified" and old and new:
            if old.sha256 != new.sha256:
                parts.append(f"Hash changed: {old.sha256[:12]}… → {new.sha256[:12]}…")
            if old.size != new.size:
                diff = new.size - old.size
                parts.append(f"Size: {old.size} → {new.size} ({'+' if diff>0 else ''}{diff} bytes)")

        if event.event_type == "permissions" and old and new:
            parts.append(f"Mode: {oct(old.mode)} → {oct(new.mode)}")
            if old.uid != new.uid:
                parts.append(f"UID: {old.uid} → {new.uid}")

        if event.ml_label != "benign":
            parts.append(f"ML: {event.ml_label} (score={event.ml_score:.2f})")

        return " | ".join(parts)

    # ── Persistence ────────────────────────────────────────────────────────────
    def _save_baseline(self):
        try:
            os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)
            data = {k: v.to_dict() for k, v in self.baseline.items()}
            tmp = self.baseline_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f, separators=(",", ":"))
            os.replace(tmp, self.baseline_path)
        except Exception as e:
            logger.error("FIM: failed to save baseline: %s", e)

    def _load_baseline(self):
        try:
            if not os.path.exists(self.baseline_path):
                return
            with open(self.baseline_path) as f:
                data = json.load(f)
            self.baseline = {
                k: FileRecord(**v) for k, v in data.items()
            }
            self._stats["baseline_established"] = True
        except Exception as e:
            logger.warning("FIM: failed to load baseline: %s — will re-establish", e)
            self.baseline = {}


# ── Singleton ──────────────────────────────────────────────────────────────────
_fim_instance: Optional[FileIntegrityMonitor] = None

def get_fim() -> FileIntegrityMonitor:
    global _fim_instance
    if _fim_instance is None:
        _fim_instance = FileIntegrityMonitor()
    return _fim_instance
