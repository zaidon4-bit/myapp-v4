from __future__ import annotations

import argparse
import hmac
import hashlib
import secrets
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .. import __version__
from .. import cli
from ..apk_assets import find_apk_bundle_root, validate_apk_bundle

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_LOG_CHARS = 120000
WSL_RISK_PHRASE = "yes"
ANDROID_TEXT_SPECIALS = set("'\"`$&|;<>(){}[]*?!#~")

SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|token|secret|api[_-]?key)=([^\s&]+)"),
    re.compile(r"(?i)(https?|socks5?)://([^:@\s/]+):([^@\s/]+)@"),
    re.compile(r"(?i)(--proxy\s+)(\S+)"),
    re.compile(r"(?i)(proxy\s*[:=]\s*)(\S+)"),
]

COMMAND_TIMEOUTS = {
    "check-env": 900,
    "install-deps": 2400,
    "fix-wsl": 1200,
    "install-apks": 2400,
    "install-image": 3600,
    "install-viewer": 1800,
    "devices": 60,
    "wsl-kernel-status": 120,
    "wsl-kernel-install": 900,
    "screenshot": 120,
    "quick-check": 120,
    "navigate": 90,
    "record": 240,
    "view": 30,
    "proof": 3600,
    "proof-all": 7200,
    "start-workers": 1800,
    "resume-workers": 1800,
    "add-worker": 1800,
    "add-workers": 3600,
    "resume-worker": 180,
    "stop-worker": 180,
    "delete-worker": 180,
    "restart-worker": 900,
    "stop-workers": 300,
    "delete-workers": 300,
    "fix-internet": 120,
    "random-profile": 240,
    "random-profile-all": 1200,
}

PROBE_INVALIDATING_ACTIONS = {
    "install-deps",
    "fix-wsl",
    "install-apks",
    "install-image",
    "install-viewer",
    "wsl-kernel-install",
    "start-workers",
    "resume-workers",
    "add-worker",
    "add-workers",
    "resume-worker",
    "stop-worker",
    "delete-worker",
    "restart-worker",
    "stop-workers",
    "delete-workers",
    "fix-internet",
    "random-profile",
    "random-profile-all",
}




SUBSCRIPTIONS_DB = cli._repo_root() / "infinite_subscriptions.db"
ADMIN_SESSION_TTL = 8 * 60 * 60
_ADMIN_SESSIONS: dict[str, float] = {}
_ADMIN_SESSION_LOCK = threading.Lock()
_USER_SESSIONS: dict[str, float] = {}
_USER_SESSION_LOCK = threading.Lock()
USER_SESSION_TTL = 24 * 60 * 60


def subscription_db() -> sqlite3.Connection:
    conn = sqlite3.connect(SUBSCRIPTIONS_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL DEFAULT '',
        plan TEXT NOT NULL DEFAULT 'manual',
        status TEXT NOT NULL DEFAULT 'active',
        starts_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        notes TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""")
    try:
        conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    conn.commit()
    return conn


def hash_user_password(password: str) -> str:
    if not password or len(password) < 8:
        raise ValueError("User password must be at least 8 characters.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240_000)
    return "pbkdf2_sha256$240000$" + salt.hex() + "$" + digest.hex()


def verify_user_password(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt_hex, digest_hex = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def create_user_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    with _USER_SESSION_LOCK:
        _USER_SESSIONS[token] = time.time() + USER_SESSION_TTL
    return token


def valid_user_session(token: str) -> bool:
    if not token:
        return False
    with _USER_SESSION_LOCK:
        expiry = _USER_SESSIONS.get(token)
        if not expiry or expiry <= time.time():
            _USER_SESSIONS.pop(token, None)
            return False
        return True


def user_session_token(handler: Any) -> str:
    return parse_cookie(handler.headers.get("Cookie", "")).get("infinite_user", "")


def authenticated_username(handler: Any) -> str | None:
    token = user_session_token(handler)
    if not valid_user_session(token):
        return None
    with _USER_SESSION_LOCK:
        pass
    # Session tokens are intentionally opaque; resolve username from a separate map.
    return _USER_SESSION_USERS.get(token)


def user_login(username: str, password: str) -> dict[str, Any] | None:
    conn = subscription_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row or not row["password_hash"] or not verify_user_password(password, row["password_hash"]):
            return None
        # A subscription is usable only while active and inside its date window.
        now = time.time()
        try:
            starts = __import__("datetime").datetime.fromisoformat(row["starts_at"].replace("Z", "+00:00")).timestamp()
            expires = __import__("datetime").datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")).timestamp()
        except Exception:
            return None
        if row["status"] != "active" or now < starts or now >= expires:
            return None
        return dict(row)
    finally:
        conn.close()


_USER_SESSION_USERS: dict[str, str] = {}

def user_authenticated(handler: Any) -> bool:
    return authenticated_username(handler) is not None


def admin_password() -> str:
    return os.environ.get("INFINITE_ADMIN_PASSWORD", "")


def create_admin_session() -> str:
    token = secrets.token_urlsafe(32)
    with _ADMIN_SESSION_LOCK:
        _ADMIN_SESSIONS[token] = time.time() + ADMIN_SESSION_TTL
    return token


def valid_admin_session(token: str) -> bool:
    if not token:
        return False
    now = time.time()
    with _ADMIN_SESSION_LOCK:
        expiry = _ADMIN_SESSIONS.get(token)
        if not expiry or expiry <= now:
            _ADMIN_SESSIONS.pop(token, None)
            return False
        return True


def parse_cookie(header: str) -> dict[str, str]:
    result = {}
    for item in (header or "").split(";"):
        if "=" in item:
            k, v = item.strip().split("=", 1)
            result[k] = v
    return result


def admin_authenticated(handler: Any) -> bool:
    return valid_admin_session(parse_cookie(handler.headers.get("Cookie", "")).get("infinite_admin", ""))


def subscription_rows() -> list[dict[str, Any]]:
    conn = subscription_db()
    try:
        rows = conn.execute("SELECT id,username,plan,status,starts_at,expires_at,notes,created_at,updated_at FROM users ORDER BY expires_at DESC, username COLLATE NOCASE").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def upsert_subscription(payload: dict[str, Any]) -> dict[str, Any]:
    username = str(payload.get("username") or "").strip()
    plan = str(payload.get("plan") or "manual").strip() or "manual"
    status = str(payload.get("status") or "active").strip() or "active"
    starts_at = str(payload.get("starts_at") or "").strip()
    expires_at = str(payload.get("expires_at") or "").strip()
    notes = str(payload.get("notes") or "").strip()[:2000]
    password = str(payload.get("password") or "")
    if not username or len(username) > 120:
        raise ValueError("Username is required and must be at most 120 characters.")
    if not starts_at or not expires_at:
        raise ValueError("Start and expiry dates are required.")
    if status not in {"active", "paused", "expired", "cancelled"}:
        raise ValueError("Invalid subscription status.")
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn = subscription_db()
    try:
        existing = conn.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
        if existing and existing["password_hash"] and not password:
            password_hash = existing["password_hash"]
        else:
            password_hash = hash_user_password(password)
        conn.execute("""INSERT INTO users(username,password_hash,plan,status,starts_at,expires_at,notes,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,plan=excluded.plan,status=excluded.status,
            starts_at=excluded.starts_at,expires_at=excluded.expires_at,notes=excluded.notes,updated_at=excluded.updated_at""",
            (username, password_hash, plan, status, starts_at, expires_at, notes, now, now))
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row)
    finally:
        conn.close()


def delete_subscription(username: str) -> None:
    conn = subscription_db()
    try:
        cur = conn.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()
        if cur.rowcount == 0:
            raise KeyError("User not found")
    finally:
        conn.close()


def redact(value: str) -> str:
    text = value or ""
    text = SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)}://<redacted>:<redacted>@", text)
    text = SECRET_PATTERNS[2].sub(lambda m: f"{m.group(1)}<redacted>", text)
    text = SECRET_PATTERNS[3].sub(lambda m: f"{m.group(1)}<redacted>", text)
    return text


def android_input_text(value: str) -> str:
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = " ".join(part for part in text.split("\n") if part)[:500]
    out: list[str] = []
    for ch in text:
        if ch == " ":
            out.append("%s")
        elif ch == "%":
            out.append("%25")
        elif ch in ANDROID_TEXT_SPECIALS:
            out.append("\\" + ch)
        elif ord(ch) >= 32:
            out.append(ch)
    return "".join(out)


def now_ms() -> int:
    return int(time.time() * 1000)


def static_dir() -> Path:
    return Path(__file__).resolve().parent / "static"


def capture_dir() -> Path:
    path = cli._repo_root() / "docs" / "assets" / "ui-captures"
    path.mkdir(parents=True, exist_ok=True)
    return path


def package_command(*parts: str) -> list[str]:
    return [sys.executable, "-m", "damru", *parts]


def run_text(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")


def config_snapshot() -> dict[str, Any]:
    try:
        from .. import config
    except Exception as exc:
        return {"error": str(exc)}

    keys = ["MODE", "NUM_DEVICES", "WSL_DISTRO", "WSL_USERNAME", "REDROID_IMAGE", "CHROME_APK", "REDROID_BASE_PORT"]
    data: dict[str, Any] = {}
    for key in keys:
        if hasattr(config, key):
            value = getattr(config, key)
            if "PASSWORD" in key or "PROXY" in key:
                value = "<redacted>" if value else ""
            data[key] = value
    return data

def config_backups() -> list[dict[str, Any]]:
    target = cli._config_path()
    backups = sorted(
        target.parent.glob(target.name + ".ui-backup-*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return [
        {
            "name": path.name,
            "path": str(path),
            "modified_ms": int(path.stat().st_mtime * 1000),
            "size": path.stat().st_size,
        }
        for path in backups[:20]
        if path.is_file()
    ]

def _reload_config_module() -> None:
    import importlib
    import sys
    for name in list(sys.modules.keys()):
        if name.endswith("damru.config"):
            try:
                importlib.reload(sys.modules[name])
            except Exception:
                pass

def restore_config_backup(name: str | None = None) -> Path:
    target = cli._config_path()
    backups = config_backups()
    if not backups:
        raise FileNotFoundError("No UI config backups found")
    selected = None
    if name:
        for item in backups:
            if item["name"] == name:
                selected = Path(item["path"])
                break
        if selected is None:
            raise FileNotFoundError("Requested config backup was not found")
    else:
        selected = Path(backups[0]["path"])
    if selected.parent.resolve() != target.parent.resolve() or not selected.name.startswith(target.name + ".ui-backup-"):
        raise ValueError("Invalid config backup path")
    shutil.copy2(selected, target)
    _reload_config_module()
    return selected


def safe_write_config(updates: dict[str, Any]) -> Path:
    allowed: dict[str, Any] = {
        "MODE": str,
        "NUM_DEVICES": int,
        "WSL_DISTRO": str,
        "WSL_USERNAME": str,
        "REDROID_IMAGE": str,
        "CHROME_APK": (str, type(None)),
        "REDROID_BASE_PORT": int,
    }
    clean: dict[str, Any] = {}
    for key, value in updates.items():
        if key not in allowed:
            continue
        if value == "":
            value = None if key == "CHROME_APK" else value
        if allowed[key] is int:
            value = int(value)
        elif not isinstance(value, allowed[key]):
            value = str(value)
        clean[key] = value
    if not clean:
        raise ValueError("No supported config keys were provided")
    res = cli._write_config(clean)
    _reload_config_module()
    return res


@dataclass
class Job:
    id: str
    name: str
    command_key: str
    command: list[str]
    status: str = "queued"
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    created_ms: int = field(default_factory=now_ms)
    started_ms: int | None = None
    ended_ms: int | None = None
    artifact: str | None = None

    def to_dict(self, include_log: bool = True) -> dict[str, Any]:
        log = redact((self.stdout or "") + ("\n" if self.stdout and self.stderr else "") + (self.stderr or ""))
        if len(log) > MAX_LOG_CHARS:
            log = log[-MAX_LOG_CHARS:]
        return {
            "id": self.id,
            "name": self.name,
            "command_key": self.command_key,
            "command": redact(" ".join(self.command)),
            "status": self.status,
            "returncode": self.returncode,
            "created_ms": self.created_ms,
            "started_ms": self.started_ms,
            "ended_ms": self.ended_ms,
            "duration_ms": (self.ended_ms or now_ms()) - (self.started_ms or self.created_ms),
            "artifact": self.artifact,
            "log": log if include_log else "",
        }


class UIState:
    def __init__(self) -> None:
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()

    def add_job(self, name: str, command_key: str, command: list[str], timeout: int, artifact: str | None = None) -> Job:
        if command_key in PROBE_INVALIDATING_ACTIONS:
            clear_probe_cache()
        job = Job(id=uuid.uuid4().hex[:12], name=name, command_key=command_key, command=command, artifact=artifact)
        with self.lock:
            self.jobs[job.id] = job
        thread = threading.Thread(target=self._run_job, args=(job, timeout), daemon=True)
        thread.start()
        return job

    def _run_job(self, job: Job, timeout: int) -> None:
        with self.lock:
            job.status = "running"
            job.started_ms = now_ms()
        try:
            if job.command_key == "view":
                subprocess.Popen(
                    job.command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                )
                with self.lock:
                    job.returncode = 0
                    job.stdout = "Viewer launch requested. Close the scrcpy window when finished."
                    job.status = "success"
                    job.ended_ms = now_ms()
                return
            proc = run_text(job.command, timeout=timeout)
            with self.lock:
                job.returncode = proc.returncode
                job.stdout = redact(proc.stdout or "")
                job.stderr = redact(proc.stderr or "")
                job.status = "success" if proc.returncode == 0 else "failed"
                job.ended_ms = now_ms()
        except subprocess.TimeoutExpired as exc:
            with self.lock:
                job.returncode = 124
                job.stdout = redact(exc.stdout or "") if isinstance(exc.stdout, str) else ""
                job.stderr = redact((exc.stderr or "") if isinstance(exc.stderr, str) else "") + f"\nTimed out after {timeout}s."
                job.status = "failed"
                job.ended_ms = now_ms()
        except Exception as exc:
            with self.lock:
                job.returncode = 1
                job.stderr = redact(str(exc))
                job.status = "failed"
                job.ended_ms = now_ms()
        finally:
            if job.command_key in PROBE_INVALIDATING_ACTIONS:
                clear_probe_cache()

    def list_jobs(self) -> list[dict[str, Any]]:
        with self.lock:
            jobs = sorted(self.jobs.values(), key=lambda j: j.created_ms, reverse=True)
            return [job.to_dict(include_log=False) for job in jobs]

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.lock:
            job = self.jobs.get(job_id)
            return job.to_dict(include_log=True) if job else None

    def clear_finished_jobs(self) -> int:
        with self.lock:
            removable = [job_id for job_id, job in self.jobs.items() if job.status in {"success", "failed", "queued"}]
            for job_id in removable:
                self.jobs.pop(job_id, None)
            return len(removable)

    def add_failed_job(self, name: str, command_key: str, message: str) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], name=name, command_key=command_key, command=[])
        job.status = "failed"
        job.returncode = 1
        job.stderr = redact(message)
        job.started_ms = now_ms()
        job.ended_ms = job.started_ms
        with self.lock:
            self.jobs[job.id] = job
        return job


STATE = UIState()

_CACHE: dict[str, tuple[float, Any]] = {}
_CACHE_LOCKS: dict[str, threading.Lock] = {}
_CACHE_ROOT_LOCK = threading.Lock()
_VIEWER_CONNECT: dict[str, float] = {}
_VIEWER_CONNECT_LOCK = threading.Lock()

def cached_value(key: str, ttl: float, builder: Any) -> Any:
    now = time.monotonic()
    with _CACHE_ROOT_LOCK:
        lock = _CACHE_LOCKS.setdefault(key, threading.Lock())
    with lock:
        hit = _CACHE.get(key)
        if hit and hit[0] > now:
            return hit[1]
        value = builder()
        _CACHE[key] = (time.monotonic() + ttl, value)
        return value

def clear_probe_cache() -> None:
    with _CACHE_ROOT_LOCK:
        _CACHE.clear()

def ensure_viewer_adb(serial: str) -> None:
    now = time.monotonic()
    with _VIEWER_CONNECT_LOCK:
        last = _VIEWER_CONNECT.get(serial, 0.0)
        if now - last < 20.0:
            return
        cli._ensure_adb_connected(serial)
        _VIEWER_CONNECT[serial] = now


def detect_environment() -> dict[str, Any]:
    return cached_value("env", 30.0, _detect_environment_uncached)

def _detect_environment_uncached() -> dict[str, Any]:
    is_windows = cli._is_windows()
    is_wsl = cli._is_wsl_linux()
    env = {
        "platform": platform.system(),
        "release": platform.release(),
        "python": platform.python_version(),
        "damru_version": __version__,
        "is_windows": is_windows,
        "is_wsl_linux": is_wsl,
        "is_native_linux": platform.system() == "Linux" and not is_wsl,
        "wsl_distro": cli._configured_wsl_distro() if is_windows else "",
        "cwd": str(cli._repo_root()),
    }
    if is_windows and shutil.which("wsl"):
        proc = run_text(["wsl", "-d", env["wsl_distro"], "--", "uname", "-r"], timeout=15)
        env["kernel"] = redact((proc.stdout or proc.stderr).strip())
    elif platform.system() == "Linux":
        env["kernel"] = platform.uname().release
    else:
        env["kernel"] = ""
    return env


def command_status_linux(command: str) -> bool:
    try:
        return cli._check_command_linux(command)
    except Exception:
        return False

def command_statuses_linux(commands: tuple[str, ...]) -> dict[str, bool]:
    def _probe() -> dict[str, bool]:
        try:
            script = "\n".join(
                f"if command -v {cli.shlex.quote(command)} >/dev/null 2>&1; then echo {cli.shlex.quote(command)}=1; else echo {cli.shlex.quote(command)}=0; fi"
                for command in commands
            )
            proc = cli._linux_run(script, timeout=8)
        except Exception:
            return {command: False for command in commands}
        out: dict[str, bool] = {command: False for command in commands}
        for line in (proc.stdout or "").splitlines():
            if "=" not in line:
                continue
            key, value = line.rsplit("=", 1)
            if key in out:
                out[key] = value.strip() == "1"
        return out

    return cached_value("commands:" + ",".join(commands), 30.0, _probe)


def next_action(checks: list[dict[str, Any]], status: str) -> dict[str, str]:
    if status == "unsupported":
        return {"label": "Read requirements", "action": "none"}
    for key in ("wsl", "adb", "docker", "curl", "wget", "jq"):
        if any(c["key"] == key and not c["ok"] for c in checks):
            return {"label": "Install dependencies", "action": "install-deps"}
    if any(c["key"] in {"docker-daemon", "binderfs"} and not c["ok"] for c in checks):
        return {"label": "Repair Docker / binderfs", "action": "fix-wsl"}
    if any(c["key"] == "apks" and not c["ok"] for c in checks):
        return {"label": "Install APK bundle", "action": "install-apks"}
    if any(c["key"] == "image" and not c["ok"] for c in checks):
        return {"label": "Install Redroid image", "action": "install-image"}
    return {"label": "Start working", "action": "workers"}


def quick_health() -> dict[str, Any]:
    return cached_value("health", 6.0, _quick_health_uncached)

def _quick_health_uncached() -> dict[str, Any]:
    env = detect_environment()
    checks: list[dict[str, Any]] = []

    def add(key: str, label: str, ok: bool, detail: str = "", repair: str | None = None) -> None:
        checks.append({"key": key, "label": label, "ok": bool(ok), "detail": redact(detail), "repair": repair})

    supported_os = bool(env["is_windows"] or env["is_wsl_linux"] or env["is_native_linux"])
    add("os", "Supported host", supported_os, "Windows WSL2 Ubuntu or native Ubuntu" if supported_os else "Unsupported host")
    add("python", "Python 3.10+", sys.version_info >= (3, 10), platform.python_version())
    if env["is_windows"]:
        add("wsl", "WSL launcher", shutil.which("wsl") is not None, env.get("wsl_distro", ""), "install-deps")

    command_names = ("adb", "docker", "curl", "wget", "jq")
    command_status = command_statuses_linux(command_names)
    for command in command_names:
        add(command, f"Linux command: {command}", command_status.get(command, False), repair="install-deps")

    def probe_docker() -> bool:
        try:
            return cli._docker_info_ok(timeout=2)
        except Exception:
            return False

    def probe_binderfs() -> bool:
        try:
            return cli._linux_run("test -d /dev/binderfs && mount | grep -q ' /dev/binderfs '", timeout=5, root_user=env["is_windows"]).returncode == 0
        except Exception:
            return False

    def probe_apks() -> tuple[bool, str]:
        try:
            apk_root = find_apk_bundle_root()
            if apk_root:
                return validate_apk_bundle(apk_root)
            return False, "not found"
        except Exception as exc:
            return False, str(exc)

    def probe_viewer() -> bool:
        try:
            return cli._check_command_host_or_linux("scrcpy")
        except Exception:
            return False

    def probe_internet() -> tuple[bool, str]:
        try:
            dns = cli._linux_run("timeout 10 getent hosts example.com >/dev/null 2>&1", timeout=15, root_user=env["is_windows"])
            ip = cli._linux_run(
                "timeout 8 python3 -c \"import socket; s=socket.create_connection(('example.com',443),5); s.close()\" >/dev/null 2>&1",
                timeout=10,
                root_user=env["is_windows"],
            )
            if dns.returncode == 0 and ip.returncode == 0:
                return True, "DNS and TCP internet reachable"
            return False, f"DNS rc={dns.returncode}, TCP rc={ip.returncode}"
        except Exception as exc:
            return False, str(exc)

    with ThreadPoolExecutor(max_workers=5) as pool:
        docker_future = pool.submit(probe_docker)
        binderfs_future = pool.submit(probe_binderfs)
        apks_future = pool.submit(probe_apks)
        viewer_future = pool.submit(probe_viewer)
        internet_future = pool.submit(probe_internet)

        docker_ok = docker_future.result()
        binderfs_ok = binderfs_future.result()
        apk_ok, apk_detail = apks_future.result()
        viewer_ok = viewer_future.result()
        internet_ok, internet_detail = internet_future.result()

    add("internet", "Linux/WSL internet", internet_ok, internet_detail, "fix-internet")
    add("docker-daemon", "Docker daemon", docker_ok, "running" if docker_ok else "not reachable", "fix-wsl" if env["is_windows"] else "install-deps")
    add("binderfs", "binderfs mounted", binderfs_ok, "/dev/binderfs", "fix-wsl")
    add("apks", "APK bundle", apk_ok, apk_detail, "install-apks")

    try:
        from ..config import REDROID_IMAGE
    except Exception:
        REDROID_IMAGE = "damru-redroid:latest"
    image_ok = False
    if docker_ok:
        try:
            image_ok = cli._linux_run(f"docker images -q {cli.shlex.quote(REDROID_IMAGE)} | grep -q .", timeout=8, root_user=env["is_windows"]).returncode == 0
        except Exception:
            image_ok = False
    add("image", f"Redroid image: {REDROID_IMAGE}", image_ok, "loaded" if image_ok else "missing or Docker unavailable", "install-image")
    add("viewer", "Optional viewer", viewer_ok, "scrcpy" if viewer_ok else "not installed", "install-viewer")

    critical = [c for c in checks if not c["ok"] and c["key"] not in {"viewer"}]
    status = "ready" if not critical else ("needs_setup" if supported_os else "unsupported")
    return {
        "status": status,
        "env": env,
        "config": config_snapshot(),
        "checks": checks,
        "next_action": next_action(checks, status),
        "jobs": STATE.list_jobs()[:5],
        "workers": worker_summary(),
    }


def parse_adb_devices(text: str) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            devices.append({"serial": parts[0], "state": parts[1]})
    return devices


def _linux_adb_devices() -> list[dict[str, str]]:
    try:
        proc = cli._linux_run("adb devices -l", timeout=6)
    except Exception:
        return []
    if proc.returncode != 0:
        return []
    devices = parse_adb_devices(proc.stdout or "")
    if cli._is_windows():
        for device in devices:
            if not device["serial"].startswith("wsl:"):
                device["serial"] = "wsl:" + device["serial"]
    return devices


def adb_devices(workers: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    def _probe() -> list[dict[str, str]]:
        try:
            return parse_adb_devices(cli._adb_devices_text())
        except Exception:
            return []

    devices = cached_value("adb-devices", 15.0, _probe)
    if not cli._is_windows():
        return devices
    try:
        from ..config import MODE
    except Exception:
        MODE = "auto"
    if MODE not in ("auto", "docker"):
        return devices
    try:
        from ..config import REDROID_BASE_PORT
    except Exception:
        REDROID_BASE_PORT = 5600
    allowed: set[str] = set()
    for worker in workers if workers is not None else docker_workers():
        name = str(worker.get("name") or "")
        if str(worker.get("state") or "").lower() != "running":
            continue
        match = re.search(r"(\d+)$", name)
        if not match:
            continue
        port = int(REDROID_BASE_PORT) + int(match.group(1))
        allowed.add(f"wsl:127.0.0.1:{port}")
    present = {d.get("serial") for d in devices}
    missing = sorted(allowed - present)
    if missing:
        for serial in missing:
            try:
                cli._ensure_adb_connected(serial)
            except Exception:
                pass
        _CACHE.pop("adb-devices", None)
        devices = _probe()
    return [d for d in devices if d.get("serial") in allowed]


def docker_workers() -> list[dict[str, Any]]:
    return cached_value("docker-workers", 15.0, _docker_workers_uncached)


def _docker_workers_uncached() -> list[dict[str, Any]]:
    try:
        proc = cli._linux_run("docker ps -a --filter name=damru --format '{{json .}}'", timeout=8, root_user=cli._is_windows())
    except Exception:
        return []
    raw_workers: list[dict[str, Any]] = []
    for line in (proc.stdout or "").splitlines():
        try:
            raw_workers.append(json.loads(line))
        except Exception:
            continue

    boot_by_name: dict[str, str] = {}
    names = [str(item.get("Names") or "") for item in raw_workers if item.get("Names")]
    if names:
        lines = [
            f"if [ \"$(docker inspect -f '{{{{.State.Running}}}}' {cli.shlex.quote(name)} 2>/dev/null)\" = true ]; then printf '%s=' {cli.shlex.quote(name)}; docker exec {cli.shlex.quote(name)} getprop sys.boot_completed 2>/dev/null || true; else printf '%s=stopped\\n' {cli.shlex.quote(name)}; fi"
            for name in names
        ]
        try:
            boot_proc = cli._linux_run("\n".join(lines), timeout=max(4, len(names) * 2), root_user=cli._is_windows())
            for line in (boot_proc.stdout or "").splitlines():
                if "=" not in line:
                    continue
                name, value = line.split("=", 1)
                raw_value = value.strip()
                boot_by_name[name] = "stopped" if raw_value == "stopped" else ("booted" if raw_value == "1" else "booting")
        except Exception:
            pass

    workers: list[dict[str, Any]] = []
    for item in raw_workers:
        name = item.get("Names", "")
        workers.append({"id": item.get("ID", ""), "name": name, "image": item.get("Image", ""), "status": item.get("Status", ""), "state": item.get("State", ""), "ports": item.get("Ports", ""), "boot": boot_by_name.get(name, "unknown")})

    def sort_key(worker: dict[str, Any]) -> tuple[int, str]:
        match = re.search(r"(\d+)$", str(worker.get("name") or ""))
        return (int(match.group(1)) if match else 9999, str(worker.get("name") or ""))

    return sorted(workers, key=sort_key)


def worker_summary() -> dict[str, Any]:
    workers = docker_workers()
    devices = adb_devices(workers)
    return {"count": len(workers), "running": len([w for w in workers if w.get("state") == "running"]), "booted": len([w for w in workers if w.get("boot") == "booted"]), "adb_devices": devices}


def captures() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    root = capture_dir()
    for path in sorted(root.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
        if path.suffix.lower() not in {".png", ".mp4", ".json"}:
            continue
        out.append({"name": path.name, "path": str(path), "url": "/captures/" + path.name, "size": path.stat().st_size, "modified_ms": int(path.stat().st_mtime * 1000), "type": path.suffix.lower().lstrip(".")})
    return out

def clear_captures() -> dict[str, int]:
    root = capture_dir().resolve()
    removed = 0
    for path in root.iterdir():
        target = path.resolve()
        if root not in target.parents and target != root:
            continue
        if path.is_dir():
            shutil.rmtree(path)
            removed += 1
        elif path.suffix.lower() in {".png", ".mp4", ".json"}:
            path.unlink()
            removed += 1
    return {"removed": removed}


def build_command(action: str, payload: dict[str, Any]) -> tuple[str, list[str], int, str | None]:
    timeout = COMMAND_TIMEOUTS.get(action, 600)
    artifact = None
    if action == "check-env":
        return "Check environment", package_command("check-env", "--viewer"), timeout, artifact
    if action == "install-deps":
        return "Install dependencies", package_command("install-deps", "-y"), timeout, artifact
    if action == "fix-wsl":
        return "Repair WSL/Linux runtime", package_command("fix-wsl", "-y"), timeout, artifact
    if action == "install-apks":
        return "Install APK bundle", package_command("install-apks", "--download"), timeout, artifact
    if action == "install-image":
        return "Install Redroid image", package_command("install-image", "--download"), timeout, artifact
    if action == "install-viewer":
        return "Install viewer", package_command("install-viewer", "-y"), timeout, artifact
    if action == "fix-internet":
        serial = str(payload.get("serial") or "").strip()
        cmd = package_command("fix-internet")
        if serial:
            cmd.extend(["--serial", serial])
        elif payload.get("all"):
            cmd.append("--all")
        return "Fix internet", cmd, timeout, artifact
    if action == "random-profile":
        proxy = str(payload.get("proxy") or "").strip()
        extra: list[str] = []
        if proxy:
            extra.extend(["--proxy", proxy])
        if payload.get("all"):
            return "Random stealth profile all", package_command("random-profile", "--all", *extra), COMMAND_TIMEOUTS.get("random-profile-all", timeout), artifact
        serial = str(payload.get("serial") or "").strip()
        if not serial:
            raise ValueError("Choose an online ADB device first.")
        return "Random stealth profile", package_command("random-profile", "--serial", serial, *extra), timeout, artifact
    if action == "devices":
        return "List ADB devices", package_command("devices"), timeout, artifact
    if action == "wsl-kernel-status":
        return "Check WSL kernel", package_command("wsl-kernel", "status"), timeout, artifact
    if action == "wsl-kernel-install":
        if payload.get("phrase") != WSL_RISK_PHRASE:
            raise PermissionError("Exact WSL risk phrase is required")
        return "Install Damru WSL kernel", package_command("wsl-kernel", "install", "-y", "--confirm-wsl-kernel-risk"), timeout, artifact
    if action == "screenshot":
        serial = str(payload.get("serial") or "").strip()
        name = f"screenshot-{int(time.time())}.png"
        artifact_path = capture_dir() / name
        cmd = package_command("screenshot", "--output", str(artifact_path))
        if serial:
            cmd.extend(["--serial", serial])
        return "Capture screenshot", cmd, timeout, "/captures/" + name
    if action == "quick-check":
        serial = str(payload.get("serial") or "").strip()
        if not serial:
            raise ValueError("Choose an online ADB device before running quick checker.")
        name = f"quick-check-{int(time.time())}.json"
        artifact_path = capture_dir() / name
        return "Quick checker", package_command("quick-check", "--serial", serial, "--output", str(artifact_path)), timeout, "/captures/" + name
    if action == "navigate":
        serial = str(payload.get("serial") or "").strip()
        url = str(payload.get("url") or "").strip()
        if not serial:
            raise ValueError("Choose an online ADB device before opening a URL.")
        if not re.match(r"^https?://", url, re.IGNORECASE):
            raise ValueError("Enter a URL that starts with http:// or https://.")
        proxy = str(payload.get("proxy") or "").strip()
        cmd = package_command("stealth-open-url", "--serial", serial, "--url", url)
        if proxy:
            cmd.extend(["--proxy", proxy])
        return "Open URL", cmd, COMMAND_TIMEOUTS.get("proof", 300), artifact
    if action == "record":
        serial = str(payload.get("serial") or "").strip()
        seconds = max(1, min(int(payload.get("time_limit") or 15), 180))
        name = f"record-{int(time.time())}.mp4"
        artifact_path = capture_dir() / name
        cmd = package_command("record", "--output", str(artifact_path), "--time-limit", str(seconds))
        if serial:
            cmd.extend(["--serial", serial])
        return "Record device", cmd, timeout, "/captures/" + name
    if action == "view":
        if not cli._check_command_host_or_linux("scrcpy"):
            raise RuntimeError("scrcpy is not installed. Run install viewer first.")
        serial = str(payload.get("serial") or "").strip()
        cmd = package_command("view")
        if serial:
            cmd.extend(["--serial", serial])
        if payload.get("no_control"):
            cmd.append("--no-control")
        max_size = str(payload.get("max_size") or "").strip()
        if max_size:
            cmd.extend(["--max-size", max_size])
        return "Open viewer", cmd, timeout, artifact
    if action == "proof":
        out_root = capture_dir() / f"proof-{int(time.time())}"
        out_root.mkdir(parents=True, exist_ok=True)
        cmd = package_command("benchmark", "--screenshots", str(out_root), "--output", str(out_root / "proof.json"))
        serial = str(payload.get("serial") or "").strip()
        url_proxy = str(payload.get("proxy") or "").strip()
        if serial:
            cmd.extend(["--serial", serial])
        if url_proxy:
            cmd.extend(["--proxy", url_proxy])
        return "Stealth checker", cmd, timeout, "/captures/" + out_root.name
    if action == "proof-all":
        out_root = capture_dir() / f"stealth-all-{int(time.time())}"
        out_root.mkdir(parents=True, exist_ok=True)
        cmd = package_command("ui-stealth-check-all", "--output-root", str(out_root))
        url_proxy = str(payload.get("proxy") or "").strip()
        if url_proxy:
            cmd.extend(["--proxy", url_proxy])
        return "Stealth checker all", cmd, timeout, "/captures/" + out_root.name
    if action == "start-workers":
        count = int(payload.get("count") or 0)
        if count < 1 or count > 50:
            raise ValueError("Worker count must be between 1 and 50.")
        return f"Apply {count} Damru worker(s)", package_command("ui-worker", "start", "--count", str(count)), timeout, artifact
    if action == "resume-workers":
        count = int(payload.get("count") or 0)
        cmd = package_command("ui-worker", "resume-all")
        if 1 <= count <= 50:
            cmd.extend(["--count", str(count)])
        return "Start stopped Damru workers", cmd, timeout, artifact
    if action == "add-worker":
        return "Add one Damru worker", package_command("ui-worker", "add"), timeout, artifact
    if action == "add-workers":
        count = int(payload.get("count") or 0)
        if count < 1 or count > 50:
            raise ValueError("Workers to add must be between 1 and 50.")
        label = "worker" if count == 1 else "workers"
        return f"Add {count} Damru {label}", package_command("ui-worker", "add", "--count", str(count)), timeout, artifact
    if action == "resume-worker":
        index = max(0, int(payload.get("index") or 0))
        return f"Start Damru worker {index}", package_command("ui-worker", "resume", "--index", str(index)), timeout, artifact
    if action == "stop-worker":
        index = max(0, int(payload.get("index") or 0))
        return f"Stop Damru worker {index}", package_command("ui-worker", "pause", "--index", str(index)), timeout, artifact
    if action == "delete-worker":
        index = max(0, int(payload.get("index") or 0))
        return f"Delete Damru worker {index}", package_command("ui-worker", "delete", "--index", str(index)), timeout, artifact
    if action == "restart-worker":
        index = max(0, int(payload.get("index") or 0))
        return f"Restart Damru worker {index}", package_command("ui-worker", "restart", "--index", str(index)), timeout, artifact
    if action == "stop-workers":
        return "Stop all Damru workers", package_command("ui-worker", "stop-all"), timeout, artifact
    if action == "delete-workers":
        return "Delete all Damru workers", package_command("ui-worker", "delete-all"), timeout, artifact
    raise KeyError(f"Unsupported action: {action}")


class Handler(BaseHTTPRequestHandler):
    server_version = "DamruUI/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_bytes(self, body: bytes, mime: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/admin":
            self.serve_static("/admin.html")
            return
        if path == "/api/admin/status":
            self.send_json({"authenticated": admin_authenticated(self), "configured": bool(admin_password())})
            return
        if path == "/api/admin/users":
            if not admin_authenticated(self):
                self.send_json({"error": "admin authentication required"}, 401)
                return
            self.send_json({"users": subscription_rows()})
            return
        if path == "/api/auth/status":
            username = authenticated_username(self)
            self.send_json({"authenticated": bool(username), "username": username})
            return
        if path == "/api/health":
            if not user_authenticated(self):
                self.send_json({"error": "user authentication required"}, 401)
                return
            self.send_json(quick_health())
            return
        if path == "/api/workers":
            if not user_authenticated(self):
                self.send_json({"error": "user authentication required"}, 401)
                return
            workers = docker_workers()
            self.send_json({"workers": workers, "adb_devices": adb_devices(workers)})
            return
        if path == "/api/jobs":
            self.send_json({"jobs": STATE.list_jobs()})
            return
        if path.startswith("/api/jobs/"):
            job = STATE.get_job(path.rsplit("/", 1)[-1])
            self.send_json(job or {"error": "job not found"}, 200 if job else 404)
            return
        if path == "/api/config":
            self.send_json({"config": config_snapshot(), "backups": config_backups()})
            return
        if path == "/api/captures":
            self.send_json({"captures": captures()})
            return
        if path == "/api/viewer/frame":
            qs = parse_qs(parsed.query)
            serial = qs.get("serial", [""])[0].strip()
            if not serial:
                self.send_json({"error": "serial is required"}, 400)
                return
            try:
                ensure_viewer_adb(serial)
                frame = cli._run_adb_bytes(serial, "exec-out", "screencap", "-p", timeout=8)
                if frame.returncode != 0 or not frame.stdout:
                    err = frame.stderr.decode("utf-8", errors="replace") if isinstance(frame.stderr, bytes) else str(frame.stderr or "")
                    self.send_json({"error": redact(err or "ADB screencap failed")}, 502)
                    return
                self.send_bytes(frame.stdout, "image/png")
            except Exception as exc:
                self.send_json({"error": redact(str(exc))}, 500)
            return
        if path == "/api/viewer/size":
            qs = parse_qs(parsed.query)
            serial = qs.get("serial", [""])[0].strip()
            if not serial:
                self.send_json({"error": "serial is required"}, 400)
                return
            try:
                ensure_viewer_adb(serial)
                proc = cli._run_adb_text(serial, "shell", "wm", "size", timeout=8)
                matches = re.findall(r"(\d+)x(\d+)", proc.stdout or "")
                width, height = (matches[-1] if matches else (0, 0))
                self.send_json({"width": int(width), "height": int(height), "raw": redact(proc.stdout or proc.stderr or "")})
            except Exception as exc:
                self.send_json({"error": redact(str(exc))}, 500)
            return
        if path == "/api/probe":
            qs = parse_qs(parsed.query)
            url = qs.get("url", [""])[0].strip()
            if not url:
                self.send_json(quick_health())
            else:
                self.send_json({"url": url, "ok": False, "reason": "Use the Work page Open URL action for browser navigation checks"})
            return
        if path.startswith("/api/") and not user_authenticated(self):
            self.send_json({"error": "user authentication required"}, 401)
            return
        self.serve_static(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/captures/clear":
            try:
                self.send_json({"ok": True, **clear_captures()})
            except Exception as exc:
                STATE.add_failed_job("UI action failed", "ui-error", str(exc))
                self.send_json({"error": redact(str(exc))}, 400)
            return
        if path == "/api/jobs/clear":
            try:
                removed = STATE.clear_finished_jobs()
                self.send_json({"ok": True, "removed": removed, "jobs": STATE.list_jobs()})
            except Exception as exc:
                STATE.add_failed_job("UI action failed", "ui-error", str(exc))
                self.send_json({"error": redact(str(exc))}, 400)
            return
        try:
            payload = self.read_json()
            if path == "/api/auth/login":
                username = str(payload.get("username") or "").strip()
                password = str(payload.get("password") or "")
                row = user_login(username, password)
                if not row:
                    self.send_json({"error": "Invalid username/password or inactive/expired subscription."}, 401)
                    return
                token = create_user_session(username)
                _USER_SESSION_USERS[token] = username
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", f"infinite_user={token}; HttpOnly; SameSite=Strict; Max-Age={USER_SESSION_TTL}; Path=/")
                body = json.dumps({"ok": True, "username": username}).encode("utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/api/auth/logout":
                token = user_session_token(self)
                with _USER_SESSION_LOCK:
                    _USER_SESSIONS.pop(token, None)
                    _USER_SESSION_USERS.pop(token, None)
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", "infinite_user=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/")
                body = b'{"ok":true}'
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/api/admin/login":
                password = str(payload.get("password") or "")
                configured = admin_password()
                if not configured:
                    self.send_json({"error": "Set INFINITE_ADMIN_PASSWORD before using the admin panel."}, 503)
                    return
                if not hmac.compare_digest(password, configured):
                    self.send_json({"error": "Invalid admin password."}, 401)
                    return
                token = create_admin_session()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", f"infinite_admin={token}; HttpOnly; SameSite=Strict; Max-Age={ADMIN_SESSION_TTL}; Path=/")
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/api/admin/logout":
                token = parse_cookie(self.headers.get("Cookie", "")).get("infinite_admin", "")
                with _ADMIN_SESSION_LOCK:
                    _ADMIN_SESSIONS.pop(token, None)
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", "infinite_admin=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/")
                body = b'{"ok":true}'
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path in {"/api/admin/users", "/api/admin/users/delete"} and not admin_authenticated(self):
                self.send_json({"error": "admin authentication required"}, 401)
                return
            if path == "/api/admin/users":
                self.send_json({"ok": True, "user": upsert_subscription(payload)})
                return
            if path == "/api/admin/users/delete":
                username = str(payload.get("username") or "").strip()
                if not username:
                    raise ValueError("username is required")
                delete_subscription(username)
                self.send_json({"ok": True})
                return
            if path.startswith("/api/") and not user_authenticated(self):
                self.send_json({"error": "user authentication required"}, 401)
                return
            if path == "/api/jobs/run":
                action = str(payload.get("action") or "")
                name, command, timeout, artifact = build_command(action, payload)
                job = STATE.add_job(name, action, command, timeout, artifact=artifact)
                self.send_json({"job": job.to_dict(include_log=False)}, 202)
                return
            if path == "/api/config":
                target = cli._config_path()
                backup = target.with_suffix(target.suffix + f".ui-backup-{time.strftime('%Y%m%d-%H%M%S')}")
                if target.exists():
                    shutil.copy2(target, backup)
                updated = safe_write_config(payload.get("updates") or {})
                self.send_json({"ok": True, "path": str(updated), "backup": str(backup)})
                return
            if path == "/api/config/restore":
                restored = restore_config_backup(str(payload.get("name") or "").strip() or None)
                self.send_json({"ok": True, "restored": str(restored), "config": config_snapshot(), "backups": config_backups()})
                return
            if path == "/api/viewer/tap":
                serial = str(payload.get("serial") or "").strip()
                x = int(float(payload.get("x") or 0))
                y = int(float(payload.get("y") or 0))
                if not serial or x < 0 or y < 0:
                    raise ValueError("serial, x, and y are required")
                ensure_viewer_adb(serial)
                proc = cli._run_adb_text(serial, "shell", "input", "tap", str(x), str(y), timeout=8)
                self.send_json({"ok": proc.returncode == 0, "stderr": redact(proc.stderr or "")}, 200 if proc.returncode == 0 else 502)
                return
            if path == "/api/viewer/swipe":
                serial = str(payload.get("serial") or "").strip()
                x1 = int(float(payload.get("x1") or 0))
                y1 = int(float(payload.get("y1") or 0))
                x2 = int(float(payload.get("x2") or 0))
                y2 = int(float(payload.get("y2") or 0))
                duration = max(80, min(int(float(payload.get("duration") or 220)), 1200))
                if not serial or min(x1, y1, x2, y2) < 0:
                    raise ValueError("serial and swipe coordinates are required")
                ensure_viewer_adb(serial)
                proc = cli._run_adb_text(serial, "shell", "input", "swipe", str(x1), str(y1), str(x2), str(y2), str(duration), timeout=10)
                self.send_json({"ok": proc.returncode == 0, "stderr": redact(proc.stderr or "")}, 200 if proc.returncode == 0 else 502)
                return
            if path == "/api/viewer/text":
                serial = str(payload.get("serial") or "").strip()
                text = str(payload.get("text") or "")
                encoded = android_input_text(text)
                if not serial or not encoded:
                    raise ValueError("serial and text are required")
                ensure_viewer_adb(serial)
                proc = cli._run_adb_text(serial, "shell", "input", "text", encoded, timeout=12)
                self.send_json({"ok": proc.returncode == 0, "stderr": redact(proc.stderr or "")}, 200 if proc.returncode == 0 else 502)
                return
            if path == "/api/viewer/key":
                serial = str(payload.get("serial") or "").strip()
                key = str(payload.get("key") or "").strip()
                allowed = {
                    "HOME": "3",
                    "BACK": "4",
                    "DPAD_UP": "19",
                    "DPAD_DOWN": "20",
                    "DPAD_LEFT": "21",
                    "DPAD_RIGHT": "22",
                    "TAB": "61",
                    "ENTER": "66",
                    "DEL": "67",
                    "APP_SWITCH": "187",
                    "SPACE": "62",
                }
                if not serial or key not in allowed:
                    raise ValueError("unsupported viewer key")
                ensure_viewer_adb(serial)
                proc = cli._run_adb_text(serial, "shell", "input", "keyevent", allowed[key], timeout=8)
                self.send_json({"ok": proc.returncode == 0, "stderr": redact(proc.stderr or "")}, 200 if proc.returncode == 0 else 502)
                return
        except PermissionError as exc:
            STATE.add_failed_job("UI action rejected", "ui-error", str(exc))
            self.send_json({"error": str(exc)}, 403)
            return
        except Exception as exc:
            STATE.add_failed_job("UI action failed", "ui-error", str(exc))
            self.send_json({"error": redact(str(exc))}, 400)
            return
        self.send_json({"error": "not found"}, 404)

    def serve_static(self, path: str) -> None:
        if path.startswith("/captures/"):
            root = capture_dir().resolve()
            target = (root / path.removeprefix("/captures/")).resolve()
            if root not in target.parents and target != root:
                self.send_error(HTTPStatus.FORBIDDEN)
                return
        else:
            root = static_dir().resolve()
            rel = "index.html" if path in {"/", ""} else path.lstrip("/")
            if rel == "favicon.ico":
                rel = "index.html"
            target = (root / rel).resolve()
            if root not in target.parents and target != root:
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            if not target.exists() and "." not in Path(path).name:
                target = root / "index.html"
        if not target.exists() or not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        mime = "text/plain"
        if target.suffix == ".html":
            mime = "text/html; charset=utf-8"
        elif target.suffix == ".css":
            mime = "text/css; charset=utf-8"
        elif target.suffix == ".js":
            mime = "application/javascript; charset=utf-8"
        elif target.suffix == ".png":
            mime = "image/png"
        elif target.suffix == ".mp4":
            mime = "video/mp4"
        elif target.suffix == ".json":
            mime = "application/json; charset=utf-8"
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Cache-Control", "no-store" if target.suffix in {".html", ".js", ".css"} else "private, max-age=60")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_ui(host: str = "127.0.0.1", port: int = DEFAULT_PORT, open_browser: bool = True) -> int:
    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"Damru UI running at {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Damru UI.")
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m damru ui", description="Run the local Damru web UI")
    parser.add_argument("--host", default="127.0.0.1", help="host to bind the server to")
    parser.add_argument("--port", type=int, default=int(os.environ.get("DAMRU_UI_PORT", DEFAULT_PORT)))
    parser.add_argument("--no-open", action="store_true", help="do not open a browser automatically")
    args = parser.parse_args(argv)
    return run_ui(host=args.host, port=args.port, open_browser=not args.no_open)


# === Infinite subscription/admin extension ===
# User-facing/admin functionality only. Existing runtime internals remain unchanged.
import os as _infinite_os
import sqlite3 as _infinite_sqlite3
import secrets as _infinite_secrets
import hashlib as _infinite_hashlib
import time as _infinite_time
from datetime import datetime as _InfiniteDatetime, timezone as _InfiniteTimezone, timedelta as _InfiniteTimedelta

_INFINITE_DB = _infinite_os.environ.get(
    "INFINITE_SUBSCRIPTIONS_DB",
    _infinite_os.path.join(_infinite_os.path.dirname(__file__), "infinite_subscriptions.db")
)
_INFINITE_ADMIN_PASSWORD_HASH = _infinite_os.environ.get("INFINITE_ADMIN_PASSWORD_HASH", "")
_INFINITE_ADMIN_PASSWORD = _infinite_os.environ.get("INFINITE_ADMIN_PASSWORD", "")

def _infinite_hash_password(password, salt=None):
    salt = salt or _infinite_secrets.token_hex(16)
    digest = _infinite_hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000).hex()
    return salt + "$" + digest

def _infinite_verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
        test = _infinite_hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000).hex()
        return _infinite_secrets.compare_digest(test, digest)
    except Exception:
        return False

def _infinite_db():
    c = _infinite_sqlite3.connect(_INFINITE_DB)
    c.row_factory = _infinite_sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        plan TEXT NOT NULL DEFAULT 'Custom',
        status TEXT NOT NULL DEFAULT 'Active',
        start_date TEXT NOT NULL,
        expiry_date TEXT NOT NULL,
        notes TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS admin_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        username TEXT,
        details TEXT,
        created_at TEXT NOT NULL
    )""")
    c.commit()
    return c

def _infinite_now():
    return _InfiniteDatetime.now(_InfiniteTimezone.utc).isoformat()

def _infinite_log(db, action, username="", details=""):
    db.execute("INSERT INTO admin_log(action,username,details,created_at) VALUES(?,?,?,?)",
               (action, username, details, _infinite_now()))
    db.commit()

def _infinite_days_left(expiry):
    try:
        d=_InfiniteDatetime.fromisoformat(expiry.replace("Z","+00:00"))
        return max(0, (d-_InfiniteDatetime.now(_InfiniteTimezone.utc)).days)
    except Exception:
        return 0

# Flask integration, only if the host module exposes Flask's app.
def _infinite_install_routes(app):
    try:
        from flask import request, jsonify, session, send_from_directory
        app.secret_key = app.secret_key or _infinite_os.environ.get("INFINITE_SESSION_SECRET", _infinite_secrets.token_hex(32))
    except Exception:
        return

    def admin_ok():
        return bool(session.get("infinite_admin"))

    @app.route("/admin", methods=["GET"])
    def infinite_admin_page():
        return send_from_directory(str(static), "admin.html")

    @app.route("/login", methods=["GET"])
    def infinite_login_page():
        return send_from_directory(str(static), "login.html")

    @app.route("/api/infinite/admin/login", methods=["POST"])
    def infinite_admin_login():
        data=request.get_json(silent=True) or {}
        pw=str(data.get("password",""))
        ok=False
        if _INFINITE_ADMIN_PASSWORD_HASH:
            ok=_infinite_verify_password(pw,_INFINITE_ADMIN_PASSWORD_HASH)
        elif _INFINITE_ADMIN_PASSWORD:
            ok=_infinite_secrets.compare_digest(pw,_INFINITE_ADMIN_PASSWORD)
        if not ok:
            return jsonify({"ok":False,"error":"Invalid admin password"}),401
        session["infinite_admin"]=True
        return jsonify({"ok":True})

    @app.route("/api/infinite/admin/logout", methods=["POST"])
    def infinite_admin_logout():
        session.pop("infinite_admin",None)
        return jsonify({"ok":True})

    @app.route("/api/infinite/admin/stats", methods=["GET"])
    def infinite_admin_stats():
        if not admin_ok(): return jsonify({"error":"Unauthorized"}),401
        db=_infinite_db()
        rows=db.execute("SELECT status,expiry_date FROM users").fetchall()
        now=_InfiniteDatetime.now(_InfiniteTimezone.utc)
        active=expired=suspended=0
        for r in rows:
            st=r["status"].lower()
            try: exp=_InfiniteDatetime.fromisoformat(r["expiry_date"].replace("Z","+00:00"))
            except: exp=now
            if st=="active" and exp>=now: active+=1
            elif st=="suspended": suspended+=1
            else: expired+=1
        return jsonify({"total":len(rows),"active":active,"expired":expired,"suspended":suspended})

    @app.route("/api/infinite/admin/users", methods=["GET"])
    def infinite_users():
        if not admin_ok(): return jsonify({"error":"Unauthorized"}),401
        q=request.args.get("q","").strip().lower()
        db=_infinite_db()
        if q:
            rows=db.execute("SELECT * FROM users WHERE lower(username) LIKE ? ORDER BY id DESC",("%"+q+"%",)).fetchall()
        else:
            rows=db.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
        return jsonify([dict(r, days_left=_infinite_days_left(r["expiry_date"])) for r in rows])

    @app.route("/api/infinite/admin/users", methods=["POST"])
    def infinite_create_user():
        if not admin_ok(): return jsonify({"error":"Unauthorized"}),401
        data=request.get_json(silent=True) or {}
        username=str(data.get("username","")).strip()
        password=str(data.get("password",""))
        plan=str(data.get("plan","Custom"))
        status=str(data.get("status","Active"))
        start=str(data.get("start_date","")).strip()
        expiry=str(data.get("expiry_date","")).strip()
        notes=str(data.get("notes",""))
        if len(username)<3 or len(password)<8 or not start or not expiry:
            return jsonify({"error":"Username, password (8+ chars), start and expiry are required"}),400
        db=_infinite_db()
        try:
            db.execute("INSERT INTO users(username,password_hash,plan,status,start_date,expiry_date,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (username,_infinite_hash_password(password),plan,status,start,expiry,notes,_infinite_now(),_infinite_now()))
            db.commit(); _infinite_log(db,"create_user",username,"Created subscription")
            return jsonify({"ok":True})
        except _infinite_sqlite3.IntegrityError:
            return jsonify({"error":"Username already exists"}),409

    @app.route("/api/infinite/admin/users/<int:uid>", methods=["PUT"])
    def infinite_update_user(uid):
        if not admin_ok(): return jsonify({"error":"Unauthorized"}),401
        data=request.get_json(silent=True) or {}
        db=_infinite_db()
        row=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
        if not row: return jsonify({"error":"User not found"}),404
        fields=[]; vals=[]
        for k in ("plan","status","start_date","expiry_date","notes"):
            if k in data: fields.append(k+"=?"); vals.append(str(data[k]))
        if data.get("password"):
            fields.append("password_hash=?"); vals.append(_infinite_hash_password(str(data["password"])))
        if not fields: return jsonify({"ok":True})
        fields.append("updated_at=?"); vals.append(_infinite_now()); vals.append(uid)
        db.execute("UPDATE users SET "+",".join(fields)+" WHERE id=?",vals); db.commit()
        _infinite_log(db,"update_user",row["username"],"Updated account")
        return jsonify({"ok":True})

    @app.route("/api/infinite/admin/users/<int:uid>", methods=["DELETE"])
    def infinite_delete_user(uid):
        if not admin_ok(): return jsonify({"error":"Unauthorized"}),401
        db=_infinite_db(); row=db.execute("SELECT username FROM users WHERE id=?",(uid,)).fetchone()
        if not row: return jsonify({"error":"User not found"}),404
        db.execute("DELETE FROM users WHERE id=?",(uid,)); db.commit()
        _infinite_log(db,"delete_user",row["username"],"Deleted account")
        return jsonify({"ok":True})

    @app.route("/api/infinite/admin/users/<int:uid>/extend", methods=["POST"])
    def infinite_extend(uid):
        if not admin_ok(): return jsonify({"error":"Unauthorized"}),401
        days=int((request.get_json(silent=True) or {}).get("days",30))
        db=_infinite_db(); row=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
        if not row: return jsonify({"error":"User not found"}),404
        try: base=_InfiniteDatetime.fromisoformat(row["expiry_date"].replace("Z","+00:00"))
        except: base=_InfiniteDatetime.now(_InfiniteTimezone.utc)
        if base < _InfiniteDatetime.now(_InfiniteTimezone.utc): base=_InfiniteDatetime.now(_InfiniteTimezone.utc)
        expiry=(base+_InfiniteTimedelta(days=days)).isoformat()
        db.execute("UPDATE users SET expiry_date=?,status='Active',updated_at=? WHERE id=?",(expiry,_infinite_now(),uid)); db.commit()
        _infinite_log(db,"extend_user",row["username"],f"Extended {days} days")
        return jsonify({"ok":True,"expiry_date":expiry})

    @app.route("/api/infinite/admin/logs", methods=["GET"])
    def infinite_logs():
        if not admin_ok(): return jsonify({"error":"Unauthorized"}),401
        db=_infinite_db()
        return jsonify([dict(r) for r in db.execute("SELECT * FROM admin_log ORDER BY id DESC LIMIT 200").fetchall()])

    @app.route("/api/infinite/login", methods=["POST"])
    def infinite_user_login():
        data=request.get_json(silent=True) or {}
        username=str(data.get("username","")).strip()
        password=str(data.get("password",""))
        db=_infinite_db(); row=db.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
        if not row or not _infinite_verify_password(password,row["password_hash"]):
            return jsonify({"ok":False,"error":"Invalid username or password"}),401
        now=_InfiniteDatetime.now(_InfiniteTimezone.utc)
        try: exp=_InfiniteDatetime.fromisoformat(row["expiry_date"].replace("Z","+00:00"))
        except: exp=now
        if row["status"].lower()!="active" or exp<now:
            return jsonify({"ok":False,"error":"Subscription is not active"}),403
        session["infinite_user_id"]=row["id"]; session["infinite_username"]=row["username"]
        return jsonify({"ok":True,"username":row["username"],"plan":row["plan"],"expiry_date":row["expiry_date"],"days_left":_infinite_days_left(row["expiry_date"])})

    @app.route("/api/infinite/me", methods=["GET"])
    def infinite_me():
        uid=session.get("infinite_user_id")
        if not uid: return jsonify({"ok":False}),401
        db=_infinite_db(); row=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
        if not row: session.pop("infinite_user_id",None); return jsonify({"ok":False}),401
        now=_InfiniteDatetime.now(_InfiniteTimezone.utc)
        try: exp=_InfiniteDatetime.fromisoformat(row["expiry_date"].replace("Z","+00:00"))
        except: exp=now
        if row["status"].lower()!="active" or exp<now:
            session.pop("infinite_user_id",None); return jsonify({"ok":False,"error":"Subscription is not active"}),403
        return jsonify({"ok":True,"username":row["username"],"plan":row["plan"],"status":row["status"],"start_date":row["start_date"],"expiry_date":row["expiry_date"],"days_left":_infinite_days_left(row["expiry_date"])})

    @app.route("/api/infinite/logout", methods=["POST"])
    def infinite_logout():
        session.pop("infinite_user_id",None); session.pop("infinite_username",None)
        return jsonify({"ok":True})

# === End Infinite extension ===

try:
    _infinite_install_routes(app)
except Exception:
    pass
