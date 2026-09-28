"""Shared helpers for the Aegis MCP servers. Keep this file next to the servers.

Every tool result goes through ok() or err(), so every result has the same
envelope: status, evidence_type, and (for ok) observed_at. Tools must NOT use
"status" / "evidence_type" / "observed_at" for their own fields
(for example, use "container_status", not "status").
"""

import os
import re
from datetime import datetime, timezone

# How much text a tool may hand to a small local model.
MAX_LOG_LINES = int(os.getenv("AEGIS_MAX_LOG_LINES", "10"))
MAX_LINE_CHARS = int(os.getenv("AEGIS_MAX_LINE_CHARS", "200"))

# Only containers whose name starts with this prefix may be touched.
LAB_PREFIX = os.getenv("AEGIS_CONTAINER_PREFIX", "aegis")

_RESERVED = {"status", "evidence_type", "observed_at"}
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# Best-effort redaction: "password=abc", "token: abc", "api_key=abc" ...
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\b(\s*[=:]\s*)(\S+)"
)
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ok(evidence_type: str, **fields) -> dict:
    clash = _RESERVED & fields.keys()
    if clash:
        raise ValueError(f"Reserved result keys used: {sorted(clash)}")
    return {
        "status": "ok",
        "evidence_type": evidence_type,
        "observed_at": now_iso(),
        **fields,
    }


def err(evidence_type: str, message: str, **fields) -> dict:
    return {
        "status": "error",
        "evidence_type": evidence_type,
        "message": message,
        **fields,
    }


def sanitize_line(line: str) -> str:
    """Log lines are untrusted input: strip control characters, redact
    obvious secrets, and cap the length before a model ever sees them."""
    line = _CONTROL_RE.sub("", line.strip())
    line = _SECRET_RE.sub(r"\1\2[REDACTED]", line)
    if len(line) > MAX_LINE_CHARS:
        line = line[:MAX_LINE_CHARS] + "..."
    return line

def parse_ts(value: str):
    """Extract and parse an ISO timestamp from a log line."""
    if not value:
        return None

    match = re.search(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
        value,
    )

    if not match:
        return None

    try:
        return datetime.fromisoformat(
            match.group(0).replace("Z", "+00:00")
        )
    except ValueError:
        return None


def failure_lines(lines: list[str]) -> list[str]:
    """Return log lines that contain common failure indicators."""
    patterns = (
        "error",
        "exception",
        "traceback",
        "failed",
        "failure",
        "fatal",
        "critical",
        "panic",
        "oom",
        "killed",
    )

    return [
        line
        for line in lines
        if any(pattern in line.lower() for pattern in patterns)
    ]