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


def check_container(name: str):
    """Return an actionable error message if `name` is not an Aegis lab
    container name, otherwise None."""
    if not isinstance(name, str) or not _NAME_RE.match(name) or not name.startswith(LAB_PREFIX):
        return (
            f"'{name}' is not an Aegis lab container. Names must start with "
            f"'{LAB_PREFIX}'. Call list_containers to see the valid names."
        )
    return None