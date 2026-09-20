import os
import re
from collections import deque

from fastmcp import FastMCP

from common import MAX_LOG_LINES, err, ok, sanitize_line


mcp = FastMCP("Logs")

# Absolute path (or an env var) so it does not depend on the working directory.
# In Docker, mount the log directory as a volume.
LOG_FILE = os.getenv("AEGIS_LOG_FILE", "logs/aegis.log")

SLOW_SECONDS = 5.0

# Adjust to your log format. Case-sensitive on purpose: a plain
# "error" substring also matches "no error" or "/error-page".
ERROR_RE = re.compile(r"\b(ERROR|CRITICAL)\b")
DURATION_RE = re.compile(r"duration=([0-9]*\.?[0-9]+)(ms|s)\b")


def scan(predicate):
    """Stream the log once. Returns (total_matches, newest_matching_lines)
    or None if the log file does not exist.

    The total is the TRUE number of matching lines. Previously match_count was
    capped at 20, so 5000 errors were reported as "20".
    """

    total = 0
    recent = deque(maxlen=MAX_LOG_LINES)

    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as file:
            for line in file:
                if predicate(line):
                    total += 1
                    recent.append(sanitize_line(line))

    except FileNotFoundError:
        return None

    return total, list(recent)


def build_result(evidence_type: str, scanned, **extra) -> dict:
    if scanned is None:
        # A missing log file must not look like "no matches".
        return err(evidence_type, f"Log file not found: {LOG_FILE}")

    total, matches = scanned

    return ok(
        evidence_type,
        match_count=total,
        returned_count=len(matches),   # newest lines only, oldest first
        matches=matches,
        **extra,
    )


def duration_seconds(line: str):
    match = DURATION_RE.search(line)

    if not match:
        return None

    value = float(match.group(1))

    return value / 1000 if match.group(2) == "ms" else value


@mcp.tool(
    description=(
        "Search Aegis application logs using a short literal text query. "
        "Use specific terms from the incident, such as an endpoint path, "
        "an error message, or a status code. "
        "Do not send a sentence, hypothesis, or explanation. "
        "Returns the total number of matching entries and the newest ones."
    )
)
def search_logs(query: str) -> dict:
    """Search application logs for a specific literal term."""

    query = query.strip()

    if not query:
        return err("application_logs", "Log query cannot be empty.")

    if len(query) > 100:
        return err(
            "application_logs",
            "Log query is too long. Use a short literal term, not a sentence.",
        )

    needle = query.lower()

    return build_result(
        "application_logs",
        scan(lambda line: needle in line.lower()),
        query=query,
    )


@mcp.tool(
    description=(
        "Search Aegis logs specifically for application errors. "
        "Use this when investigating HTTP failures or application failures. "
        "This is read-only evidence."
    )
)
def search_errors() -> dict:
    """Return recent application error log entries."""

    return build_result(
        "application_error_logs",
        scan(lambda line: ERROR_RE.search(line) is not None),
        query="ERROR",
    )


@mcp.tool(
    description=(
        "Search Aegis logs for slow HTTP requests (5 seconds or longer). "
        "Use this when investigating latency or unusually long request durations. "
        "This is read-only evidence."
    )
)
def search_slow_requests() -> dict:
    """Return recent log entries for slow requests."""

    def is_slow(line: str) -> bool:
        seconds = duration_seconds(line)
        return seconds is not None and seconds >= SLOW_SECONDS

    return build_result(
        "slow_request_logs",
        scan(is_slow),
        threshold={
            "value": SLOW_SECONDS,
            "unit": "seconds",
            "comparison": "greater_than_or_equal",
        },
    )


if __name__ == "__main__":
    mcp.run()