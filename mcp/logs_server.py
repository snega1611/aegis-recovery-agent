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
    or None if the log file does not exist."""

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


# NOTE: with FastMCP, `description=` REPLACES the docstring. Guidance for the
# model must be in `description=`; text added to a docstring is never seen.

@mcp.tool(
    description=(
        "Search the application's own log file for a short literal term (an "
        "endpoint, error text or status code). Do not search for the word "
        "ERROR: use the error search. Only shows what the application wrote "
        "to its log file."
    )
)
def search_logs(query: str) -> dict:
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
        "Find ERROR/CRITICAL lines in the application's own log file. Only "
        "shows what the application logged: a crash before logging starts is "
        "not visible here, so read the container's logs instead. Do not also "
        "search the general log for ERROR."
    )
)
def search_errors() -> dict:
    return build_result(
        "application_error_logs",
        scan(lambda line: ERROR_RE.search(line) is not None),
        query="ERROR",
    )


@mcp.tool(
    description=(
        "Find requests that took 5 seconds or more in the application log. "
        "Use only for latency, timeout or slow-request incidents, not for "
        "outages or crashes."
    )
)
def search_slow_requests() -> dict:
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