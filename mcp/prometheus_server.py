import math
import os

import httpx
from fastmcp import FastMCP

from common import err, ok, sanitize_line


mcp = FastMCP("Prometheus")

# Inside Docker, "localhost" is the container itself. In compose use
# PROMETHEUS_URL=http://prometheus:9090
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090")

MAX_SERIES = 10
MAX_TARGETS = 20

# The tools below have NO job / service names in them. Anything that depends
# on which service failed (targets, memory) returns one row per job and
# instance, and the agent reads the row that matches the incident.


def get_json(path: str, params: dict | None = None):
    """GET a Prometheus API path. Returns (data, error_message).
    Exactly one of them is None, so a failed request is never confused
    with "no data"."""

    try:
        response = httpx.get(f"{PROMETHEUS_URL}{path}", params=params, timeout=5.0)
        response.raise_for_status()
        payload = response.json()

    except Exception as exc:
        return None, f"Prometheus request failed: {exc}"

    if payload.get("status") != "success":
        return None, payload.get("error", "Prometheus returned an error.")

    return payload.get("data", {}), None


def run_query(query: str):
    """Execute a fixed Prometheus instant query. Aegis never exposes
    arbitrary PromQL as a tool."""
    return get_json("/api/v1/query", {"query": query})


def instant_metric(*, evidence_type, metric, unit, time_scope, query, **extra) -> dict:
    """One fixed query, first series only (the queries aggregate with sum())."""

    data, error = run_query(query)

    if error:
        return err(evidence_type, error)

    result = data.get("result", [])

    try:
        value = float(result[0]["value"][1])
    except (IndexError, KeyError, TypeError, ValueError):
        return err(
            evidence_type,
            "Prometheus returned no data for this measurement "
            "(metric missing or target not scraped).",
        )

    if not math.isfinite(value):
        # e.g. latency = sum/count while there is no traffic -> NaN
        return err(
            evidence_type,
            "The measurement is not a finite number "
            "(for example, no traffic in the window).",
        )

    return ok(
        evidence_type,
        metric=metric,
        value=value,
        unit=unit,
        time_scope=time_scope,
        series_count=len(result),
        **extra,
    )


def series_metric(*, evidence_type, metric, unit, time_scope, query) -> dict:
    """One fixed query, one row per job and instance (largest first)."""

    data, error = run_query(query)

    if error:
        return err(evidence_type, error)

    rows = []

    for item in data.get("result", []):
        try:
            value = float(item["value"][1])
        except (KeyError, TypeError, ValueError, IndexError):
            continue

        if not math.isfinite(value):
            continue

        labels = item.get("metric", {})
        rows.append(
            {
                "job": labels.get("job", ""),
                "instance": labels.get("instance", ""),
                "value": value,
            }
        )

    if not rows:
        return err(
            evidence_type,
            "Prometheus returned no data for this measurement "
            "(metric missing or targets not scraped).",
        )

    rows.sort(key=lambda row: row["value"], reverse=True)

    return ok(
        evidence_type,
        metric=metric,
        unit=unit,
        time_scope=time_scope,
        series_count=len(rows),
        series=rows[:MAX_SERIES],
    )


@mcp.tool(
    description=(
        "Show every Prometheus scrape target: job, instance, health (up/down) "
        "and last scrape error. Use early when a service is reported down or "
        "unreachable: it shows which targets are down and often why the scrape "
        "failed (connection refused, host not found). It does not show what "
        "happened inside the service."
    )
)
def query_targets() -> dict:
    data, error = get_json("/api/v1/targets", {"state": "active"})

    if error:
        return err("scrape_targets", error)

    targets = []

    for target in data.get("activeTargets", []):
        labels = target.get("labels", {})
        targets.append(
            {
                "job": labels.get("job", ""),
                "instance": labels.get("instance", ""),
                "health": target.get("health", "unknown"),
                "last_error": sanitize_line(target.get("lastError") or "") or None,
                "last_scrape": target.get("lastScrape"),
            }
        )

    if not targets:
        return err("scrape_targets", "Prometheus has no active scrape targets.")

    targets.sort(key=lambda t: (t["health"] == "up", t["job"]))   # down first
    down = [t for t in targets if t["health"] != "up"]

    if down:
        finding = f"{len(down)} of {len(targets)} scrape targets are not up: " + "; ".join(
            f"{t['job']} ({t['instance']}): {t['last_error'] or t['health']}"
            for t in down[:5]
        )
    else:
        finding = f"All {len(targets)} scrape targets are up."

    return ok(
        "scrape_targets",
        time_scope="current",
        total_count=len(targets),
        down_count=len(down),
        targets=targets[:MAX_TARGETS],
        finding=finding,
    )


@mcp.tool(
    description=(
        "Current CPU usage percent of the monitored application. Use to check "
        "whether CPU is elevated right now. Shows the value only, not the "
        "cause. Returns an error when the application is down."
    )
)
def query_cpu() -> dict:
    return instant_metric(
        evidence_type="cpu_current",
        metric="cpu_usage",
        unit="percent",
        time_scope="current",
        query="aegis_cpu_usage_percent",
        threshold={"value": 70.0, "unit": "percent", "comparison": "greater_than"},
    )


@mcp.tool(
    description=(
        "CPU usage of the monitored application averaged over the last 5 "
        "minutes. Use to check whether high CPU persisted over time. "
        "Historical, not the current instant."
    )
)
def query_cpu_history() -> dict:
    return instant_metric(
        evidence_type="cpu_history",
        metric="cpu_usage",
        unit="percent",
        time_scope="5m_average",
        query="avg_over_time(aegis_cpu_usage_percent[5m])",
    )


@mcp.tool(
    description=(
        "Current resident memory of every scraped process, one row per job "
        "and instance, in bytes. Use to check memory pressure or after an "
        "out-of-memory kill; read the row for the failing service."
    )
)
def query_memory() -> dict:
    return series_metric(
        evidence_type="memory_current",
        metric="resident_memory",
        unit="bytes",
        time_scope="current",
        query="process_resident_memory_bytes",
    )


@mcp.tool(
    description=(
        "Change in resident memory over the last 15 minutes for every scraped "
        "process, one row per job and instance (positive means growth). Use to "
        "tell a memory leak or sustained growth from a stable level. "
        "Historical, not the current instant."
    )
)
def query_memory_history() -> dict:
    return series_metric(
        evidence_type="memory_history",
        metric="resident_memory_change",
        unit="bytes",
        time_scope="15m_change",
        query="delta(process_resident_memory_bytes[15m])",
    )


@mcp.tool(
    description=(
        "Current HTTP request rate of the monitored application (requests per "
        "second). Use only for traffic-related incidents."
    )
)
def query_request_rate() -> dict:
    # sum(): the counter has one series per label combination.
    return instant_metric(
        evidence_type="request_rate_current",
        metric="request_rate",
        unit="requests_per_second",
        time_scope="current_1m_rate",
        query="sum(rate(aegis_http_requests_total[1m]))",
    )


@mcp.tool(
    description=(
        "Current HTTP error rate of the monitored application (4xx and 5xx "
        "per second). Use for failed-request incidents, or to see whether "
        "errors accompany another problem."
    )
)
def query_error_rate() -> dict:
    return instant_metric(
        evidence_type="error_rate_current",
        metric="http_error_rate",
        unit="errors_per_second",
        time_scope="current_1m_rate",
        query="sum(rate(aegis_http_errors_total[1m]))",
    )


@mcp.tool(
    description=(
        "Current average HTTP request latency of the monitored application, "
        "in seconds. Use only for slowness or latency incidents."
    )
)
def query_latency() -> dict:
    return instant_metric(
        evidence_type="latency_current",
        metric="request_latency",
        unit="seconds",
        time_scope="current_1m_average",
        query=(
            "sum(rate(aegis_http_request_duration_seconds_sum[1m])) "
            "/ "
            "sum(rate(aegis_http_request_duration_seconds_count[1m]))"
        ),
    )


if __name__ == "__main__":
    mcp.run()