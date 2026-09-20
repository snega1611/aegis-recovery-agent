import math
import os
from datetime import datetime, timezone

import httpx
from fastmcp import FastMCP

from common import err, ok


mcp = FastMCP("Prometheus")

# Inside Docker, "localhost" is the container itself. In compose use
# PROMETHEUS_URL=http://prometheus:9090
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090")

# Scrape job of the Aegis backend (the "job" in prometheus.yml). Needed because
# generic metrics such as process_resident_memory_bytes exist for EVERY scraped
# process (Prometheus itself, exporters...). Without a filter you get an
# arbitrary process.
BACKEND_JOB = os.getenv("AEGIS_BACKEND_JOB", "aegis-backend")
JOB = f'{{job="{BACKEND_JOB}"}}'


def run_query(query: str):
    """Execute a Prometheus instant query.

    Returns (data, error_message). Exactly one of them is None, so a failed
    query is never confused with "no data".

    Aegis does not expose arbitrary PromQL as a tool; each tool below uses a
    fixed, predefined query.
    """

    try:
        response = httpx.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=5.0,
        )
        response.raise_for_status()
        payload = response.json()

    except Exception as exc:
        return None, f"Prometheus query failed: {exc}"

    if payload.get("status") != "success":
        return None, payload.get("error", "Prometheus returned an error.")

    return payload.get("data", {}), None


def first_sample(data: dict):
    """Return (value, sample_time_iso, series_count) or None."""

    result = data.get("result", [])

    if not result:
        return None

    sample = result[0].get("value")

    if not sample or len(sample) < 2:
        return None

    try:
        value = float(sample[1])
        sample_time = datetime.fromtimestamp(
            float(sample[0]), tz=timezone.utc
        ).isoformat()

    except (TypeError, ValueError):
        return None

    return value, sample_time, len(result)


def instant_metric(
    *,
    evidence_type: str,
    metric: str,
    unit: str,
    time_scope: str,
    query: str,
    **extra,
) -> dict:
    """Run one fixed query and wrap the result in the standard evidence shape."""

    data, error = run_query(query)

    if error:
        return err(evidence_type, error)

    sample = first_sample(data)

    if sample is None:
        return err(
            evidence_type,
            "Prometheus returned no data for this measurement "
            "(metric missing or target not scraped).",
        )

    value, sample_time, series_count = sample

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
        sample_time=sample_time,     # when Prometheus evaluated the sample
        series_count=series_count,   # >1 means the query needs aggregation
        **extra,
    )


@mcp.tool(
    description=(
        "Read the current Aegis backend CPU usage from Prometheus. "
        "Use this to determine whether CPU usage is currently elevated. "
        "This provides current telemetry only and does not explain the cause."
    )
)
def query_cpu() -> dict:
    """Return the current CPU usage percentage of the Aegis backend."""

    return instant_metric(
        evidence_type="cpu_current",
        metric="cpu_usage",
        unit="percent",
        time_scope="current",
        query="aegis_cpu_usage_percent",
        threshold={
            "value": 70.0,
            "unit": "percent",
            "comparison": "greater_than",
        },
    )


@mcp.tool(
    description=(
        "Read the Aegis backend CPU average over the previous five minutes. "
        "Use this to determine whether elevated CPU persisted over time. "
        "This is historical telemetry and does not describe the current instant."
    )
)
def query_cpu_history() -> dict:
    """Return the five-minute average CPU usage percentage."""

    return instant_metric(
        evidence_type="cpu_history",
        metric="cpu_usage",
        unit="percent",
        time_scope="5m_average",
        query="avg_over_time(aegis_cpu_usage_percent[5m])",
    )


@mcp.tool(
    description=(
        "Read the current resident memory used by the Aegis backend process. "
        "Use this when investigating memory pressure or determining whether "
        "the application process is consuming unusually large amounts of memory. "
        "This is read-only telemetry."
    )
)
def query_memory() -> dict:
    """Return current resident memory used by the backend process."""

    return instant_metric(
        evidence_type="memory_current",
        metric="resident_memory",
        unit="bytes",
        time_scope="current",
        query=f"process_resident_memory_bytes{JOB}",
    )


@mcp.tool(
    description=(
        "Read how much the Aegis backend resident memory changed over the "
        "previous 15 minutes (positive means it grew). "
        "Use this to tell a memory leak or sustained growth from a stable level. "
        "This is historical telemetry and does not describe the current instant."
    )
)
def query_memory_history() -> dict:
    """NEW: memory trend. CPU had a history tool; memory had none."""

    return instant_metric(
        evidence_type="memory_history",
        metric="resident_memory_change",
        unit="bytes",
        time_scope="15m_change",
        query=f"delta(process_resident_memory_bytes{JOB}[15m])",
    )


@mcp.tool(
    description=(
        "Check whether Prometheus can currently scrape the Aegis backend "
        "(1 = reachable, 0 = down). Use this to tell a stopped or unreachable "
        "service apart from a service that simply has no data. "
        "This is read-only telemetry."
    )
)
def query_service_up() -> dict:
    """NEW: distinguishes 'service down' from 'no data'."""

    return instant_metric(
        evidence_type="service_up_current",
        metric="target_up",
        unit="boolean",
        time_scope="current",
        query=f"up{JOB}",
    )


@mcp.tool(
    description=(
        "Read the current HTTP request rate for the Aegis backend. "
        "Use this when investigating traffic-related incidents or determining "
        "whether request volume is currently elevated. "
        "This is read-only telemetry."
    )
)
def query_request_rate() -> dict:
    """Return the current total HTTP request rate."""

    # sum(): the counter has one series per label combination. Without it the
    # tool would report an arbitrary single series, not the total.
    return instant_metric(
        evidence_type="request_rate_current",
        metric="request_rate",
        unit="requests_per_second",
        time_scope="current_1m_rate",
        query="sum(rate(aegis_http_requests_total[1m]))",
    )


@mcp.tool(
    description=(
        "Read the current HTTP error rate for the Aegis backend. "
        "Use this when investigating failed requests or determining whether "
        "the incident is associated with HTTP errors. "
        "This is read-only telemetry."
    )
)
def query_error_rate() -> dict:
    """Return the current total HTTP error rate."""

    return instant_metric(
        evidence_type="error_rate_current",
        metric="http_error_rate",
        unit="errors_per_second",
        time_scope="current_1m_rate",
        query="sum(rate(aegis_http_errors_total[1m]))",
    )


@mcp.tool(
    description=(
        "Read the current average HTTP request latency for the Aegis backend. "
        "Use this when investigating slow requests or determining whether "
        "request latency is elevated. "
        "This is read-only telemetry."
    )
)
def query_latency() -> dict:
    """Return the current average HTTP request duration in seconds."""

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