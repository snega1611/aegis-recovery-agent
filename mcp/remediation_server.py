"""Mutating actions. Still blocked.

IMPORTANT
- The investigation graph must NOT load this server. The LLM should never have
  a callable mutating tool.
- Later, only the graph's `execute` node calls these, from code, after a human
  approval bound to the exact action + parameters.
- Grant this server the only write-capable Docker access, through a proxy
  that allows just the endpoints these actions need.
"""

from fastmcp import FastMCP

from docker_utils import resolve_container
from common import err


mcp = FastMCP("Remediation")

BLOCKED_REASON = (
    "Mutating actions are disabled until policy validation "
    "and human approval are implemented."
)


def blocked(action: str, container_name: str) -> dict:
    container_name, problem = resolve_container(container_name)
    if problem:
        return err("docker_container_inspect", problem)

    return {
        "status": "blocked",
        "action": action,
        "container": container_name,
        "reason": BLOCKED_REASON,
    }


@mcp.tool(
    description=(
        "Restart one Aegis lab Docker container. Mutating and reversible. "
        "Currently blocked until the policy and human-approval layer exists."
    )
)
def restart_container(container_name: str) -> dict:
    return blocked("restart_container", container_name)


@mcp.tool(
    description=(
        "Stop one Aegis lab Docker container. High-impact mutating action. "
        "Currently blocked until the policy and human-approval layer exists."
    )
)
def stop_container(container_name: str) -> dict:
    return blocked("stop_container", container_name)


if __name__ == "__main__":
    mcp.run()