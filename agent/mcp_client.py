import os
import sys
from pathlib import Path

from langchain.mcp import MCPAdapter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVERS_DIR = PROJECT_ROOT / "mcp"

PASS_THROUGH = ("PROMETHEUS_URL", "DOCKER_HOST")


def server_env() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key.startswith("AEGIS_") or key in PASS_THROUGH
    }


def stdio_server(script: str) -> dict:
    return {
        "transport": "stdio",
        "command": sys.executable,
        "args": [str(SERVERS_DIR / script)],
        "cwd": str(PROJECT_ROOT),
        "env": server_env(),
    }


def create_mcp_adapter() -> MCPAdapter:
    """Investigation servers only (read-only). Never add remediation here."""
    return MCPAdapter(
        {
            "prometheus": stdio_server("prometheus_server.py"),
            "logs": stdio_server("logs_server.py"),
            "operations": stdio_server("operations_server.py"),
        }
    )


def create_remediation_client() -> MCPAdapter:
    """For the future execute node only, after human approval.
    The LLM must never be given these tools.
    """
    return MCPAdapter(
        {
            "remediation": stdio_server("remediation_server.py")
        }
    )