"""Docker helpers shared by the operations and remediation servers.

No container names are hard-coded anywhere. Valid names come from Docker at
call time, and the model may refer to a container by its name or by its
Docker Compose service name (which is what an incident usually says).
"""

import os
import subprocess

# Which containers Aegis may look at. Default: every Docker Compose container.
# Narrow it, for example:
#   AEGIS_CONTAINER_FILTER="label=com.docker.compose.project=myproject"
CONTAINER_FILTER = os.getenv("AEGIS_CONTAINER_FILTER", "label=com.docker.compose.project")

MAX_OUTPUT_CHARS = 50_000


def run_command(command: list[str], timeout: int = 10, merge_stderr: bool = False):
    """Execute one fixed local command (never a shell string).

    Returns (returncode, stdout, stderr). Output is size-capped.
    """

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )

    except subprocess.TimeoutExpired:
        return 124, "", "Command timed out."

    except Exception as exc:
        return 1, "", str(exc)

    return (
        result.returncode,
        (result.stdout or "")[:MAX_OUTPUT_CHARS],
        (result.stderr or "")[:MAX_OUTPUT_CHARS],
    )


def list_lab_containers():
    """Return (containers, error). Each container is a dict with
    name, image, state, status and compose service."""

    code, stdout, stderr = run_command(
        [
            "docker", "ps", "-a", "--filter", CONTAINER_FILTER, "--format",
            '{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}|{{.Label "com.docker.compose.service"}}',
        ]
    )

    if code != 0:
        return None, stderr.strip() or "Docker command failed."

    containers = []

    for line in stdout.splitlines():
        parts = line.split("|", 4)

        if len(parts) != 5:
            continue

        containers.append(
            {
                "name": parts[0],
                "image": parts[1],
                "state": parts[2],
                "status": parts[3],
                "service": parts[4],
            }
        )

    return containers, None


def describe_containers(containers: list[dict]) -> str:
    return ", ".join(
        f"{c['name']} (service {c['service'] or '-'}, {c['state']})" for c in containers
    )


def resolve_container(name: str):
    """Return (container_name, error).

    Accepts the exact container name, else the compose service name, else a
    unique partial match. The returned name always comes from Docker itself,
    so nothing the model typed is ever passed to a command.
    """

    containers, error = list_lab_containers()

    if error:
        return None, error

    if not containers:
        return None, f"No containers match the filter '{CONTAINER_FILTER}'."

    wanted = (name or "").strip().lower()

    exact = [c for c in containers if c["name"].lower() == wanted]
    by_service = [c for c in containers if c["service"].lower() == wanted]
    partial = [c for c in containers if wanted and wanted in c["name"].lower()]

    for group in (exact, by_service, partial):
        if len(group) == 1:
            return group[0]["name"], None

        if len(group) > 1:
            return None, (
                f"'{name}' matches several containers: {describe_containers(group)}. "
                "Use the exact container name."
            )

    return None, (
        f"Unknown container '{name}'. "
        f"Known containers: {describe_containers(containers)}."
    )