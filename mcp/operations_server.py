"""Read-only diagnostics: Docker and Git.

Mutating actions (restart/stop) are NOT in this server any more. They live in
remediation_server.py, which the investigation graph must never load.

Running inside Docker: the docker CLI honours DOCKER_HOST. Point it at a
docker-socket-proxy that only allows read (GET) container endpoints instead of
mounting /var/run/docker.sock. Mount the repo read-only and set
AEGIS_REPO_PATH.
"""

import json
import os
import re
import subprocess

from fastmcp import FastMCP

from common import (
    LAB_PREFIX,
    MAX_LOG_LINES,
    check_container,
    err,
    ok,
    sanitize_line,
)


mcp = FastMCP("Operations")

REPO_PATH = os.path.abspath(os.getenv("AEGIS_REPO_PATH", "."))
MAX_OUTPUT_CHARS = 50_000

# Only a hex hash is accepted. This also blocks argument injection such as
# commit="--output=/some/file", which `git show` would happily obey.
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def run_command(command: list[str], timeout: int = 10, merge_stderr: bool = False):
    """Execute one fixed local diagnostic command (never a shell string).

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


def git(*args: str):
    # -c safe.directory avoids "dubious ownership" errors for a mounted repo.
    return run_command(
        ["git", "-c", f"safe.directory={REPO_PATH}", "-C", REPO_PATH, *args]
    )


def percent(text):
    try:
        return float(str(text).rstrip("%"))
    except ValueError:
        return None


# ----------------------------------------------------------------------
# Docker
# ----------------------------------------------------------------------

@mcp.tool(
    description=(
        "List the Aegis lab Docker containers with name, image and state. "
        "Use this to identify the runtime container associated with an incident "
        "and to get valid container names for other tools. "
        "This is read-only container evidence."
        
    )
)
def list_containers() -> dict:
    """Return the Aegis lab container inventory (not every container on the host).
    Use this first when an incident says a container or service is down: it shows which containers exist and whether they 
            are running, and gives the exact names other container tools need.
            """

    code, stdout, stderr = run_command(
        [
            "docker", "ps", "-a", "--format",
            "{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}",
        ]
    )

    if code != 0:
        return err("docker_containers", stderr.strip() or "Docker command failed.")

    containers = []

    for line in stdout.splitlines():
        parts = line.split("|", 3)

        if len(parts) != 4 or not parts[0].startswith(LAB_PREFIX):
            continue

        containers.append(
            {
                "name": parts[0],
                "image": parts[1],
                "state": parts[2],
                "status": parts[3],
            }
        )

    return ok("docker_containers", count=len(containers), containers=containers)


@mcp.tool(
    description=(
        
        "Inspect one Aegis lab Docker container and return its runtime state: "
        "status, restart count, exit code, OOM-killed flag, health, and "
        "configured CPU/memory limits. "
        "Use this to investigate crashes, restarts or memory-related incidents. "
        "The container name must come from list_containers. This is read-only."
    )
)
def inspect_container(container_name: str) -> dict:
    """Inspect the runtime state of one Docker container.
        Use this first for a container that is stopped, exited, restarting or crashing. 
        It works on stopped containers and shows how the container ended (exit code, OOM kill, error).
            """

    problem = check_container(container_name)
    if problem:
        return err("docker_container_inspect", problem, container=container_name)

    code, stdout, stderr = run_command(
        ["docker", "container", "inspect", container_name]
    )

    if code != 0:
        return err(
            "docker_container_inspect",
            stderr.strip() or "Docker inspect failed.",
            container=container_name,
        )

    try:
        info = json.loads(stdout)[0]

    except (json.JSONDecodeError, IndexError):
        return err(
            "docker_container_inspect",
            "Docker returned an unexpected inspect result.",
            container=container_name,
        )

    state = info.get("State", {})
    host = info.get("HostConfig", {})
    memory_limit = host.get("Memory") or 0
    cpu_limit = (host.get("NanoCpus") or 0) / 1e9

    return ok(
        "docker_container_inspect",
        container=container_name,
        container_status=state.get("Status"),      # not "status": that key is the envelope
        running=state.get("Running"),
        error=state.get("Error") or None,
        image=(info.get("Config") or {}).get("Image"), 
        restarting=state.get("Restarting"),
        # RestartCount is a TOP-LEVEL field of `docker inspect`, not part of
        # State. The old code read it from State and always returned null.
        restart_count=info.get("RestartCount"),
        exit_code=state.get("ExitCode"),
        oom_killed=state.get("OOMKilled"),
        health=(state.get("Health") or {}).get("Status"),
        memory_limit_bytes=memory_limit if memory_limit else "unlimited",
        cpu_limit_cores=cpu_limit if cpu_limit else "unlimited",
        started_at=state.get("StartedAt"),
        finished_at=state.get("FinishedAt"),
        time_scope="current",
    )


@mcp.tool(
    description=(
        "Read current CPU and memory statistics for one Aegis lab Docker "
        "container. CPU percent is relative to one core, so it can exceed 100 "
        "on multi-core containers. Use this to identify whether a particular "
        "container is consuming resources. The container name must come from "
        "list_containers. This is read-only runtime evidence."
    )
)
def get_container_stats(container_name: str) -> dict:
    
    """Return current Docker container resource statistics.
    Only meaningful for a RUNNING container. If it reports running=false, use the container inspect tool instead.
    """

    problem = check_container(container_name)
    if problem:
        return err("docker_container_stats", problem, container=container_name)

    # `docker stats` on a stopped container reports 0% - which would look like
    # a healthy idle container. Check that it is running first.
    code, stdout, stderr = run_command(
        ["docker", "container", "inspect", "--format", "{{.State.Running}}", container_name]
    )

    if code != 0:
        return err(
            "docker_container_stats",
            stderr.strip() or "Docker inspect failed.",
            container=container_name,
        )

    if stdout.strip() != "true":
        return ok(
            "docker_container_stats",
            container=container_name,
            running=False,
            note="Container is not running; resource statistics are not meaningful.",
            time_scope="current",
        )

    code, stdout, stderr = run_command(
        [
            "docker", "stats", container_name, "--no-stream",
            "--format", "{{json .}}",
        ],
        timeout=15,
    )

    if code != 0:
        return err(
            "docker_container_stats",
            stderr.strip() or "Docker stats failed.",
            container=container_name,
        )

    try:
        stats = json.loads(stdout.strip())

    except json.JSONDecodeError:
        return err(
            "docker_container_stats",
            "Docker returned an unexpected stats result.",
            container=container_name,
        )

    return ok(
        "docker_container_stats",
        container=container_name,
        running=True,
        cpu_percent=percent(stats.get("CPUPerc")),
        memory_percent=percent(stats.get("MemPerc")),
        memory_usage=stats.get("MemUsage"),
        pids=stats.get("PIDs"),
        time_scope="current",
    )


@mcp.tool(
    description=(
        "Read the most recent log lines from one Aegis lab Docker container "
        "(stdout and stderr combined, with timestamps). "
        "Use this when application-level logs do not provide enough runtime "
        "evidence. The container name must come from list_containers. "
        "This is read-only container evidence."
    )
)
def get_container_logs(container_name: str) -> dict:
    """Return recent logs from one Docker container.
    Works on stopped containers. Use it when the container state shows a non-zero exit code, 
    an error or restarts: the last lines usually show why the process ended.
    """

    problem = check_container(container_name)
    if problem:
        return err("docker_container_logs", problem, container=container_name)

    # Apps often log to stderr, and `docker logs` replays container stderr on
    # its own stderr. The old code read stdout only and could return nothing.
    code, stdout, stderr = run_command(
        [
            "docker", "logs", "--tail", str(MAX_LOG_LINES),
            "--timestamps", container_name,
        ],
        merge_stderr=True,
    )

    if code != 0:
        return err(
            "docker_container_logs",
            (stdout or stderr).strip() or "Docker logs failed.",
            container=container_name,
        )

    lines = [sanitize_line(line) for line in stdout.splitlines()[-MAX_LOG_LINES:]]

    return ok(
        "docker_container_logs",
        container=container_name,
        line_count=len(lines),
        lines=lines,
        time_scope=f"last_{MAX_LOG_LINES}_lines",
    )


# ----------------------------------------------------------------------
# Git
# ----------------------------------------------------------------------

@mcp.tool(
    description=(
        "Read recent Git commits from the Aegis repository (short hash, date, "
        "author, subject). Use this when investigating whether a recent code "
        "or configuration change may be associated with an incident. "
        "Only changes made BEFORE the incident started can be a cause. "
        "This is read-only evidence."
    )
)
def get_recent_commits(limit: int = 5) -> dict:
    """Use it only when evidence points to a code, configuration, image or deployment change, 
    for example a failure right after startup with an application or import error.
    Return recent Git commits."""

    limit = max(1, min(limit, 20))

    code, stdout, stderr = git(
        "log", f"-{limit}", "--abbrev=12", "--date=iso-strict",
        "--pretty=format:%h|%ad|%an|%s",
    )

    if code != 0:
        return err("git_recent_commits", stderr.strip() or "Git command failed.")

    commits = []

    for line in stdout.splitlines():
        parts = line.split("|", 3)

        if len(parts) != 4:
            continue

        commits.append(
            {
                "commit": parts[0],
                "date": parts[1],
                "author": parts[2],
                "message": sanitize_line(parts[3]),
            }
        )

    return ok("git_recent_commits", count=len(commits), commits=commits)


@mcp.tool(
    description=(
        "Read metadata and the message for one Git commit. The commit must be "
        "a hexadecimal hash taken from get_recent_commits. "
        "Use this when a recent commit is relevant to the incident. "
        "This is read-only evidence."
    )
)
def get_commit(commit: str) -> dict:
    """Return metadata for a specific Git commit.
    Use only after the recent-commits tool shows a commit relevant to the evidence.
    """

    if not COMMIT_RE.match(commit):
        return err(
            "git_commit",
            "Commit must be a 7-40 character hexadecimal hash from get_recent_commits.",
            commit=commit,
        )

    code, stdout, stderr = git(
        "show", "--no-patch", "--date=iso-strict",
        "--format=%H%n%ad%n%an%n%s%n%b", commit, "--",
    )

    if code != 0:
        return err("git_commit", stderr.strip() or "Git commit lookup failed.", commit=commit)

    lines = stdout.splitlines()

    if len(lines) < 4:
        return err("git_commit", "Git returned an unexpected result.", commit=commit)

    body = " ".join(line.strip() for line in lines[4:] if line.strip())

    return ok(
        "git_commit",
        commit=commit,
        full_hash=lines[0],
        date=lines[1],
        author=lines[2],
        subject=sanitize_line(lines[3]),
        body=sanitize_line(body),
    )


@mcp.tool(
    description=(
        "List the files changed by one Git commit with added/removed line "
        "counts. It does NOT show the code itself. The commit must be a "
        "hexadecimal hash from get_recent_commits. "
        "Use this to judge whether a change touched something relevant to the "
        "incident. This is read-only evidence."
    )
)
def get_commit_files(commit: str) -> dict:
    """Renamed from get_file_diff: it only ever returned `git show --stat`.
    Use only after the recent-commits tool shows a commit relevant to the evidence.
    """

    if not COMMIT_RE.match(commit):
        return err(
            "git_commit_files",
            "Commit must be a 7-40 character hexadecimal hash from get_recent_commits.",
            commit=commit,
        )

    code, stdout, stderr = git(
        "show", "--format=", "--stat=120", "--no-color", commit, "--"
    )

    if code != 0:
        return err("git_commit_files", stderr.strip() or "Git lookup failed.", commit=commit)

    summary = [sanitize_line(line) for line in stdout.splitlines()[:25]]

    return ok("git_commit_files", commit=commit, summary=summary)


if __name__ == "__main__":
    mcp.run()