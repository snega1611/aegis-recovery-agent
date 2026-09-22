"""Read-only diagnostics: Docker and Git.

Mutating actions (restart/stop) live in remediation_server.py, which the
investigation graph must never load.

No container names are hard-coded: valid names come from Docker (see
docker_utils.py). In Docker, point the docker CLI at a read-only
docker-socket-proxy through DOCKER_HOST instead of mounting the socket, and
mount the repo read-only (AEGIS_REPO_PATH).

NOTE: with FastMCP, `description=` REPLACES the docstring. Guidance for the
model must be in `description=`; text added to a docstring is never seen.
"""

import json
import os
import re

from fastmcp import FastMCP

from common import MAX_LOG_LINES, err, ok, sanitize_line
from docker_utils import describe_containers, list_lab_containers, resolve_container, run_command


mcp = FastMCP("Operations")

REPO_PATH = os.path.abspath(os.getenv("AEGIS_REPO_PATH", "."))

# Only a hex hash is accepted. This also blocks argument injection such as
# commit="--output=/some/file", which `git show` would happily obey.
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


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
        "List containers with name, compose service, image and state. Use to "
        "find the container behind a failing service and to see whether it is "
        "running. Other container tools accept a container name or a service "
        "name taken from the incident."
    )
)
def list_containers() -> dict:
    containers, error = list_lab_containers()

    if error:
        return err("docker_containers", error)

    not_running = [c for c in containers if c["state"] != "running"]

    if not_running:
        finding = f"{len(not_running)} of {len(containers)} containers are not running: " + ", ".join(
            f"{c['name']} ({c['state']})" for c in not_running
        )
    else:
        finding = f"All {len(containers)} containers are running."

    return ok(
        "docker_containers",
        count=len(containers),
        containers=containers,
        finding=finding,
        time_scope="current",
    )


@mcp.tool(
    description=(
        "Show a container's runtime state: running or exited, exit code, "
        "OOM-killed flag, Docker error, restart count, health, image. Works on "
        "stopped containers. Use first when a container or service is down: "
        "the exit code and OOM flag show how it ended. Accepts a container "
        "name or a compose service name."
    )
)
def inspect_container(container_name: str) -> dict:
    name, problem = resolve_container(container_name)

    if problem:
        return err("docker_container_inspect", problem)

    code, stdout, stderr = run_command(["docker", "container", "inspect", name])

    if code != 0:
        return err(
            "docker_container_inspect",
            stderr.strip() or "Docker inspect failed.",
            container=name,
        )

    try:
        info = json.loads(stdout)[0]

    except (json.JSONDecodeError, IndexError):
        return err(
            "docker_container_inspect",
            "Docker returned an unexpected inspect result.",
            container=name,
        )

    state = info.get("State", {})
    host = info.get("HostConfig", {})
    memory_limit = host.get("Memory") or 0
    cpu_limit = (host.get("NanoCpus") or 0) / 1e9
    docker_error = sanitize_line(state.get("Error") or "") or None

    if state.get("Running"):
        finding = f"Container {name} is running (started {state.get('StartedAt')})."
    else:
        parts = [
            f"Container {name} is not running "
            f"(status {state.get('Status')}, exit code {state.get('ExitCode')})"
        ]
        if state.get("OOMKilled"):
            parts.append("it was killed for exceeding its memory limit")
        if docker_error:
            parts.append(f"Docker error: {docker_error}")
        finding = "; ".join(parts) + "."

    return ok(
        "docker_container_inspect",
        container=name,
        container_status=state.get("Status"),      # not "status": that key is the envelope
        running=state.get("Running"),
        exit_code=state.get("ExitCode"),
        oom_killed=state.get("OOMKilled"),
        error=docker_error,
        # RestartCount is a TOP-LEVEL field of `docker inspect`, not in State.
        restart_count=info.get("RestartCount"),
        restarting=state.get("Restarting"),
        health=(state.get("Health") or {}).get("Status"),
        image=(info.get("Config") or {}).get("Image"),
        memory_limit_bytes=memory_limit if memory_limit else "unlimited",
        cpu_limit_cores=cpu_limit if cpu_limit else "unlimited",
        started_at=state.get("StartedAt"),
        finished_at=state.get("FinishedAt"),
        finding=finding,
        time_scope="current",
    )


@mcp.tool(
    description=(
        "Live CPU and memory usage of a RUNNING container (CPU percent is "
        "relative to one core). Not meaningful for a stopped container: use "
        "the container inspect tool instead. Accepts a container name or a "
        "compose service name."
    )
)
def get_container_stats(container_name: str) -> dict:
    name, problem = resolve_container(container_name)

    if problem:
        return err("docker_container_stats", problem)

    # `docker stats` on a stopped container reports 0%, which would look like
    # a healthy idle container. Check that it is running first.
    code, stdout, stderr = run_command(
        ["docker", "container", "inspect", "--format", "{{.State.Running}}", name]
    )

    if code != 0:
        return err(
            "docker_container_stats",
            stderr.strip() or "Docker inspect failed.",
            container=name,
        )

    if stdout.strip() != "true":
        return ok(
            "docker_container_stats",
            container=name,
            running=False,
            note="Container is not running; resource statistics are not meaningful.",
            time_scope="current",
        )

    code, stdout, stderr = run_command(
        ["docker", "stats", name, "--no-stream", "--format", "{{json .}}"],
        timeout=15,
    )

    if code != 0:
        return err(
            "docker_container_stats",
            stderr.strip() or "Docker stats failed.",
            container=name,
        )

    try:
        stats = json.loads(stdout.strip())

    except json.JSONDecodeError:
        return err(
            "docker_container_stats",
            "Docker returned an unexpected stats result.",
            container=name,
        )

    return ok(
        "docker_container_stats",
        container=name,
        running=True,
        cpu_percent=percent(stats.get("CPUPerc")),
        memory_percent=percent(stats.get("MemPerc")),
        memory_usage=stats.get("MemUsage"),
        pids=stats.get("PIDs"),
        time_scope="current",
    )


@mcp.tool(
    description=(
        "Last log lines of a container (stdout and stderr; works on stopped "
        "containers). Use after inspecting a container that exited with a "
        "non-zero code, was killed or restarted: the last lines usually hold "
        "the error or stack trace that explains why. Also where to look when "
        "the application's own log file shows nothing."
    )
)
def get_container_logs(container_name: str) -> dict:
    name, problem = resolve_container(container_name)

    if problem:
        return err("docker_container_logs", problem)

    # Apps often log to stderr, and `docker logs` replays container stderr on
    # its own stderr, so both streams are merged.
    code, stdout, stderr = run_command(
        ["docker", "logs", "--tail", str(MAX_LOG_LINES), "--timestamps", name],
        merge_stderr=True,
    )

    if code != 0:
        return err(
            "docker_container_logs",
            (stdout or stderr).strip() or "Docker logs failed.",
            container=name,
        )

    lines = [sanitize_line(line) for line in stdout.splitlines()[-MAX_LOG_LINES:]]

    timestamps = []
    for line in lines:
        if line:
            timestamp = line.split(" ", 1)[0]
            if "T" in timestamp:
                timestamps.append(timestamp)

    time_scope = f"last_{MAX_LOG_LINES}_lines"
    if timestamps:
        time_scope = {
            "type": "log_range",
            "from": timestamps[0],
            "to": timestamps[-1],
        }

    return ok(
        "docker_container_logs",
        container=name,
        line_count=len(lines),
        lines=lines,
        time_scope=time_scope,
    )


# ----------------------------------------------------------------------
# Git
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# Git
# ----------------------------------------------------------------------

@mcp.tool(
    description=(
        "List recent Git commits with their short hash, date, author, and "
        "commit message. Use this FIRST when investigating whether a recent "
        "code, configuration, or deployment change may explain an incident. "
        "Check the commit message and date to identify potentially relevant "
        "changes. Only commits made before the incident started can be "
        "considered as possible causes. The returned 'commit' value is the "
        "hash to use with get_commit or get_commit_files."
    )
)
def get_recent_commits(limit: int = 5) -> dict:
    limit = max(1, min(limit, 20))

    code, stdout, stderr = git(
        "log",
        f"-{limit}",
        "--abbrev=12",
        "--date=iso-strict",
        "--pretty=format:%h|%ad|%an|%s",
    )

    if code != 0:
        return err(
            "git_recent_commits",
            stderr.strip() or "Git command failed.",
        )

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

    return ok(
        "git_recent_commits",
        count=len(commits),
        commits=commits,
    )


@mcp.tool(
    description=(
        "Read the metadata and full message of one Git commit. "
        "FIRST call get_recent_commits and select a relevant commit from "
        "its returned list. Pass the exact 'commit' hash returned by "
        "get_recent_commits. Do not pass a service name, container name, "
        "commit message, or invented identifier. Use this when the commit "
        "message or full commit details are needed to investigate the incident."
    )
)
def get_commit(commit: str) -> dict:
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        return err(
            "git_commit",
            (
                "Invalid commit identifier. Use the exact 7-40 character "
                "hexadecimal commit hash returned by get_recent_commits."
            ),
            commit=commit,
            category="invalid",
        )

    code, stdout, stderr = git(
        "show",
        "--no-patch",
        "--date=iso-strict",
        "--format=%H%n%ad%n%an%n%s%n%b",
        commit,
        "--",
    )

    if code != 0:
        return err(
            "git_commit",
            stderr.strip() or "Git commit lookup failed.",
            commit=commit,
        )

    lines = stdout.splitlines()

    if len(lines) < 4:
        return err(
            "git_commit",
            "Git returned an unexpected result.",
            commit=commit,
        )

    body = " ".join(
        line.strip()
        for line in lines[4:]
        if line.strip()
    )

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
        "List the files changed by one Git commit, with line counts. "
        "FIRST call get_recent_commits and select a relevant commit from "
        "its returned list. Pass the exact 'commit' hash returned by "
        "get_recent_commits. Do not pass a service name, container name, "
        "commit message, or invented identifier. Use this to determine "
        "whether the relevant commit touched the failing component."
    )
)
def get_commit_files(commit: str) -> dict:
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        return err(
            "git_commit_files",
            (
                "Invalid commit identifier. Use the exact 7-40 character "
                "hexadecimal commit hash returned by get_recent_commits."
            ),
            commit=commit,
            category="invalid",
        )

    code, stdout, stderr = git(
        "show",
        "--format=",
        "--stat=120",
        "--no-color",
        commit,
        "--",
    )

    if code != 0:
        return err(
            "git_commit_files",
            stderr.strip() or "Git lookup failed.",
            commit=commit,
        )

    summary = [
        sanitize_line(line)
        for line in stdout.splitlines()[:25]
    ]

    return ok(
        "git_commit_files",
        commit=commit,
        summary=summary,
    )

@mcp.tool(
    description=(
        "Read the actual code patch introduced by one Git commit. "
        "FIRST call get_recent_commits and select a relevant commit from "
        "its returned list. Pass the exact 'commit' hash returned by "
        "get_recent_commits. Do not pass a service name, container name, "
        "commit message, or invented identifier. Use this after "
        "get_commit_files confirms that the commit touched the relevant "
        "component. The returned diff shows the actual lines added and "
        "removed by the commit and can be used to identify a code or "
        "configuration change that explains an incident. "
        "Only commits made before the incident started can be considered "
        "as possible causes."
    )
)
def get_commit_diff(commit: str) -> dict:
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        return err(
            "git_commit_diff",
            (
                "Invalid commit identifier. Use the exact 7-40 character "
                "hexadecimal commit hash returned by get_recent_commits."
            ),
            commit=commit,
            category="invalid",
        )

    code, stdout, stderr = git(
        "show",
        "--format=",
        "--no-color",
        "--no-ext-diff",
        commit,
        "--",
    )

    if code != 0:
        return err(
            "git_commit_diff",
            stderr.strip() or "Git diff lookup failed.",
            commit=commit,
        )

    MAX_DIFF_CHARS = 12000
    diff = stdout[:MAX_DIFF_CHARS]

    truncated = len(stdout) > MAX_DIFF_CHARS

    return ok(
        "git_commit_diff",
        commit=commit,
        diff=diff,
        truncated=truncated,
    )

if __name__ == "__main__":
    mcp.run()