import asyncio
import json
import operator
import os
import re
import sys
from datetime import datetime, timezone
from typing import Annotated, TypedDict

import psycopg2

from langchain_core.messages import AIMessage
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.types import Command

from agent.mcp_client import create_mcp_adapter
from rag.vectorstore import load_vector_store
from guardrails.config.actions import aegis_sre_policy


# ============================================================
# PROMPTS
# ============================================================

SYSTEM_PROMPT = """You are Aegis, an SRE incident-investigation assistant.

Investigate incidents using diagnostic tools.

Always distinguish:

1. OBSERVED PROBLEM
   What is visibly happening?

2. FAILURE MECHANISM
   What technically failed and how?

3. ROOT CAUSE
   What underlying change, condition, configuration, dependency,
   or event explains why the failure mechanism occurred?

These are different.

Rules:
- Never invent facts.
- Never invent metrics.
- Never invent identifiers.
- Never invent commit hashes.
- Never invent root causes.
- Never treat an alert as a root cause.
- Never treat a symptom as a root cause.
- Never treat a failure mechanism as automatically being the root cause.
- Tool results are evidence.
- Runbook guidance is not incident evidence.
- Respect the time scope of every tool result.
"""


DEFAULT_OPEN_QUESTION = (
    "What evidence should be collected first to establish what is happening?"
)


AGENT_PROMPT = """You are the diagnostic tool-selection component of Aegis.

Choose EXACTLY ONE tool from AVAILABLE TOOLS.

INCIDENT:
{incident}

OBSERVED PROBLEM:
{observed_problem}

FAILURE MECHANISM:
{failure_mechanism}

ROOT CAUSE:
{root_cause}

OPEN QUESTION:
{open_question}

CURRENT EVIDENCE:
{evidence}

TOOLS ALREADY USED:
{tried}

AVAILABLE TOOLS:
{tool_catalog}

RUNBOOK GUIDANCE:
{guidance}

Rules:

1. Choose exactly ONE available tool.
2. The tool must provide NEW evidence relevant to the OPEN QUESTION.
3. Never repeat the same tool call with the same arguments.
4. Never invent identifiers.
5. Never invent commit hashes.
6. Use identifiers from the incident or previous tool results.
7. If the selected tool requires arguments, provide ALL required arguments.
8. Do not call an argument-taking tool with an empty object.
9. Do not claim a root cause.
10. Do not stop while useful diagnostic tools remain available.

GIT RULES:

- get_recent_commits must happen before commit-specific tools.
- get_commit requires a hash returned by get_recent_commits.
- get_commit_files requires a hash returned by get_recent_commits.
- get_commit_diff requires a hash returned by get_recent_commits.
- Never invent a commit hash.
- Only commits before the incident start can explain the incident.

Call exactly ONE tool.
"""


DECISION_PROMPT = """You are the investigation-state analyzer inside Aegis.

Analyze the supplied evidence.

INCIDENT:
{incident}

OBSERVED PROBLEM:
{observed_problem}

FAILURE MECHANISM:
{failure_mechanism}

ROOT CAUSE:
{root_cause}

OPEN QUESTION:
{open_question}

ALL EVIDENCE:
{evidence}

NEWEST EVIDENCE:
{newest_evidence}

RUNBOOK GUIDANCE:
{guidance}

Distinguish:

Observed problem:
The externally visible incident.

Failure mechanism:
The technical failure directly explaining the incident.

Root cause:
The underlying reason that caused or introduced the failure mechanism.

Examples:

"Backend is unreachable"
= observed problem.

"Backend process failed because a Python module could not be imported"
= failure mechanism.

"A code/dependency/configuration change caused that module to be unavailable"
= possible root cause.

Rules:

- Alert state is not root cause.
- A target being down is not root cause.
- Current CPU/memory metrics are normally symptom evidence.
- Container exit status can establish process failure, not automatically its cause.
- Stack traces can establish a failure mechanism.
- A pre-incident Git diff can establish root cause when it directly explains
  the failure mechanism.
- A log can establish root cause when it directly contains reliable causal
  evidence.
- Post-incident changes cannot cause an earlier incident.
- Runbook text is not evidence.

Return exactly:

Observed problem: <statement>

Failure mechanism: <statement or unknown>

Root cause: <statement or unknown>

Root cause evidence: [N]
or
Root cause evidence: none

Open question: <question or none>

Investigation complete: yes
or
Investigation complete: no
"""


FINAL_PROMPT = """You are Aegis, an SRE incident-investigation assistant.

Produce a final evidence-based incident report.

INCIDENT:
{incident}

OBSERVED PROBLEM:
{observed_problem}

FAILURE MECHANISM:
{failure_mechanism}

ROOT CAUSE:
{root_cause}

ROOT CAUSE EVIDENCE:
{root_cause_evidence}

EVIDENCE:
{evidence}

RUNBOOK GUIDANCE:
{guidance}

Use exactly these sections:

1. Incident
2. Current state
3. Root cause
4. Recommended resolution
5. Risk
6. Gaps

Rules:

- Use only supplied evidence.
- Never invent facts.
- Never invent a root cause.
- Never claim remediation was executed.
- Failure mechanism is not automatically root cause.
- If root cause is unconfirmed, say so clearly.
- A recommendation must be supported by evidence.
- If root cause is unconfirmed, recommendations must be limited to
  investigation or evidence-supported containment guidance.
"""


# ============================================================
# CONSTANTS
# ============================================================

THINK_RE = re.compile(
    r"<think>.*?</think>",
    re.DOTALL,
)

MAX_TOOL_CALLS = 8

GUIDANCE_K = 3
GUIDANCE_CHARS = 400

MAX_LIST_ITEMS = 6
MAX_ITEM_CHARS = 160


# ============================================================
# TOOL CATEGORIES
# ============================================================

TOOL_CATEGORY = {
    "prometheus_query_targets": "symptom",
    "prometheus_query_cpu": "symptom",
    "prometheus_query_cpu_history": "symptom",
    "prometheus_query_memory": "symptom",
    "prometheus_query_memory_history": "symptom",
    "prometheus_query_request_rate": "symptom",
    "prometheus_query_error_rate": "symptom",
    "prometheus_query_latency": "symptom",

    "logs_search_logs": "direct",
    "logs_search_errors": "direct",
    "logs_search_slow_requests": "direct",

    "operations_list_containers": "symptom",
    "operations_inspect_container": "direct",
    "operations_get_container_stats": "direct",
    "operations_get_container_logs": "direct",

    "operations_get_recent_commits": "context",
    "operations_get_commit": "context",
    "operations_get_commit_files": "context",
    "operations_get_commit_diff": "direct",
}


GIT_TOOLS = {
    "operations_get_recent_commits",
    "operations_get_commit",
    "operations_get_commit_files",
    "operations_get_commit_diff",
}


COMMIT_SPECIFIC_TOOLS = {
    "operations_get_commit",
    "operations_get_commit_files",
    "operations_get_commit_diff",
}


# ============================================================
# STATE
# ============================================================

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]

    investigation_status: str

    evidence: Annotated[list, operator.add]
    used_tools: Annotated[list, operator.add]
    tool_errors: Annotated[list, operator.add]

    investigation_summary: dict


# ============================================================
# HELPERS
# ============================================================

def call_signature(
    name: str,
    args: dict,
) -> str:

    return (
        f"{name}:"
        f"{json.dumps(args or {}, sort_keys=True, default=str)}"
    )


def format_tried(
    used_tools: list[str],
) -> str:

    if not used_tools:
        return "(none)"

    return "\n".join(
        f"- {item}"
        for item in used_tools[-MAX_LIST_ITEMS:]
    )


def is_informative(
    result,
) -> bool:

    if not isinstance(result, dict):
        return bool(result)

    for key in (
        "finding",
        "value",
        "series",
        "targets",
        "containers",
        "matches",
        "lines",
        "failure_lines",
        "commits",
        "diff",
        "summary",
        "subject",
        "body",
    ):

        value = result.get(key)

        if value is None:
            continue

        if isinstance(
            value,
            (list, dict, str),
        ) and not value:
            continue

        return True

    return False


def evidence_category(
    tool_name: str,
    result,
) -> str:

    if not isinstance(result, dict):
        return "invalid"

    if result.get("status") == "error":
        return "invalid"

    if not is_informative(result):
        return "inconclusive"

    return TOOL_CATEGORY.get(
        tool_name,
        "symptom",
    )


def compact(
    value,
    started_at=None,
):

    if isinstance(value, dict):

        if (
            "commits" in value
            and isinstance(
                value["commits"],
                list,
            )
        ):

            commits = []

            for commit in value["commits"]:

                if not isinstance(
                    commit,
                    dict,
                ):
                    continue

                date = commit.get("date")

                if (
                    started_at
                    and date
                    and not commit_predates_incident(
                        date,
                        started_at,
                    )
                ):
                    continue

                commits.append(
                    commit
                )

            value = dict(value)
            value["commits"] = commits

        result = {}

        for key, item in value.items():

            if isinstance(item, list):

                result[key] = [
                    compact(
                        x,
                        started_at=started_at,
                    )
                    for x in item[:MAX_LIST_ITEMS]
                ]

            elif isinstance(item, dict):

                result[key] = compact(
                    item,
                    started_at=started_at,
                )

            elif isinstance(item, str):

                result[key] = item[
                    :MAX_ITEM_CHARS
                ]

            else:

                result[key] = item

        return result

    if isinstance(value, list):

        return [
            compact(
                x,
                started_at=started_at,
            )
            for x in value[:MAX_LIST_ITEMS]
        ]

    if isinstance(value, str):
        return value[
            :MAX_ITEM_CHARS
        ]

    return value


def format_evidence(
    evidence,
    started_at=None,
):

    if not evidence:
        return "(none)"

    return "\n".join(
        f"[{i}] "
        f"({item.get('category', 'unknown')}) "
        f"{item.get('call', '')} -> "
        f"{compact(item.get('result', {}), started_at=started_at)}"
        for i, item in enumerate(
            evidence,
            1,
        )
    )


# ============================================================
# TIME
# ============================================================

def parse_datetime(
    value,
):

    if not value:
        return None

    if isinstance(
        value,
        datetime,
    ):

        dt = value

    else:

        text = str(
            value
        ).strip()

        if text.endswith("Z"):
            text = (
                text[:-1]
                + "+00:00"
            )

        try:

            dt = datetime.fromisoformat(
                text
            )

        except ValueError:

            return None

    if dt.tzinfo is None:

        dt = dt.replace(
            tzinfo=timezone.utc
        )

    return dt


def commit_predates_incident(
    commit_date,
    incident_started_at,
):

    commit_dt = parse_datetime(
        commit_date
    )

    incident_dt = parse_datetime(
        incident_started_at
    )

    if (
        not commit_dt
        or not incident_dt
    ):
        return True

    return commit_dt < incident_dt


def valid_commit_hash(
    value,
):

    if not isinstance(
        value,
        str,
    ):
        return False

    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{7,40}",
            value.strip(),
        )
    )


def find_commit_date(
    evidence,
    commit_hash,
):

    if not commit_hash:
        return None

    for item in evidence:

        if (
            item.get("tool")
            != "operations_get_recent_commits"
        ):
            continue

        result = item.get(
            "result",
            {},
        )

        if not isinstance(
            result,
            dict,
        ):
            continue

        commits = result.get(
            "commits",
            [],
        )

        if not isinstance(
            commits,
            list,
        ):
            continue

        for commit in commits:

            if not isinstance(
                commit,
                dict,
            ):
                continue

            if (
                commit.get("commit")
                == commit_hash
            ):

                return commit.get(
                    "date"
                )

    return None


def get_valid_commit_hashes(
    evidence,
    incident_started_at,
):

    hashes = []

    for item in evidence:

        if (
            item.get("tool")
            != "operations_get_recent_commits"
        ):
            continue

        result = item.get(
            "result",
            {},
        )

        if not isinstance(
            result,
            dict,
        ):
            continue

        commits = result.get(
            "commits",
            [],
        )

        if not isinstance(
            commits,
            list,
        ):
            continue

        for commit in commits:

            if not isinstance(
                commit,
                dict,
            ):
                continue

            commit_hash = commit.get(
                "commit"
            )

            commit_date = commit.get(
                "date"
            )

            if not valid_commit_hash(
                commit_hash
            ):
                continue

            if (
                incident_started_at
                and commit_date
                and not commit_predates_incident(
                    commit_date,
                    incident_started_at,
                )
            ):
                continue

            hashes.append(
                commit_hash
            )

    return hashes


# ============================================================
# TOOL SCHEMA
# ============================================================

def allowed_arg_names(
    tool,
):

    schema = getattr(
        tool,
        "args_schema",
        None,
    )

    if schema is None:
        return set()

    fields = getattr(
        schema,
        "model_fields",
        None,
    )

    if fields is not None:
        return set(
            fields.keys()
        )

    fields = getattr(
        schema,
        "__fields__",
        None,
    )

    if fields is not None:
        return set(
            fields.keys()
        )

    return set()


def clean_args(
    tool,
    args,
):

    if not isinstance(
        args,
        dict,
    ):
        return {}

    allowed = allowed_arg_names(
        tool
    )

    if not allowed:
        return {}

    cleaned = {
        key: value
        for key, value in args.items()
        if key in allowed
    }

    for key, value in list(
        cleaned.items()
    ):

        if (
            isinstance(
                value,
                dict,
            )
            and set(
                value.keys()
            )
            == {"value"}
        ):

            cleaned[key] = value[
                "value"
            ]

    return cleaned


def validate_tool_args(
    tool,
    args,
):

    schema = getattr(
        tool,
        "args_schema",
        None,
    )

    if schema is None:
        return True

    try:

        if hasattr(
            schema,
            "model_validate",
        ):

            schema.model_validate(
                args
            )

            return True

        if hasattr(
            schema,
            "parse_obj",
        ):

            schema.parse_obj(
                args
            )

            return True

    except Exception:

        return False

    return True


# ============================================================
# DETERMINISTIC ARGUMENT REPAIR
# ============================================================

def extract_search_term(
    incident,
    evidence,
):

    # Prefer a meaningful error identifier from
    # already collected evidence.

    patterns = [
        r"\b[A-Za-z_][A-Za-z0-9_]*Error\b",
        r"\b[A-Za-z_][A-Za-z0-9_]*Exception\b",
        r"\bModuleNotFoundError\b",
        r"\bConnectionRefusedError\b",
        r"\bTimeoutError\b",
        r"\bTraceback\b",
    ]

    for item in reversed(
        evidence
    ):

        result = item.get(
            "result",
            {},
        )

        text = json.dumps(
            result,
            default=str,
        )

        for pattern in patterns:

            match = re.search(
                pattern,
                text,
            )

            if match:
                return match.group(0)

    # Safe fallback: incident service.
    return incident.get(
        "service",
        "error",
    )


def repair_tool_args(
    tool_name,
    args,
    incident,
    evidence,
):

    args = dict(
        args or {}
    )

    # --------------------------------------------------------
    # Container tools
    # --------------------------------------------------------

    container_tools = {
        "operations_inspect_container",
        "operations_get_container_stats",
        "operations_get_container_logs",
    }

    if tool_name in container_tools:

        if not args.get(
            "container_name"
        ):

            service = incident.get(
                "service"
            )

            if service:
                args[
                    "container_name"
                ] = service

    # --------------------------------------------------------
    # Generic log search
    # --------------------------------------------------------

    if tool_name == "logs_search_logs":

        if not args.get(
            "query"
        ):

            args["query"] = (
                extract_search_term(
                    incident,
                    evidence,
                )
            )

    return args


# ============================================================
# TOOL CALL NORMALIZATION
# ============================================================

def normalize_tool_call(
    response,
    tools_by_name,
):

    if not response.tool_calls:
        return response, None

    call = response.tool_calls[0]

    name = call.get(
        "name"
    )

    tool = tools_by_name.get(
        name
    )

    if tool is None:
        return response, None

    args = clean_args(
        tool,
        call.get(
            "args",
            {},
        ),
    )

    call["args"] = args

    return (
        response,
        call_signature(
            name,
            args,
        ),
    )


# ============================================================
# INVESTIGATION TOOL STAGING
# ============================================================

def has_direct_evidence(
    evidence,
):

    return any(
        item.get("category")
        == "direct"
        for item in evidence
    )


def has_git_recent_commits(
    evidence,
):

    for item in evidence:

        if (
            item.get("tool")
            != "operations_get_recent_commits"
        ):
            continue

        result = item.get(
            "result",
            {},
        )

        if not isinstance(
            result,
            dict,
        ):
            continue

        if isinstance(
            result.get("commits"),
            list,
        ):
            return True

    return False


def open_question_needs_history(
    question,
):

    if not question:
        return False

    text = question.lower()

    terms = (
        "introduced",
        "introduction",
        "change",
        "changed",
        "commit",
        "deployment",
        "deployed",
        "configuration",
        "code change",
        "what caused",
        "why did",
        "why does",
        "what explains",
        "root cause",
        "underlying",
    )

    return any(
        term in text
        for term in terms
    )


def available_tools(
    tools,
    used_tools,
    evidence=None,
    open_question="",
    incident_started_at=None,
):

    evidence = evidence or []

    used_set = set(
        used_tools
    )

    direct_exists = (
        has_direct_evidence(
            evidence
        )
    )

    git_history_available = (
        has_git_recent_commits(
            evidence
        )
    )

    valid_hashes = (
        get_valid_commit_hashes(
            evidence,
            incident_started_at,
        )
    )

    usable = []

    for tool in tools:

        name = tool.name

        # Used zero-argument tools are not useful again.
        if (
            allowed_arg_names(tool)
            == set()
            and call_signature(
                name,
                {},
            )
            in used_set
        ):
            continue

        # ----------------------------------------------------
        # Commit-specific tools
        # ----------------------------------------------------

        if name in COMMIT_SPECIFIC_TOOLS:

            if not git_history_available:
                continue

            if not valid_hashes:
                continue

            usable.append(
                tool
            )

            continue

        # ----------------------------------------------------
        # Recent commits
        # ----------------------------------------------------

        if (
            name
            == "operations_get_recent_commits"
        ):

            if git_history_available:
                continue

            if not direct_exists:
                continue

            if not open_question_needs_history(
                open_question
            ):
                continue

            usable.append(
                tool
            )

            continue

        # ----------------------------------------------------
        # Before direct evidence
        # ----------------------------------------------------

        if not direct_exists:

            category = TOOL_CATEGORY.get(
                name,
                "symptom",
            )

            if category in {
                "symptom",
                "direct",
            }:

                usable.append(
                    tool
                )

            continue

        # ----------------------------------------------------
        # After direct evidence
        # ----------------------------------------------------

        category = TOOL_CATEGORY.get(
            name,
            "symptom",
        )

        if category in {
            "symptom",
            "direct",
        }:

            usable.append(
                tool
            )

    # --------------------------------------------------------
    # History must be next
    # --------------------------------------------------------

    if (
        direct_exists
        and open_question_needs_history(
            open_question
        )
        and not git_history_available
    ):

        history_tool = [
            tool
            for tool in usable
            if tool.name
            == "operations_get_recent_commits"
        ]

        if history_tool:
            return history_tool

    # --------------------------------------------------------
    # Commit details
    # --------------------------------------------------------

    if (
        git_history_available
        and valid_hashes
        and open_question_needs_history(
            open_question
        )
    ):

        commit_tools = [
            tool
            for tool in usable
            if tool.name
            in COMMIT_SPECIFIC_TOOLS
        ]

        if commit_tools:
            return commit_tools

    return usable


def format_catalog(
    tools,
):

    if not tools:
        return "(none)"

    lines = []

    for tool in tools:

        description = (
            getattr(
                tool,
                "description",
                "",
            )
            or ""
        )

        first_line = (
            description
            .splitlines()[0]
            .strip()
        )

        lines.append(
            f"- {tool.name}: {first_line}"
        )

    return "\n".join(
        lines
    )


# ============================================================
# RAG
# ============================================================

async def retrieve_guidance(
    vector_store,
    query,
):

    try:

        docs = await asyncio.to_thread(
            vector_store.similarity_search,
            query,
            k=GUIDANCE_K,
        )

    except Exception:

        return (
            "(no runbook guidance available)"
        )

    if not docs:
        return (
            "(no runbook guidance available)"
        )

    chunks = []

    for doc in docs:

        content = getattr(
            doc,
            "page_content",
            "",
        )

        if content:
            chunks.append(
                content[
                    :GUIDANCE_CHARS
                ]
            )

    if not chunks:
        return (
            "(no runbook guidance available)"
        )

    return "\n---\n".join(
        chunks
    )


# ============================================================
# DATABASE
# ============================================================

def load_incident(
    incident_id,
):

    conn = psycopg2.connect(
        host="127.0.0.1",
        port=5433,
        database="aegis_incidents",
        user="postgres",
        password="postgres",
    )

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                incident_id,
                alert_name,
                incident_type,
                severity,
                service,
                status,
                started_at,
                description
            FROM incidents
            WHERE incident_id = %s
            """,
            (incident_id,),
        )

        row = cursor.fetchone()

        if not row:
            return None

        return {
            "incident_id": row[0],
            "alert_name": row[1],
            "incident_type": row[2],
            "severity": row[3],
            "service": row[4],
            "status": row[5],
            "started_at": row[6],
            "description": row[7],
        }

    finally:

        conn.close()


# ============================================================
# MESSAGE BUILDER
# ============================================================

def build_messages(
    content,
):

    return [
        {
            "role": "system",
            "content": SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": content,
        },
    ]


# ============================================================
# MAIN
# ============================================================

async def run_investigation(
    incident_id: str,
    on_event=None,
):

    def emit_event(
        event_type,
        **data,
    ):
        if on_event:
            on_event(
                {
                    "type": event_type,
                    **data,
                }
            )

    # ========================================================
    # INCIDENT
    # ========================================================

    incident = await asyncio.to_thread(
        load_incident,
        incident_id,
    )

    if not incident:
        raise ValueError(
            f"Incident not found: {incident_id}"
        )

    event_payload = {
        "incident_id": incident["incident_id"],
        "description": incident["description"],
        "severity": incident["severity"],
        "status": incident["status"],
    }

    print(
        "INCIDENT EVENT SENT:",
        event_payload,
        flush=True,
    )

    emit_event(
        "incident_received",
        **event_payload,
    )

    incident_text = (
        f"Incident ID: "
        f"{incident['incident_id']}\n"
        f"Alert: "
        f"{incident['alert_name']}\n"
        f"Type: "
        f"{incident['incident_type']}\n"
        f"Severity: "
        f"{incident['severity']}\n"
        f"Service: "
        f"{incident['service']}\n"
        f"Status: "
        f"{incident['status']}\n"
        f"Started at: "
        f"{incident['started_at']}\n"
        f"Description: "
        f"{incident['description']}"
    )

    incident_query = (
        f"{incident['alert_name']} "
        f"{incident['incident_type']} "
        f"{incident['service']} "
        f"{incident['description']}"
    )

    # ========================================================
    # MCP
    # ========================================================

    adapter = create_mcp_adapter()

    tools = await adapter.list_tools()

    tools_by_name = {
        tool.name: tool
        for tool in tools
    }

    # ========================================================
    # RAG
    # ========================================================

    vector_store = load_vector_store()

    # ========================================================
    # LLM
    # ========================================================

    llm = ChatOllama(
        model=os.getenv(
            "AEGIS_MODEL",
            "qwen3:1.7b",
        ),
        temperature=0,
        num_ctx=8192,
        reasoning=False,
    )

    # ========================================================
    # AGENT NODE
    # ========================================================

    async def agent_node(
        state: AgentState,
    ):

        summary = state.get(
            "investigation_summary",
            {},
        )

        observed_problem = summary.get(
            "observed_problem",
            incident["description"],
        )

        failure_mechanism = summary.get(
            "failure_mechanism",
            "Unknown",
        )

        root_cause = summary.get(
            "root_cause",
            "Unknown",
        )

        open_question = summary.get(
            "open_question",
            DEFAULT_OPEN_QUESTION,
        )

        guidance = await retrieve_guidance(
            vector_store,
            incident_query,
        )

        usable = available_tools(
            tools,
            state["used_tools"],
            state["evidence"],
            open_question=open_question,
            incident_started_at=incident[
                "started_at"
            ],
        )

        if not usable:

            return {
                "messages": [
                    AIMessage(
                        content="NO_NEW_EVIDENCE"
                    )
                ]
            }

        prompt = AGENT_PROMPT.format(
            incident=incident_text,

            observed_problem=(
                observed_problem
            ),

            failure_mechanism=(
                failure_mechanism
            ),

            root_cause=root_cause,

            open_question=open_question,

            evidence=format_evidence(
                state["evidence"],
                started_at=incident[
                    "started_at"
                ],
            ),

            tried=format_tried(
                state["used_tools"]
            ),

            tool_catalog=format_catalog(
                usable
            ),

            guidance=guidance,
        )

        response = await llm.bind_tools(
            usable
        ).ainvoke(
            build_messages(
                prompt
            )
        )

        response, signature = (
            normalize_tool_call(
                response,
                tools_by_name,
            )
        )

        # ----------------------------------------------------
        # Retry when Qwen produces no tool call.
        # ----------------------------------------------------

        if not response.tool_calls:

            retry_prompt = (
                prompt
                + """

The investigation is still in progress.

Choose exactly ONE available diagnostic tool.

If the tool requires arguments, provide all
required arguments.
"""
            )

            retry = await llm.bind_tools(
                usable
            ).ainvoke(
                build_messages(
                    retry_prompt
                )
            )

            retry, signature = (
                normalize_tool_call(
                    retry,
                    tools_by_name,
                )
            )

            if retry.tool_calls:

                response = retry

            else:

                response = AIMessage(
                    content="NO_NEW_EVIDENCE"
                )

        # ----------------------------------------------------
        # Basic pre-execution model validation.
        # ----------------------------------------------------

        if response.tool_calls:

            call = response.tool_calls[0]

            name = call.get(
                "name"
            )

            args = call.get(
                "args",
                {},
            )

            allowed_names = {
                tool.name
                for tool in usable
            }

            if name not in allowed_names:

                response = AIMessage(
                    content="NO_NEW_EVIDENCE"
                )

            else:

                tool = tools_by_name.get(
                    name
                )

                if tool is not None:

                    repaired = (
                        repair_tool_args(
                            name,
                            args,
                            incident,
                            state[
                                "evidence"
                            ],
                        )
                    )

                    repaired = clean_args(
                        tool,
                        repaired,
                    )

                    call["args"] = repaired

                    print(
                        "MODEL TOOL CALL:",
                        name,
                        args,
                    )

                    if repaired != args:

                        print(
                            "AEGIS ARG REPAIR:",
                            args,
                            "->",
                            repaired,
                        )

        print(
            "AGENT:",
            response.tool_calls
            or response.content,
        )

        return {
            "messages": [
                response
            ]
        }

    # ========================================================
    # TOOL EXECUTION WRAPPER
    # ========================================================

    async def capture_tool_result(
        request,
        execute,
    ):

        name = request.tool_call[
            "name"
        ]

        original_args = request.tool_call.get(
            "args",
            {},
        )

        # ----------------------------------------------------
        # THIS IS THE CRITICAL FIX.
        #
        # Repair arguments immediately before MCP execution.
        # ----------------------------------------------------

        repaired_args = repair_tool_args(
            name,
            original_args,
            incident,
            [],
        )

        # Use current state evidence if available through
        # request metadata when supported.
        #
        # For the currently problematic tools, the incident
        # service is sufficient for container_name and the
        # incident/error context is sufficient for query.
        request.tool_call[
            "args"
        ] = repaired_args

        args = repaired_args

        print(
            "TOOL CALL:",
            {
                "name": name,
                "args": args,
            },
        )

        emit_event(
            "tool_start",
            tool=name,
        )

        # ----------------------------------------------------
        # Execute MCP ONLY after argument repair.
        # ----------------------------------------------------

        result = await execute(
            request
        )

        emit_event(
            "tool_complete",
            tool=name,
        )

        artifact = getattr(
            result,
            "artifact",
            None,
        )

        if (
            isinstance(
                artifact,
                dict,
            )
            and "structured_content"
            in artifact
        ):

            tool_result = artifact[
                "structured_content"
            ]

        else:

            tool_result = result.content

        signature = call_signature(
            name,
            args,
        )

        category = evidence_category(
            name,
            tool_result,
        )

        item = {
            "tool": name,
            "args": args,
            "call": signature,
            "result": tool_result,
            "category": category,
            "collected_at": datetime.now(
                timezone.utc
            ).isoformat(),
        }

        # ----------------------------------------------------
        # MCP VALIDATION ERROR
        # ----------------------------------------------------

        if (
            isinstance(
                tool_result,
                list,
            )
            and any(
                "validation error"
                in str(x).lower()
                for x in tool_result
            )
        ):

            print(
                "MCP ARGUMENT ERROR:",
                item,
            )

            return Command(
                update={
                    "messages": [
                        result
                    ],
                    "tool_errors": [
                        item
                    ],
                    "used_tools": [
                        signature
                    ],
                }
            )

        # ----------------------------------------------------
        # NORMAL MCP ERROR
        # ----------------------------------------------------

        if (
            isinstance(
                tool_result,
                dict,
            )
            and tool_result.get(
                "status"
            )
            == "error"
        ):

            print(
                "TOOL ERROR:",
                item,
            )

            return Command(
                update={
                    "messages": [
                        result
                    ],
                    "tool_errors": [
                        item
                    ],
                    "used_tools": [
                        signature
                    ],
                }
            )

        # ----------------------------------------------------
        # NORMAL EVIDENCE
        # ----------------------------------------------------

        print(
            "EVIDENCE STORED:",
            item,
        )

        return Command(
            update={
                "messages": [
                    result
                ],
                "evidence": [
                    item
                ],
                "used_tools": [
                    signature
                ],
            }
        )

    # ========================================================
    # TOOL NODE
    # ========================================================

    tool_node = ToolNode(
        tools,
        awrap_tool_call=capture_tool_result,
    )

    # ========================================================
    # DECISION NODE
    # ========================================================

    async def investigation_decision(
        state: AgentState,
    ):

        evidence = state[
            "evidence"
        ]

        previous = state.get(
            "investigation_summary",
            {},
        )

        observed_problem = previous.get(
            "observed_problem",
            incident["description"],
        )

        failure_mechanism = previous.get(
            "failure_mechanism",
            "Unknown",
        )

        root_cause = previous.get(
            "root_cause",
            "Unknown",
        )

        open_question = previous.get(
            "open_question",
            DEFAULT_OPEN_QUESTION,
        )

        newest = (
            evidence[-1]
            if evidence
            else {}
        )

        guidance = await retrieve_guidance(
            vector_store,
            incident_query,
        )

        prompt = DECISION_PROMPT.format(
            incident=incident_text,

            observed_problem=(
                observed_problem
            ),

            failure_mechanism=(
                failure_mechanism
            ),

            root_cause=root_cause,

            open_question=open_question,

            evidence=format_evidence(
                evidence,
                started_at=incident[
                    "started_at"
                ],
            ),

            newest_evidence=(
                format_evidence(
                    [newest],
                    started_at=incident[
                        "started_at"
                    ],
                )
                if newest
                else "(none)"
            ),

            guidance=guidance,
        )

        response = await llm.ainvoke(
            build_messages(
                prompt
            )
        )

        raw = THINK_RE.sub(
            "",
            response.content,
        ).strip()

        print(
            "DECISION:",
            raw,
        )

        observed_match = re.search(
            r"observed problem:\s*(.+)",
            raw,
            re.IGNORECASE,
        )

        mechanism_match = re.search(
            r"failure mechanism:\s*(.+)",
            raw,
            re.IGNORECASE,
        )

        root_match = re.search(
            r"root cause:\s*(.+)",
            raw,
            re.IGNORECASE,
        )

        evidence_match = re.search(
            r"root cause evidence:\s*\[(\d+)\]",
            raw,
            re.IGNORECASE,
        )

        question_match = re.search(
            r"open question:\s*(.+)",
            raw,
            re.IGNORECASE,
        )

        observed_problem = (
            observed_match.group(1).strip()
            if observed_match
            else observed_problem
        )

        failure_mechanism = (
            mechanism_match.group(1).strip()
            if mechanism_match
            else failure_mechanism
        )

        root_cause = (
            root_match.group(1).strip()
            if root_match
            else "Unknown"
        )

        open_question = (
            question_match.group(1).strip()
            if question_match
            else open_question
        )

        cited_idx = (
            int(
                evidence_match.group(1)
            )
            if evidence_match
            else None
        )

        cited_item = None

        if (
            cited_idx is not None
            and 1 <= cited_idx <= len(
                evidence
            )
        ):

            cited_item = evidence[
                cited_idx - 1
            ]

        # ----------------------------------------------------
        # ROOT CAUSE VALIDATION
        # ----------------------------------------------------

        cause_established = False

        root_unknown = (
            not root_cause
            or root_cause.lower()
            in {
                "unknown",
                "none",
                "unconfirmed",
                "not established",
            }
        )

        if (
            not root_unknown
            and cited_item
        ):

            category = cited_item.get(
                "category"
            )

            tool_name = cited_item.get(
                "tool"
            )

            if category == "direct":

                # Git diff is valid causal evidence
                # only if its commit predates incident.
                if (
                    tool_name
                    == "operations_get_commit_diff"
                ):

                    commit_hash = (
                        cited_item
                        .get("args", {})
                        .get("commit")
                    )

                    commit_date = find_commit_date(
                        evidence,
                        commit_hash,
                    )

                    if (
                        commit_hash
                        and commit_date
                        and commit_predates_incident(
                            commit_date,
                            incident[
                                "started_at"
                            ],
                        )
                    ):

                        cause_established = True

                else:

                    # Direct logs/container evidence can
                    # establish root cause if the model
                    # explicitly identified it.
                    cause_established = True

        # ----------------------------------------------------
        # HARD BARRIER AGAINST PREMATURE STOPPING
        # ----------------------------------------------------

        if not cause_established:

            if open_question.lower() in {
                "none",
                "no further investigation",
                "no further evidence",
            }:

                if failure_mechanism != "Unknown":

                    open_question = (
                        "What evidence directly explains "
                        "why the failure mechanism occurred?"
                    )

                else:

                    open_question = (
                        "What evidence directly explains "
                        "the observed failure?"
                    )

        return {
            "investigation_status": (
                "finish"
                if cause_established
                else "continue"
            ),

            "investigation_summary": {
                "observed_problem": (
                    observed_problem
                ),

                "failure_mechanism": (
                    failure_mechanism
                ),

                "root_cause": (
                    root_cause
                    if cause_established
                    else "Unknown"
                ),

                "root_cause_evidence": (
                    cited_idx
                    if cause_established
                    else None
                ),

                "cause_established": (
                    cause_established
                ),

                "open_question": (
                    open_question
                ),

                "guidance": guidance,
            },
        }

    # ========================================================
    # ROUTER
    # ========================================================

    def route_investigation(
        state: AgentState,
    ):

        summary = state.get(
            "investigation_summary",
            {},
        )

        cause_established = bool(
            summary.get(
                "cause_established",
                False,
            )
        )

        if cause_established:
            return "final_answer"

        if (
            len(
                state["used_tools"]
            )
            >= MAX_TOOL_CALLS
        ):
            return "final_answer"

        return "agent"

    # ========================================================
    # POLICY
    # ========================================================

    def evaluate_policy(
        state: AgentState,
    ):

        summary = state.get(
            "investigation_summary",
            {},
        )

        cause_established = bool(
            summary.get(
                "cause_established",
                False,
            )
        )

        evidence_index = summary.get(
            "root_cause_evidence"
        )

        direct = False

        if (
            isinstance(
                evidence_index,
                int,
            )
            and 1 <= evidence_index <= len(
                state["evidence"]
            )
        ):

            direct = (
                state["evidence"][
                    evidence_index - 1
                ].get("category")
                == "direct"
            )

        return {
            "cause_established": (
                cause_established
            ),

            "root_cause_evidence_is_direct": (
                direct
            ),

            "recommendation_supported": (
                cause_established
                and direct
            ),
        }

    # ========================================================
    # FINAL
    # ========================================================

    async def final_answer(
        state: AgentState,
    ):

        policy = evaluate_policy(
            state
        )

        policy_result = aegis_sre_policy(
            policy
        )

        summary = state.get(
            "investigation_summary",
            {},
        )

        if not policy_result.get(
            "allowed",
            True,
        ):

            conclusion = (
                "INVESTIGATION BLOCKED "
                "BY AEGIS SRE POLICY"
            )

            return {
                "messages": [
                    AIMessage(
                        content=conclusion
                    )
                ],

                "investigation_summary": {
                    **summary,
                    "conclusion": conclusion,
                },
            }

        guidance = (
            summary.get(
                "guidance"
            )
            or await retrieve_guidance(
                vector_store,
                incident_query,
            )
        )

        root_idx = summary.get(
            "root_cause_evidence"
        )

        root_evidence = (
            f"Evidence [{root_idx}]"
            if root_idx
            else "None"
        )

        prompt = FINAL_PROMPT.format(
            incident=incident_text,

            observed_problem=summary.get(
                "observed_problem",
                "Unknown",
            ),

            failure_mechanism=summary.get(
                "failure_mechanism",
                "Unknown",
            ),

            root_cause=summary.get(
                "root_cause",
                "Unknown",
            ),

            root_cause_evidence=(
                root_evidence
            ),

            evidence=format_evidence(
                state["evidence"],
                started_at=incident[
                    "started_at"
                ],
            ),

            guidance=guidance,
        )

        response = await llm.ainvoke(
            build_messages(
                prompt
            )
        )

        conclusion = response.content

        print(
            "FINAL:",
            conclusion,
        )

        return {
            "messages": [
                response
            ],

            "investigation_summary": {
                **summary,
                "conclusion": conclusion,
            },
        }

    # ========================================================
    # GRAPH
    # ========================================================

    builder = StateGraph(
        AgentState
    )

    builder.add_node(
        "agent",
        agent_node,
    )

    builder.add_node(
        "tools",
        tool_node,
    )

    builder.add_node(
        "investigation_decision",
        investigation_decision,
    )

    builder.add_node(
        "final_answer",
        final_answer,
    )

    builder.add_edge(
        START,
        "agent",
    )

    builder.add_conditional_edges(
        "agent",
        tools_condition,
        {
            "tools": "tools",
            END: "final_answer",
        },
    )

    builder.add_edge(
        "tools",
        "investigation_decision",
    )

    builder.add_conditional_edges(
        "investigation_decision",
        route_investigation,
        {
            "agent": "agent",
            "final_answer": "final_answer",
        },
    )

    builder.add_edge(
        "final_answer",
        END,
    )

    graph = builder.compile()

    # ========================================================
    # INITIAL STATE
    # ========================================================

    initial_state: AgentState = {
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": incident_text,
            },
        ],

        "investigation_status": "continue",

        "evidence": [],

        "used_tools": [],

        "tool_errors": [],

        "investigation_summary": {
            "observed_problem": (
                incident["description"]
            ),

            "failure_mechanism": "Unknown",

            "root_cause": "Unknown",

            "root_cause_evidence": None,

            "cause_established": False,

            "open_question": (
                DEFAULT_OPEN_QUESTION
            ),

            "guidance": "",
        },
    }

    result = await graph.ainvoke(
        initial_state,
        config={
            "recursion_limit": 20,
        },
    )

    return result


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        raise SystemExit(
            "Usage: python agent.py <incident_id>"
        )

    asyncio.run(
        run_investigation(
            sys.argv[1]
        )
    )