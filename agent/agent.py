import asyncio
import json
import operator
import os
import re
import sys
from datetime import datetime, timezone
from typing import Annotated, TypedDict
import psycopg2

import httpx
from langchain_core.messages import AIMessage
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.types import Command

from agent.mcp_client import create_mcp_adapter
from rag.vectorstore import load_vector_store


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    investigation_status: str
    evidence: Annotated[list, operator.add]
    used_tools: Annotated[list, operator.add]
    tool_errors: Annotated[list, operator.add]
    investigation_summary: dict


SYSTEM_PROMPT = """You are Aegis, an SRE incident-investigation assistant.
You only state facts that appear in tool results.
Never invent data, causes, or fixes.
An incident report describes the past. A tool result describes only the moment or period given by its time_scope.
Runbook guidance is general advice, not a measurement of this incident."""

DEFAULT_OPEN_QUESTION = (
    "Nothing has been checked yet. "
    "What is the most useful first thing to check for this incident?"
)

# placeholders: {incident} {tried} {evidence} {open_question} {guidance}
AGENT_PROMPT = """INCIDENT
{incident}

CALLS ALREADY MADE
{tried}

EVIDENCE SO FAR
{evidence}

OPEN QUESTION
{open_question}

RUNBOOK GUIDANCE (general advice, NOT evidence about this incident)
{guidance}

YOUR TASK
Call exactly ONE tool that answers the open question with NEW information.

Rules:
- Use the newest evidence and the guidance to choose the tool that follows up on it.
- Read the tool descriptions. If one says to use a different tool in the current situation, use that one.
- If EVIDENCE SO FAR is "(none)", choose the tool that best shows whether the reported problem is happening right now.
- Two tools that answer the same question are duplicates. Never call both.
- NEW means a different tool, or the same tool with different arguments. Never repeat a call under CALLS ALREADY MADE.
- Take arguments from the incident or the evidence. A service name from the incident can be used where a container name is needed. If you are unsure of a name, call the tool that lists names first.


- GIT RULES:
  - Never call operations_get_commit unless EVIDENCE SO FAR contains a valid hexadecimal commit hash returned by operations_get_recent_commits.
  - If no valid commit hash is available, call operations_get_recent_commits first.
  - Never use a service name, container name, incident name, or commit message as the commit argument.
  - Never invent a commit hash.
  - Never call operations_get_commit_files unless a valid commit hash has already been returned by operations_get_recent_commits.
  - A commit can only be considered a possible cause if its commit date is before the incident started_at time.
  - Ignore commits made after the incident started_at time when investigating the cause. Do not call get_commit or get_commit_files for a post-incident commit.
  
- Confirming that a problem exists does not explain it. Once it is confirmed, choose a tool that shows why.
- When a component is down or failing, examine the component itself (its runtime state, exit information, its own logs) before unrelated metrics or logs elsewhere.
- Do not explain, guess, or state a cause.
- If EVIDENCE SO FAR is not "(none)" and no tool can give new information, reply with exactly: NO_NEW_EVIDENCE
- Never invent an identifier (a commit hash, container ID, file path). Only use one that
  appears verbatim in the incident text or in an earlier evidence item.
  """


# placeholders: {incident} {tool_catalog} {tried} {evidence} {guidance}
DECISION_PROMPT = """You are deciding whether an SRE incident investigation should continue.

INCIDENT
{incident}

EVIDENCE SO FAR
{evidence}

NEWEST EVIDENCE
{newest_evidence}

TOOLS AVAILABLE
{tool_catalog}

Review the evidence as a whole.

Separate:
- WHAT: what problem is occurring.
- FAILURE MECHANISM: what directly explains how the affected component is failing.
- ROOT CAUSE: what explains why that failure mechanism exists or was introduced.

A failure mechanism is not automatically the root cause.

Reasoning rules:

- Consider all collected evidence before deciding.
- Do not treat a symptom as its own cause.
- When multiple pieces of evidence describe the same incident, determine whether one
  provides a more direct explanation of the affected component's failure.
- Prefer evidence that directly describes the affected component or its failure mechanism
  over evidence that only observes the effect from another component or monitoring system.
- If the evidence establishes only the failure mechanism, do NOT mark the root cause as established.
- Continue investigating when evidence is still needed to explain why the failure mechanism exists or was introduced.
- Mark the root cause as established only when the evidence directly establishes it.
- A newer observation does not invalidate an earlier, stronger piece of evidence.
- If the cause is not established, identify one specific unanswered question that an
  available tool can answer.
- Never ask a question that the evidence already answers.
- Respect the time scope of each piece of evidence.
- Do not invent causes or conclusions.
- Each evidence item is labeled with a category: symptom (observed from outside, e.g. a
  monitor or scrape), direct (from the affected component's own state/logs/exit info),
  context (historical, e.g. commits), or invalid (a tool call itself failed — this is
  NOT evidence about the incident, only proof a tool call did not succeed).
- Never cite an "invalid" item as Known or as Cause established. If the newest evidence
  is invalid, pick a different tool next.
- Once a "direct" item shows the mechanism behind the reported problem (an exception, a
  crash, a non-running state, resource exhaustion, etc.), that satisfies WHY for this
  investigation. Do not keep asking what caused THAT (e.g. which commit or config caused
  it) — that is a remediation-phase question, not part of confirming why the component
  is currently failing.

Answer exactly:

Known: <what the evidence establishes, citing evidence numbers>
Cause established: <yes [n] or no>
If you answer "yes", [n] MUST identify the evidence item that directly establishes
the ROOT CAUSE, not merely the failure mechanism.
Open question: <one specific unanswered question, citing evidence, or none>
"""

# placeholders: {incident} {tried} {evidence}
FINAL_PROMPT = """INCIDENT
{incident}

CALLS MADE
{tried}

EVIDENCE
{evidence}

YOUR TASK
Write the analysis using ONLY the evidence above. The evidence list is shown to the reader separately, so do not copy it. Refer to items by number, like [2].

Use exactly these four sections:

1. Incident
One or two sentences restating the reported incident, with the severity exactly as given. Add nothing else.

2. Current state
One sentence saying what the items whose time_scope starts with "current" show about the reported problem. Use an item's "finding" or "note" if it has one. If no item has such a time_scope, write: "No current-scope evidence."

3. Root cause
Write "Confirmed: <cause> [n]" only if an item directly states or shows that cause. Otherwise write exactly: "Root cause not confirmed." Do not list possible causes.

4. Gaps
What is still unknown, as data to collect (not causes). If the root cause is not confirmed, say what evidence would establish it. Never write "None" in that case.

Rules:
- Say what a value shows only as the tool returned it. Never attribute a value to a tool that did not return it.
- A "finding" or "note" field is the tool's own statement of what its result means. Use it as written.
- A tool call or search query is not evidence. Only its result is.
- A measurement shows what a value is, not why.
- Do not say the incident is resolved unless the evidence shows it.
- Do not add facts that are not in EVIDENCE.
- An evidence item marked invalid is a tool-call failure, not incident data. You may note
  that the tool call failed; never use it to support Current state or Root cause.
  """


THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)
MAX_TOOL_CALLS = 8
GUIDANCE_K = 3
GUIDANCE_CHARS = 400


def validate_evidence(evidence: list) -> dict:
    evidence_by_type = {}
    for item in evidence:
        result = item.get("result", {})
        if not isinstance(result, dict):
            continue
        evidence_type = result.get("evidence_type")
        if not evidence_type:
            continue
        evidence_by_type.setdefault(evidence_type, []).append(item)
    return {"available_types": list(evidence_by_type.keys()), "evidence_by_type": evidence_by_type}


def call_signature(name: str, args: dict) -> str:
    return f"{name}({json.dumps(args, sort_keys=True, default=str)})"


def format_incident(incident: dict) -> str:
    return "\n".join(f"{key}: {value}" for key, value in incident.items())


def format_tried(used_tools: list) -> str:
    return "\n".join(f"- {sig}" for sig in used_tools) or "(none)"


MAX_LIST_ITEMS = 6
MAX_ITEM_CHARS = 160

# Generic classification of what a tool's evidence represents — not tied to any
# specific incident or error type. Add new tools here as they're added.
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
}

def evidence_category(tool_name: str, result) -> str:
    if isinstance(result, dict) and result.get("status") == "error":
        return "invalid"  # a tool-call failure, not evidence about the incident
    return TOOL_CATEGORY.get(tool_name, "symptom")

def compact(result):
    if not isinstance(result, dict):
        return str(result)[:MAX_ITEM_CHARS]
    parts = []
    for key, value in result.items():
        if key in ("evidence_type", "observed_at"):
            continue
        if key == "status" and value == "ok":
            continue
        if isinstance(value, list):
            shown = [str(v)[:MAX_ITEM_CHARS] for v in value[-MAX_LIST_ITEMS:]]
            earlier = len(value) - len(shown)
            value = "[" + " | ".join(shown) + "]" + (f" (+{earlier} earlier)" if earlier else "")
        elif isinstance(value, dict):
            value = json.dumps(value)
        parts.append(f"{key}={value}")
    return ", ".join(parts)

def format_evidence(evidence: list) -> str:
    if not evidence:
        return "(none)"
    return "\n".join(
        f"[{i}] ({item.get('category', 'symptom')}) {item['call']} -> {compact(item['result'])}"
        for i, item in enumerate(evidence, start=1)
    )


def first_line(text: str, limit: int = 320) -> str:
    lines = (text or "").strip().splitlines()
    return lines[0][:limit] if lines else ""


def allowed_arg_names(tool):
    schema = tool.args_schema
    if isinstance(schema, dict):
        return set(schema.get("properties", {}))
    if schema is not None and hasattr(schema, "model_fields"):
        return set(schema.model_fields)
    return None


def available_tools(tools, used_tools):
    """Hide zero-argument tools that were already called: repeating them can never add evidence."""
    return [
        t for t in tools
        if not (allowed_arg_names(t) == set() and call_signature(t.name, {}) in used_tools)
    ]


def format_catalog(tools) -> str:
    return "\n".join(f"- {t.name}: {first_line(t.description)}" for t in tools)


async def retrieve_guidance(vector_store, query: str) -> str:
    """Runbook chunks for the query. Deterministic retrieval, no LLM call."""
    try:
        docs = await asyncio.to_thread(vector_store.similarity_search, query[:500], k=GUIDANCE_K)
    except Exception as exc:
        return f"(guidance unavailable: {exc})"
    chunks = [f"- {' '.join(d.page_content.split())[:GUIDANCE_CHARS]}" for d in docs]
    return "\n".join(chunks) or "(no guidance found)"


def clean_args(tool, args):
    if not isinstance(args, dict):
        return {}
    allowed = allowed_arg_names(tool)
    if allowed is not None:
        args = {k: v for k, v in args.items() if k in allowed}
    return {k: (v["value"] if isinstance(v, dict) and "value" in v else v) for k, v in args.items()}

def validate_tool_args(tool, args: dict) -> bool:
    """True if args satisfy the tool's own schema. Catches type-shape mistakes
    like passing a JSON-schema fragment ({'type': 'string'}) instead of a value."""
    schema = tool.args_schema
    try:
        if schema is not None and hasattr(schema, "model_validate"):
            schema.model_validate(args)
            return True
        if isinstance(schema, dict):
            return all(k in args for k in schema.get("required", []))
        return True
    except Exception:
        return False


def normalize_tool_call(response, tools_by_name):
    calls = getattr(response, "tool_calls", None) or []
    if not calls:
        return response, None
    call = calls[0]
    tool = tools_by_name.get(call["name"])
    if tool is None:
        response.tool_calls = []
        return response, None
    call["args"] = clean_args(tool, call.get("args"))
    response.tool_calls = [call]
    return response, call_signature(call["name"], call["args"])


async def main():

    incident_id = sys.argv[1] if len(sys.argv) > 1 else "INC-1003"

    conn = psycopg2.connect(host="localhost", port=5433, database="aegis", user="postgres", password="postgres")
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
    cursor.close()
    conn.close()

    if row is None:
        raise RuntimeError(f"Incident {incident_id} not found")

    incident = {
        "incident_id": row[0], "alert_name": row[1], "incident_type": row[2], "severity": row[3],
        "service": row[4], "status": row[5], "started_at": row[6], "description": row[7],
    }

    print("INCIDENT RECEIVED BY AEGIS:")
    print(incident)

    adapter = create_mcp_adapter()
    tools = await adapter.list_tools()

    vector_store = load_vector_store()

    print("Tools available:", [t.name for t in tools])

    tools_by_name = {t.name: t for t in tools}
    incident_text = format_incident(incident)
    # Text used to look up runbooks: the descriptive fields only (no ids or timestamps).
    incident_query = " ".join(str(v) for k, v in incident.items() if k not in ("incident_id", "started_at"))

    llm = ChatOllama(
        model=os.getenv("AEGIS_MODEL", "qwen3:1.7b"),
        temperature=0,
        num_ctx=8192,
        reasoning=False,
    )

    def build_messages(task_prompt: str) -> list:
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": task_prompt},
        ]

    def guidance_query(state: AgentState) -> str:
        latest = compact(state["evidence"][-1]["result"]) if state["evidence"] else ""
        return f"{incident_query[:250]} | {latest[:250]}"

    async def agent_node(state: AgentState):

        summary = state.get("investigation_summary", {})
        open_question = summary.get("open_question") or DEFAULT_OPEN_QUESTION
        guidance = summary.get("guidance") or await retrieve_guidance(vector_store, incident_query)

        usable = available_tools(tools, state["used_tools"])
        if not usable:
            return {"messages": [AIMessage(content="NO_NEW_EVIDENCE")]}

        messages = build_messages(
            AGENT_PROMPT.format(
                incident=incident_text,
                tried=format_tried(state["used_tools"]),
                evidence=format_evidence(state["evidence"]),
                open_question=open_question,
                guidance=guidance,
            )
        )

        response = await llm.bind_tools(usable).ainvoke(messages)
        response, signature = normalize_tool_call(response, tools_by_name)

        # The model sometimes returns nothing at all (no tool call, no text): retry once.
        if not response.tool_calls and not (response.content or "").strip():
            response = await llm.bind_tools(usable).ainvoke(messages)
            response, signature = normalize_tool_call(response, tools_by_name)

        def _bad_call(resp):
            if not resp.tool_calls:
                return False
            call = resp.tool_calls[0]
            tool = tools_by_name.get(call["name"])
            return tool is not None and not validate_tool_args(tool, call["args"])

        # Exact repeat of an earlier call, OR args that don't satisfy the tool's own
        # schema: retry ONCE with that tool removed (temp=0 means retrying with the
        # same tool set would just reproduce the same output).
        if signature and (signature in state["used_tools"] or _bad_call(response)):
            offending = response.tool_calls[0]["name"]
            remaining = [t for t in usable if t.name != offending]

            if remaining:
                retry = await llm.bind_tools(remaining).ainvoke(messages)
                response, signature = normalize_tool_call(retry, tools_by_name)

            if not remaining or (signature and (signature in state["used_tools"] or _bad_call(response))):
                response = AIMessage(content="NO_NEW_EVIDENCE")

        print("AGENT:", response.tool_calls or response.content)

        return {"messages": [response]}

    async def capture_tool_result(request, execute):
        name = request.tool_call["name"]
        args = request.tool_call.get("args", {})
        print("TOOL CALL:", request.tool_call)

        result = await execute(request)

        artifact = getattr(result, "artifact", None)
        if isinstance(artifact, dict) and "structured_content" in artifact:
            tool_result = artifact["structured_content"]
        else:
            tool_result = result.content

        signature = call_signature(name, args)

        item = {
            "tool": name,
            "args": args,
            "call": signature,
            "result": tool_result,
            "category": evidence_category(name, tool_result),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }

        # Tool failures are NOT incident evidence.
        if isinstance(tool_result, dict) and tool_result.get("status") == "error":
            print("TOOL ERROR:", item)

            return Command(
                update={
                    "messages": [result],
                    "tool_errors": [item],
                    "used_tools": [signature],
                }
            )

        # Successful tool results are incident evidence.
        print("EVIDENCE STORED:", item)

        return Command(
            update={
                "messages": [result],
                "evidence": [item],
                "used_tools": [signature],
            }
        )


    tool_node = ToolNode(
        tools,
        awrap_tool_call=capture_tool_result,
    )

    async def investigation_decision(state: AgentState):

        guidance = await retrieve_guidance(vector_store, guidance_query(state))
        
        newest_evidence = (
            f"[{len(state['evidence'])}] {compact(state['evidence'][-1]['result'])}"
            if state["evidence"] else "(none)"
        )

        response = await llm.ainvoke(
            build_messages(
                DECISION_PROMPT.format(
                    incident=incident_text,
                    tool_catalog=format_catalog(available_tools(tools, state["used_tools"])),
                    tried=format_tried(state["used_tools"]),
                    evidence=format_evidence(state["evidence"]),
                    newest_evidence=newest_evidence,
                    guidance=guidance,
                )
            )
        )

        raw = THINK_RE.sub("", response.content).strip()

        print("DECISION RAW:", raw)

        match = re.search(
            r"cause established:\s*yes\s*\[(\d+)\]",
            raw,
            re.IGNORECASE,
        )

        cited_idx = int(match.group(1)) if match else None

        cited_item = (
            state["evidence"][cited_idx - 1]
            if cited_idx and 1 <= cited_idx <= len(state["evidence"])
            else None
        )

        cause_established = (
            cited_item is not None
            and cited_item.get("category") == "direct"
        )

        match = re.search(
            r"open question:\s*(.+)",
            raw,
            re.IGNORECASE,
        )

        open_question = match.group(1).strip() if match else ""

        nothing_left = open_question.lower().strip(" .") == "none"

        decision = "finish" if (cause_established or nothing_left) else "continue"

        print(
            "INVESTIGATION DECISION:",
            decision,
            "| cause established:",
            cause_established,
            "| open question:",
            open_question,
        )

        return {
            "investigation_status": decision,
            "investigation_summary": {
                "open_question": open_question or "Why did the reported problem happen?",
                "guidance": guidance,
            },
        }

    def route_investigation(state: AgentState):
        if state["investigation_status"] == "continue" and len(state["used_tools"]) < MAX_TOOL_CALLS:
            return "agent"
        return "final_answer"

    async def final_answer(state: AgentState):

        response = await llm.ainvoke(
            build_messages(
                FINAL_PROMPT.format(
                    incident=incident_text,
                    tried=format_tried(state["used_tools"]),
                    evidence=format_evidence(state["evidence"]),
                )
            )
        )

        analysis = THINK_RE.sub("", response.content).strip()
        conclusion = "OBSERVATIONS (from tool results)\n" + format_evidence(state["evidence"]) + "\n\nANALYSIS\n" + analysis

        print("INVESTIGATION CONCLUSION:", conclusion)

        return {
            "messages": [AIMessage(content=conclusion)],
            "investigation_summary": {
                "status": "investigation_complete", "conclusion": conclusion,
                "evidence": state["evidence"], "used_tools": state["used_tools"],
            },
        }

    graph_builder = StateGraph(AgentState)
    graph_builder.add_node("agent", agent_node)
    graph_builder.add_node("tools", tool_node)
    graph_builder.add_node("investigation_decision", investigation_decision)
    graph_builder.add_node("final_answer", final_answer)
    graph_builder.add_edge(START, "agent")
    graph_builder.add_conditional_edges("agent", tools_condition, {"tools": "tools", END: "final_answer"})
    graph_builder.add_edge("tools", "investigation_decision")
    graph_builder.add_conditional_edges("investigation_decision", route_investigation, {"agent": "agent", "final_answer": "final_answer"})
    graph_builder.add_edge("final_answer", END)
    graph = graph_builder.compile()

    initial_state = {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Investigate this incident:\n{incident_text}"},
        ],
        "investigation_status": "continue",
        "evidence": [],
        "used_tools": [],
        "tool_errors": [],
        "investigation_summary": {},
    }

    # recursion_limit is only a safety net against runaway loops.
    result = await graph.ainvoke(initial_state, config={"recursion_limit": 20})

    print("FINAL EVIDENCE:")
    print(result["evidence"])

    print("\n========== Final conversation ==========")
    for message in result["messages"]:
        print("\n", message)

    return result


if __name__ == "__main__":
    asyncio.run(main())