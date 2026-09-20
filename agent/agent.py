import asyncio
import json
import operator
import re
from datetime import datetime, timezone
from typing import Annotated, TypedDict

import httpx
from langchain_core.messages import AIMessage
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.types import Command

from agent.mcp_client import create_mcp_adapter
from rag.vectorstore import load_vector_store
from rag.retriever import create_knowledge_tool


# =====================================================================
# State (unchanged)
# =====================================================================

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    investigation_status: str
    evidence: Annotated[list, operator.add]
    used_tools: Annotated[list, operator.add]   # now holds "tool(args)" signatures
    investigation_summary: dict                 # holds {"open_question": ...} during the run


# =====================================================================
# Prompts
# =====================================================================

INITIAL_PROMPT = """
Investigate this incident:\n{incident_text}
- Do not infer a metric from a log search query.
- For each observation, use the actual fields and values returned by that tool.
- Never attribute a value to a tool that did not return that value.
"""

SYSTEM_PROMPT = """You are Aegis, an SRE incident-investigation assistant.
You only state facts that appear in tool results.
Never invent data, causes, or fixes.
An incident report describes the past. A tool result describes only the moment or period given by its time_scope.
Results from documentation or knowledge lookups are general guidance, not measurements of this incident."""

DEFAULT_OPEN_QUESTION = (
    "Nothing has been checked yet. "
    "What is the most useful first thing to check for this incident?"
)

# placeholders: {incident} {tried} {evidence} {open_question}
AGENT_PROMPT = """INCIDENT
{incident}

CALLS ALREADY MADE
{tried}

EVIDENCE SO FAR
{evidence}

OPEN QUESTION
{open_question}

YOUR TASK
Call exactly ONE tool that gives NEW information about the open question.

Rules:
- Choose by reading what each tool does. Do not pick a tool because it worked before.
- NEW means a tool not used yet, or the same tool with different arguments. Never repeat a call listed under CALLS ALREADY MADE.
- Use specific arguments taken from the incident or the evidence (service name, alert name, error text, time range). Do not use broad words that match almost everything.
- Do not explain, guess, or summarize. Do not state a cause.
- If EVIDENCE SO FAR is "(none)", you must call a tool.
- Otherwise, if no tool can give new information, reply with exactly: NO_NEW_EVIDENCE"""

# placeholders: {incident} {tool_catalog} {tried} {evidence}
DECISION_PROMPT = """INCIDENT
{incident}

TOOLS AVAILABLE
{tool_catalog}

CALLS ALREADY MADE
{tried}

EVIDENCE SO FAR
{evidence}

YOUR TASK
Decide if the investigation should continue.

First, name the most important question about this incident that the evidence above does not answer yet. Write "none" if the evidence answers what it can.

Then choose:
- continue: a tool in TOOLS AVAILABLE could answer that question with NEW information (a tool not used yet, or the same tool with different arguments).
- finish: the question is "none", OR no available tool can answer it, OR the only option would repeat a call already made.

Rules:
- Not knowing the root cause is acceptable. Choose finish if no tool can help find it.
- Do not count tools. Do not require every tool to be used.
- Check each measurement's time_scope. A current value does not describe the past. A historical value does not describe now.
- Do not assume evidence that is not listed.

Answer in exactly this format and nothing else:
Open question: <one sentence, or none>
Decision: <continue or finish>"""

# placeholders: {incident} {tried} {evidence}
FINAL_PROMPT = """INCIDENT
{incident}

CALLS MADE
{tried}

EVIDENCE
{evidence}

YOUR TASK
Write the investigation report using ONLY the evidence above.

Use exactly these five sections:

1. Incident
One or two sentences restating the reported incident. Use the severity exactly as given.

2. Observations
One bullet per evidence item: what was measured or found, the value and unit copied exactly, and its time_scope. Guidance or documentation results are not observations. List them under "Reference guidance" only if they help, and never treat them as findings.

3. Current state
Say whether the evidence shows the condition is active now. If no evidence with a current time_scope covers it, write: "Current state not determined."

4. Root cause
Write "Confirmed: <cause>" only if an observation directly states or shows that cause. Otherwise write exactly: "Root cause not confirmed." Do not list possible causes.

5. Gaps
List information that is still missing, phrased as data to collect (not as causes). Write "None" if nothing is missing.

Rules:
- Copy numbers exactly. Do not round, rescale, or convert them.
- A measurement shows what a value is, not why. Do not explain why unless an observation states the reason.
- Do not say the incident is resolved unless the evidence shows it.
- Do not add facts that are not in EVIDENCE.
- Do not call tools."""


# =====================================================================
# Helpers (pure functions, no decisions)
# =====================================================================

THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)
MAX_RESULT_CHARS = 600   # per evidence item shown to the model; raise if your ctx allows


def validate_evidence(evidence: list) -> dict:
    """Unchanged. Groups evidence by evidence_type. Useful for logging only."""
    evidence_by_type = {}

    for item in evidence:
        result = item.get("result", {})

        if not isinstance(result, dict):
            continue

        evidence_type = result.get("evidence_type")

        if not evidence_type:
            continue

        evidence_by_type.setdefault(evidence_type, []).append(item)

    return {
        "available_types": list(evidence_by_type.keys()),
        "evidence_by_type": evidence_by_type,
    }


def call_signature(name: str, args: dict) -> str:
    return f"{name}({json.dumps(args, sort_keys=True, default=str)})"


def format_incident(incident: dict) -> str:
    return "\n".join(f"{key}: {value}" for key, value in incident.items())


def format_tried(used_tools: list) -> str:
    return "\n".join(f"- {sig}" for sig in used_tools) or "(none)"


def format_evidence(evidence: list) -> str:
    """One compact line per evidence item. Used by every prompt so the
    evidence appears exactly once and in the same form everywhere."""
    if not evidence:
        return "(none)"

    lines = []
    for index, item in enumerate(evidence, start=1):
        result = item["result"]
        text = result if isinstance(result, str) else json.dumps(result, default=str)
        if len(text) > MAX_RESULT_CHARS:
            text = text[:MAX_RESULT_CHARS] + "...[truncated]"
        lines.append(f"[{index}] {item['call']} -> {text}")
    return "\n".join(lines)


def first_line(text: str, limit: int = 150) -> str:
    lines = (text or "").strip().splitlines()
    return lines[0][:limit] if lines else ""


def allowed_arg_names(tool):
    schema = tool.args_schema
    if isinstance(schema, dict):
        return set(schema.get("properties", {}))
    if schema is not None and hasattr(schema, "model_fields"):
        return set(schema.model_fields)
    return None   # unknown schema: do not filter


def clean_args(tool, args):
    """Repair typical small-model mistakes in tool arguments."""
    if not isinstance(args, dict):
        return {}

    allowed = allowed_arg_names(tool)
    if allowed is not None:
        args = {k: v for k, v in args.items() if k in allowed}

    # {"query": {"type": "string", "value": "x"}}  ->  {"query": "x"}
    return {
        k: (v["value"] if isinstance(v, dict) and "value" in v else v)
        for k, v in args.items()
    }


def normalize_tool_call(response, tools_by_name):
    """Keep at most ONE tool call, with cleaned args.
    Returns (response, signature or None)."""
    calls = getattr(response, "tool_calls", None) or []
    if not calls:
        return response, None

    call = calls[0]
    tool = tools_by_name.get(call["name"])

    if tool is None:                      # model invented a tool name
        response.tool_calls = []
        return response, None

    call["args"] = clean_args(tool, call.get("args"))
    response.tool_calls = [call]
    return response, call_signature(call["name"], call["args"])


# =====================================================================
# Main
# =====================================================================

async def main():

    incident_id = "ce70afdc-69c3-4c39-95ef-3ed71c31ce2b"

    response = httpx.get(f"http://localhost:8000/incidents/{incident_id}")
    response.raise_for_status()
    incident = response.json()

    print("🚨 INCIDENT RECEIVED BY AEGIS:")
    print(incident)

    # -----------------------------
    # Tools
    # -----------------------------

    adapter = create_mcp_adapter()
    tools = await adapter.list_tools()

    vector_store = load_vector_store()
    tools.append(create_knowledge_tool(vector_store))

    print("Tools available:")
    for tool in tools:
        print("-", tool.name)

    tools_by_name = {t.name: t for t in tools}
    tool_catalog = "\n".join(
        f"- {t.name}: {first_line(t.description)}" for t in tools
    )
    incident_text = format_incident(incident)

    # -----------------------------
    # LLM
    # -----------------------------
    # num_ctx=1024 was too small: system prompt + tool schemas + evidence
    # overflowed and Ollama silently dropped the START of the prompt.
    # reasoning=False stops Qwen3 from emitting <think> blocks
    # (needs a recent langchain-ollama and Ollama >= 0.9;
    # otherwise append /no_think to the prompts).

    llm = ChatOllama(
        model="qwen3:1.7b",
        temperature=0,
        num_ctx=4096,
        reasoning=False,
    )
    llm_with_tools = llm.bind_tools(tools)

    def build_messages(task_prompt: str) -> list:
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": task_prompt},
        ]

    # -----------------------------
    # Agent node
    # -----------------------------
    # Stateless view: the model sees the incident, what was tried, the
    # evidence and the open question. It does NOT see the raw message
    # history, so evidence is not duplicated and context stays small.

    async def agent_node(state: AgentState):

        open_question = (
            state.get("investigation_summary", {}).get("open_question")
            or DEFAULT_OPEN_QUESTION
        )

        messages = build_messages(
            AGENT_PROMPT.format(
                incident=incident_text,
                tried=format_tried(state["used_tools"]),
                evidence=format_evidence(state["evidence"]),
                open_question=open_question,
            )
        )

        response = await llm_with_tools.ainvoke(messages)
        response, signature = normalize_tool_call(response, tools_by_name)

        # Exact repeat of an earlier call: retry ONCE with that tool removed.
        if signature and signature in state["used_tools"]:
            repeated = response.tool_calls[0]["name"]
            remaining = [t for t in tools if t.name != repeated]

            if remaining:
                retry = await llm.bind_tools(remaining).ainvoke(messages)
                response, signature = normalize_tool_call(retry, tools_by_name)

            if not remaining or (signature and signature in state["used_tools"]):
                response = AIMessage(content="NO_NEW_EVIDENCE")

        print("🤖 AGENT:", response.tool_calls or response.content)

        return {"messages": [response]}

    # -----------------------------
    # Tool node
    # -----------------------------

    async def capture_tool_result(request, execute):
        name = request.tool_call["name"]
        args = request.tool_call.get("args", {})

        print("🔧 TOOL CALL:", request.tool_call)

        result = await execute(request)

        artifact = getattr(result, "artifact", None)
        if isinstance(artifact, dict) and "structured_content" in artifact:
            tool_result = artifact["structured_content"]
        else:
            tool_result = result.content

        signature = call_signature(name, args)

        evidence_item = {
            "tool": name,
            "args": args,
            "call": signature,
            "result": tool_result,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }

        print("📋 EVIDENCE STORED:", evidence_item)

        return Command(
            update={
                "messages": [result],
                "evidence": [evidence_item],
                "used_tools": [signature],
            }
        )

    tool_node = ToolNode(tools, awrap_tool_call=capture_tool_result)

    # -----------------------------
    # Decision node
    # -----------------------------

    async def investigation_decision(state: AgentState):

        print("🔎 EVIDENCE TYPES:", validate_evidence(state["evidence"])["available_types"])

        response = await llm.ainvoke(
            build_messages(
                DECISION_PROMPT.format(
                    incident=incident_text,
                    tool_catalog=tool_catalog,
                    tried=format_tried(state["used_tools"]),
                    evidence=format_evidence(state["evidence"]),
                )
            )
        )

        raw = THINK_RE.sub("", response.content).strip()

        match = re.search(r"decision:\s*(continue|finish)", raw, re.IGNORECASE)
        decision = match.group(1).lower() if match else "finish"

        match = re.search(r"open question:\s*(.+)", raw, re.IGNORECASE)
        open_question = match.group(1).strip() if match else ""

        # Consistency only: "nothing left to ask" cannot mean "continue".
        if open_question.lower().strip(" .") == "none":
            decision = "finish"

        print("INVESTIGATION DECISION:", decision, "| open question:", open_question)

        return {
            "investigation_status": decision,
            "investigation_summary": {"open_question": open_question},
        }

    def route_investigation(state: AgentState):
        if state["investigation_status"] == "continue":
            return "agent"
        return "final_answer"

    # -----------------------------
    # Final answer
    # -----------------------------

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

        conclusion = THINK_RE.sub("", response.content).strip()

        print("INVESTIGATION CONCLUSION:", conclusion)
        
        print("📊 INVESTIGATION SUMMARY:", {
            "status": "investigation_complete",
            "conclusion": conclusion,
            "evidence_count": len(state["evidence"]),
            "tools_used": len(state["used_tools"]),
        })

        return {
            "messages": [AIMessage(content=conclusion)],
            "investigation_summary": {
                "status": "investigation_complete",
                "conclusion": conclusion,
                "evidence": state["evidence"],
                "used_tools": state["used_tools"],
            },
        }

    # -----------------------------
    # Graph
    # -----------------------------

    graph_builder = StateGraph(AgentState)

    graph_builder.add_node("agent", agent_node)
    graph_builder.add_node("tools", tool_node)
    graph_builder.add_node("investigation_decision", investigation_decision)
    graph_builder.add_node("final_answer", final_answer)

    graph_builder.add_edge(START, "agent")

    # No tool call from the agent means "nothing new to collect" -> report.
    # (Before, this went to the decision node, which could say "continue"
    # and loop back to an agent that had just declined to call a tool.)
    graph_builder.add_conditional_edges(
        "agent",
        tools_condition,
        {"tools": "tools", END: "final_answer"},
    )

    graph_builder.add_edge("tools", "investigation_decision")

    graph_builder.add_conditional_edges(
        "investigation_decision",
        route_investigation,
        {"agent": "agent", "final_answer": "final_answer"},
    )

    graph_builder.add_edge("final_answer", END)

    graph = graph_builder.compile()

    # -----------------------------
    # Start investigation
    # -----------------------------

    initial_state = {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": INITIAL_PROMPT},
        ],
        "investigation_status": "continue",   # was "finish": told the first turn not to call tools
        "evidence": [],
        "used_tools": [],
        "investigation_summary": {},
    }

    # recursion_limit is only a safety net against runaway loops.
    result = await graph.ainvoke(initial_state, config={"recursion_limit": 20})

    print("FINAL EVIDENCE:")
    print(result["evidence"])

    print("\n========== Final conversation ==========")
    for message in result["messages"]:
        print("\n", message)


if __name__ == "__main__":
    asyncio.run(main())