import asyncio
import queue
import threading

import streamlit as st

from agent.agent import run_investigation


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="Aegis AI SRE",
    page_icon="🛡️",
    layout="wide",
)


# =========================================================
# STYLING
# =========================================================

st.markdown(
    """
    <style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }

    .aegis-header {
        padding-bottom: 1.5rem;
    }

    .status-online {
        display: inline-block;
        padding: 0.3rem 0.7rem;
        border-radius: 999px;
        font-size: 0.8rem;
        background: #e8f5e9;
        color: #2e7d32;
    }

    .incident-card {
        padding: 1rem;
        border: 1px solid #ddd;
        border-radius: 10px;
        margin-bottom: 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# HEADER
# =========================================================

st.markdown(
    """
    <div class="aegis-header">
        <h1>🛡️ Aegis AI SRE</h1>
        <span class="status-online">● System Online</span>
    </div>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# TOOL ACTIVITY TEXT
# =========================================================

def tool_activity(tool_name: str) -> str:
    """
    Convert an actual MCP tool name into a human-readable
    investigation activity.

    No individual tool needs to be added here.
    """

    if tool_name.startswith("prometheus_"):
        return "Checking Prometheus telemetry"

    if tool_name.startswith("logs_"):
        return "Checking application logs"

    if tool_name == "operations_list_containers":
        return "Checking Docker containers"

    if tool_name == "operations_inspect_container":
        return "Inspecting Docker container state"

    if tool_name == "operations_get_container_stats":
        return "Checking Docker container resources"

    if tool_name == "operations_get_container_logs":
        return "Checking Docker container logs"

    if tool_name == "operations_get_recent_commits":
        return "Checking recent Git changes"

    if tool_name == "operations_get_commit":
        return "Inspecting Git commit"

    if tool_name == "operations_get_commit_files":
        return "Checking changed files"

    if tool_name == "operations_get_commit_diff":
        return "Inspecting code changes"

    # Future MCP tools automatically fall back to this.
    readable = tool_name.replace("_", " ").strip()

    return f"Using {readable}"


# =========================================================
# BACKGROUND AGENT RUNNER
# =========================================================

def run_agent_in_background(
    incident_id,
    event_queue,
    result_holder,
):
    try:

        result = asyncio.run(
            run_investigation(
                incident_id,
                on_event=event_queue.put,
            )
        )

        result_holder["result"] = result

    except Exception as exc:

        result_holder["error"] = exc

    finally:

        event_queue.put(
            {
                "type": "finished"
            }
        )


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.header("Incidents")

    incident_id = st.text_input(
        "Incident ID",
        placeholder="INC-1010",
    )

    investigate = st.button(
        "🔍 Investigate incident",
        use_container_width=True,
        type="primary",
    )

    st.divider()

    st.caption("Aegis investigation sources")

    st.caption("• Prometheus telemetry")
    st.caption("• Application logs")
    st.caption("• Docker runtime evidence")
    st.caption("• Git history")
    st.caption("• RAG runbooks")
    st.caption("• SRE guardrails")


# =========================================================
# MAIN CHAT AREA
# =========================================================

st.subheader("AI SRE Assistant")


# ---------------------------------------------------------
# CHAT HISTORY
# ---------------------------------------------------------

if "messages" not in st.session_state:
    st.session_state.messages = []


for message in st.session_state.messages:

    with st.chat_message(message["role"]):

        st.markdown(message["content"])


# =========================================================
# START INVESTIGATION
# =========================================================

if investigate:

    incident_id = incident_id.strip()


    # -----------------------------------------------------
    # VALIDATE INCIDENT ID
    # -----------------------------------------------------

    if not incident_id:

        st.warning("Enter an incident ID first.")

    else:

        # -------------------------------------------------
        # USER MESSAGE
        # -------------------------------------------------

        user_message = (
            f"Check incident `{incident_id}`."
        )

        st.session_state.messages.append(
            {
                "role": "user",
                "content": user_message,
            }
        )

        with st.chat_message("user"):

            st.markdown(user_message)


        # -------------------------------------------------
        # ASSISTANT
        # -------------------------------------------------

        with st.chat_message("assistant"):

            event_queue = queue.Queue()

            result_holder = {}


            # ---------------------------------------------
            # START BACKGROUND THREAD
            # ---------------------------------------------

            thread = threading.Thread(
                target=run_agent_in_background,
                args=(
                    incident_id,
                    event_queue,
                    result_holder,
                ),
                daemon=True,
            )

            thread.start()


            # ---------------------------------------------
            # LIVE STATUS BOX
            # ---------------------------------------------

            status_box = st.status(
                "Aegis is investigating...",
                expanded=True,
            )


            # ---------------------------------------------
            # LIVE EVENTS
            # ---------------------------------------------

            while (
                thread.is_alive()
                or not event_queue.empty()
            ):

                try:

                    event = event_queue.get(
                        timeout=0.1
                    )

                    event_type = event.get("type")


                    # =====================================
                    # INCIDENT RECEIVED
                    # =====================================

                    if event_type == "incident_received":

                        received_id = event.get(
                            "incident_id",
                            incident_id,
                        )

                        description = event.get(
                            "description",
                            "",
                        )

                        severity = event.get(
                            "severity",
                            "",
                        )

                        status = event.get(
                            "status",
                            "",
                        )


                        status_box.write(
                            f"✓ **Incident received: {received_id}**"
                        )


                        if description:

                            status_box.write(
                                description
                            )


                        if severity or status:

                            details = []

                            if severity:
                                details.append(
                                    f"Severity: {severity.title()}"
                                )

                            if status:
                                details.append(
                                    f"Status: {status.title()}"
                                )

                            status_box.caption(
                                " • ".join(details)
                            )


                    # =====================================
                    # TOOL START
                    # =====================================

                    elif event_type == "tool_start":

                        tool_name = event.get(
                            "tool",
                            "unknown_tool",
                        )

                        activity = tool_activity(
                            tool_name
                        )

                        status_box.write(
                            f"🔍 **{activity}**"
                        )


                    # =====================================
                    # TOOL COMPLETE
                    # =====================================

                    elif event_type == "tool_complete":

                        tool_name = event.get(
                            "tool",
                            "unknown_tool",
                        )

                        activity = tool_activity(
                            tool_name
                        )

                        status_box.write(
                            f"✓ {activity} completed"
                        )


                    # =====================================
                    # FINISHED
                    # =====================================

                    elif event_type == "finished":

                        break


                except queue.Empty:

                    continue


            # =================================================
            # INVESTIGATION RESULT
            # =================================================

            if "error" in result_holder:

                status_box.update(
                    label="Investigation failed",
                    state="error",
                    expanded=True,
                )

                st.error(
                    str(result_holder["error"])
                )


            elif "result" in result_holder:

                status_box.update(
                    label="Investigation completed",
                    state="complete",
                    expanded=False,
                )

                result = result_holder["result"]


                # ---------------------------------------------
                # GET SUMMARY
                # ---------------------------------------------

                summary = result.get(
                    "investigation_summary",
                    {},
                )

                conclusion = summary.get(
                    "conclusion"
                )


                # ---------------------------------------------
                # FALLBACK TO FINAL MESSAGE
                # ---------------------------------------------

                if not conclusion:

                    messages = result.get(
                        "messages",
                        [],
                    )

                    if messages:

                        conclusion = (
                            messages[-1].content
                        )


                # ---------------------------------------------
                # EMPTY RESULT
                # ---------------------------------------------

                if not conclusion:

                    conclusion = (
                        "Aegis did not produce "
                        "a final conclusion."
                    )


                # ---------------------------------------------
                # DISPLAY FINAL RCA
                # ---------------------------------------------

                st.markdown(conclusion)


                # ---------------------------------------------
                # SAVE TO CHAT
                # ---------------------------------------------

                st.session_state.messages.append(
                    {
                        "role": "assistant",
                        "content": conclusion,
                    }
                )


            else:

                status_box.update(
                    label="Investigation ended without a result",
                    state="error",
                    expanded=True,
                )

                st.error(
                    "Aegis did not return an investigation result."
                )