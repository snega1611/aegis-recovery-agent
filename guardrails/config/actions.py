from typing import Optional

from nemoguardrails.actions import action
from nemoguardrails.actions.rail_outcome import RailOutcome


@action(is_system_action=True)
async def aegis_sre_policy(context: Optional[dict] = None):
    context = context or {}

    cause_established = context.get("cause_established", False)
    root_cause_evidence_is_direct = context.get(
        "root_cause_evidence_is_direct", False
    )
    recommendation_supported = context.get(
        "recommendation_supported", False
    )

    if not cause_established:
        return RailOutcome.block(
            reason="Root cause has not been established."
        )

    if not root_cause_evidence_is_direct:
        return RailOutcome.block(
            reason="Root cause is not supported by direct evidence."
        )

    if not recommendation_supported:
        return RailOutcome.block(
            reason="Recommended resolution is not supported by the confirmed root cause."
        )

    return RailOutcome.allow(
        reason="Aegis SRE policy checks passed."
    )