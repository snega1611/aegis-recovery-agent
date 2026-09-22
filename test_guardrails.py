import asyncio

from guardrails.config.actions import aegis_sre_policy


async def main():
    result = await aegis_sre_policy(
        cause_established=True,
        root_cause_evidence_is_direct=True,
        recommendation_supported=True,
    )

    print("TEST 1:", result.decision, result.reason)

    result = await aegis_sre_policy(
        cause_established=False,
        root_cause_evidence_is_direct=False,
        recommendation_supported=False,
    )

    print("TEST 2:", result.decision, result.reason)


asyncio.run(main())