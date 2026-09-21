# Software Changes and Reliability

## Changes as Operational Evidence

Software, configuration, dependency, and deployment changes can affect service reliability.

Relevant changes may include:

- application code
- configuration
- dependencies
- environment configuration
- container images
- startup commands
- infrastructure configuration

A change is evidence of something that changed.

It is not automatically the cause of an incident.

## Temporal Relationship

When investigating a failure, compare:

- incident start time
- deployment or change time
- application failure time
- container start and exit times

A change occurring before an incident can be relevant.

Temporal proximity alone does not prove causation.

## Commit History

Recent commits can provide context about what changed before an incident.

Useful information includes:

- commit timestamp
- commit message
- author
- changed files
- relevant code changes

A recent commit should be treated as a hypothesis source rather than automatic proof of root cause.

## Changed Files

Changed files can help determine whether a recent change affected the component involved in the incident.

For example, a change to application startup code is more relevant to a startup failure than an unrelated documentation change.

Relevance should be established from the affected service and available evidence.

## Code Failure

Application code can fail during:

- startup
- initialization
- request processing
- dependency initialization
- shutdown

Runtime and application evidence should be used to determine which stage failed.

## Change Correlation

A strong change-related explanation normally requires multiple pieces of evidence.

For example:

- a relevant change occurred
- the affected service subsequently failed
- runtime evidence indicates a failure consistent with the change
- logs or other evidence connect the failure to the changed component

Without such supporting evidence, the change should remain a hypothesis.

## Avoiding Blame

Do not automatically blame the newest commit.

The newest change is often investigated because it is temporally relevant, but it must still be supported by technical evidence.

## Rollback Considerations

Rollback is an operational action and should be treated separately from diagnosis.

A suspected change does not automatically justify rollback.

A remediation action should be evaluated using the available evidence, operational risk, and applicable approval policy.