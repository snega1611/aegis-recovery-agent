# SRE Incident Investigation

## Purpose

Incident investigation is the process of determining what is happening to a service, what evidence explains the behavior, and whether the available evidence is sufficient to establish a root cause.

An incident report describes the reported problem. It is not itself proof of the underlying cause.

The investigation should continuously distinguish between:

- reported symptom
- observed system state
- hypothesis
- supporting evidence
- confirmed cause
- remaining uncertainty

## Symptom Versus Cause

A symptom describes what users or monitoring systems observe.

A cause explains why the symptom occurred.

For example:

A service being unavailable is a symptom.

A process exiting with a specific application error may provide evidence for the cause.

A high CPU measurement is an observation. It does not automatically prove that CPU caused the incident.

An error log describing a failed database connection is evidence of an observed failure. It does not automatically establish why the database connection failed.

Always distinguish:

WHAT happened?

from:

WHY did it happen?

## Evidence-Driven Investigation

An investigation should proceed from evidence.

For every step:

1. Identify what is already known.
2. Identify the most important unanswered question.
3. Determine what type of evidence could answer that question.
4. Collect the most relevant available evidence.
5. Update the investigation based on the new evidence.
6. Repeat only when useful new evidence can still be obtained.

Do not collect evidence simply because a monitoring tool exists.

The existence of a metric does not make that metric relevant to every incident.

## Direct Evidence

Prefer evidence that directly describes the affected component.

Examples include:

- service availability state
- process or container state
- exit status
- application error messages
- dependency errors
- resource exhaustion indicators
- deployment or configuration changes
- request failures

Indirect evidence can support an investigation but should not automatically be treated as proof of causation.

## Evidence Scope

Every observation has a scope.

Important dimensions include:

- current versus historical
- timestamp
- measurement window
- affected service
- affected component
- query or observation period

A current measurement should not automatically be used to explain an earlier event.

A historical measurement should not automatically be used to describe the current state.

Evidence must be interpreted using the time and scope returned by the monitoring system.

## Hypotheses

A hypothesis is a possible explanation that requires evidence.

A hypothesis is not a confirmed root cause.

The investigation should collect evidence that can distinguish between competing explanations rather than collecting unrelated data.

Do not convert:

"this could explain the incident"

into:

"this caused the incident."

## Redundant Evidence

Avoid collecting multiple observations that answer the same question without adding information.

For example, two different searches for the same error condition may provide little additional value.

Before using another tool, ask:

"What new question will this tool answer?"

If the answer is the same question already answered, prefer another investigation path.

## When to Stop

An investigation should stop when:

- the available evidence directly establishes the cause, or
- no available tool can provide useful new evidence, or
- the remaining question cannot be answered with the available data.

An unknown root cause does not mean that random additional tools should be executed.

Likewise, confirming that a symptom exists does not mean that the investigation is complete.

## Root Cause

A root cause should only be marked as confirmed when available evidence directly supports the causal explanation.

A plausible explanation without supporting evidence is not a confirmed root cause.

If the available evidence only establishes the symptom, report the symptom and identify the missing evidence required to determine the cause.

## Investigation Quality

A strong investigation is:

- evidence-driven
- targeted
- incremental
- time-aware
- explicit about uncertainty
- resistant to assumptions
- resistant to redundant data collection
- capable of stopping when additional evidence is unavailable