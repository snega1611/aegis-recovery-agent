# Observability Fundamentals

## Observability

Observability is the ability to understand the internal state and behavior of a system from information produced by that system.

Common sources of operational evidence include:

- metrics
- logs
- traces
- service health checks
- runtime state
- deployment information

Metrics and logs answer different questions and should be interpreted together when appropriate.

## Metrics

A metric is a numerical measurement associated with a system or service.

Metrics should always be interpreted together with:

- metric name
- value
- unit
- timestamp
- time range
- affected service or component

A metric value without its time scope can easily be misinterpreted.

## Current Versus Historical Metrics

Current metrics describe the latest observed state.

Historical metrics describe behavior over a previous period.

A current measurement can establish whether a condition exists now.

A historical measurement can help determine whether the condition changed around the incident period.

Do not substitute one for the other.

## Availability

Availability measurements indicate whether a service or monitored target is reachable or functioning according to the monitored condition.

An unavailable target establishes a service-health problem.

It does not automatically identify the reason for the failure.

## Traffic

Traffic represents demand placed on a service.

For HTTP services, request rate is a common traffic measurement.

A change in traffic can provide context for other symptoms.

Traffic alone does not establish causation.

## Errors

Error measurements indicate failed operations or requests.

Error rate should be interpreted with:

- time
- request volume
- affected service
- error type

A high error rate establishes that failures are occurring.

The error itself may still require logs or other evidence to determine the cause.

## Latency

Latency represents the time required to process requests or operations.

Latency should be interpreted with:

- request type
- successful versus failed requests
- measurement window
- affected service

High latency is a symptom and does not automatically establish its cause.

## Saturation

Saturation describes how close a system is to a resource or capacity limit.

Examples include:

- CPU utilization
- memory utilization
- connection limits
- queue depth
- worker capacity

High resource utilization does not automatically mean that the resource caused an incident.

The timing and relationship between the measurement and the incident must be established.

## Metric Types

Prometheus commonly uses:

- counters
- gauges
- histograms

Counters represent cumulative values that normally increase or reset on restart.

Gauges represent values that can increase or decrease.

Histograms represent distributions of observations such as request duration.

Understanding the metric type is important when interpreting changes over time.

## Logs

Logs provide event-level information.

Useful log attributes include:

- timestamp
- severity
- service
- component
- message
- request
- error
- duration

Logs can provide direct evidence about application behavior.

A missing error log does not prove that an error did not occur.

Likewise, an old error log does not prove that the same error caused the current incident.

## Correlation

Two events occurring at approximately the same time may be correlated.

Correlation alone does not establish causation.

For example:

High CPU occurring during an outage is evidence that high CPU occurred.

It is not sufficient by itself to conclude that high CPU caused the outage.

## Four Golden Signals

For user-facing services, four important monitoring dimensions are:

- latency
- traffic
- errors
- saturation

These signals provide broad visibility into service behavior.

They should guide investigation but should not replace evidence-based diagnosis.