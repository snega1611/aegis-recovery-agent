# Incident: Slow Requests

## Trigger

The backend response time increases when `/slow` is called.

## Reproduction

GET /slow?seconds=10

## Known Lab Observation

During the local reproduction:

- The request took approximately 10 seconds to complete.
- Prometheus records request duration through a histogram.
- Average latency and percentile queries can be diluted by other fast requests when traffic volume is low.

## Investigation Challenge

Aegis should determine:

- Which endpoint is slow?
- How long did the affected request take?
- When did the latency increase?
- Is the latency isolated to one endpoint or affecting the service generally?
- What evidence explains the latency?

## Expected Outcome

The agent should identify slow requests using appropriate telemetry rather than relying only on a service-wide average.