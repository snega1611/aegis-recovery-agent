# Incident: High Memory Usage

## Trigger

The backend memory usage increases when `/memory-load` is called.

## Reproduction

GET /memory-load?mb=300

## Known Lab Observation

During the local reproduction:

- Backend memory increased to approximately 547.5 MiB.
- Docker reported approximately 14.65% memory utilization.
- The allocated memory remained in the backend process.

## Expected Investigation

Aegis should determine:

- Which service is consuming increased memory?
- How much memory is being consumed?
- Is memory usage still increasing?
- Is the process approaching its memory limit?
- What evidence explains the increase?

## Expected Outcome

The agent should distinguish elevated memory usage from an actual memory failure and provide evidence for its conclusion.