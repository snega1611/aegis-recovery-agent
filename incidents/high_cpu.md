# Incident: High CPU

## Trigger

The backend CPU usage increases significantly when `/cpu-load` is called.

## Reproduction

GET /cpu-load?seconds=120

## Known Lab Observation

During the local reproduction:

- Prometheus CPU metric increased.
- Grafana showed a CPU spike.
- CPU returned toward normal after the request completed.

## Expected Investigation

Aegis should determine:

- Which service is affected?
- How high is CPU usage?
- When did the spike begin?
- What evidence explains the spike?
- Is the condition still active?

## Expected Outcome

The agent should produce an evidence-backed explanation rather than simply saying "CPU is high."