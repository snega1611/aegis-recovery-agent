# Incident: HTTP Errors

## Trigger

The backend returns an HTTP 404 response for an invalid endpoint.

## Reproduction

GET /does-not-exist

## Known Lab Observation

During the local reproduction:

- The backend returned a 404 response.
- Prometheus recorded the error through `aegis_http_errors_total`.
- The error counter increased after the failed request.

## Expected Investigation

Aegis should determine:

- Which service is generating the error?
- What HTTP status code occurred?
- Which endpoint is affected?
- When did the errors begin?
- Are the errors isolated or occurring repeatedly?
- What evidence explains the errors?

## Expected Outcome

The agent should identify the affected endpoint and use application telemetry to explain the error rather than treating every HTTP error as a service failure.