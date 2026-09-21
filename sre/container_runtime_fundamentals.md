# Container Runtime Fundamentals

## Container Lifecycle

A container may move through several states during its lifecycle.

Conceptually:

created → running → stopped/exited → restarted

A container's lifecycle state is different from the health of the application running inside it.

## Running State

A running container means the container process is currently active.

It does not guarantee that the application is healthy.

An application can be running while:

- requests fail
- dependencies are unavailable
- error rates are high
- latency is excessive
- the application is degraded

## Stopped State

A stopped container means its main process is no longer running.

This establishes the current runtime state.

It does not by itself establish why the process stopped.

Possible explanations can include:

- normal termination
- application startup failure
- runtime error
- configuration problem
- resource exhaustion
- intentional stop
- deployment change

These are possibilities, not conclusions.

## Container Inspection

Container inspection provides metadata and runtime state.

Relevant information may include:

- running state
- exit code
- error information
- restart count
- OOM termination state
- image information
- configuration
- timestamps

Inspection evidence should be used to determine which investigation path is relevant.

## Container Statistics

Container statistics describe runtime resource usage.

Examples include:

- CPU usage
- memory usage
- network activity
- block I/O

Resource statistics are most meaningful while a container is running.

If a container is stopped, current runtime statistics may not provide meaningful evidence about why it exited.

## Container Logs

Container logs provide output produced by the containerized application or process.

Logs can reveal:

- startup failures
- application exceptions
- configuration errors
- dependency failures
- runtime errors
- shutdown messages

Container logs should be interpreted with their timestamps and context.

## Exit Codes

An exit code describes how the main process terminated.

A non-zero exit code generally indicates abnormal termination, but the exit code alone may not explain the complete cause.

Additional evidence such as logs or runtime inspection may be required.

## OOM Termination

A container may be terminated because of memory exhaustion.

An OOM indicator from the runtime is direct evidence that the runtime terminated the container for an out-of-memory condition.

Memory measurements can provide supporting evidence about resource behavior.

High memory usage alone does not prove that OOM termination occurred.

## Runtime Evidence Versus Application Evidence

Runtime evidence describes the container/process environment.

Application logs describe events produced by the application.

These evidence types complement each other.

For example:

Runtime inspection may establish that a container exited.

Application logs may explain what the application was doing immediately before exit.

## Investigation Principle

Do not treat container state as the complete explanation of an incident.

Container state answers questions about runtime condition.

Application logs, metrics, deployment information, and configuration evidence may be needed to determine why that condition occurred.