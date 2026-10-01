# Personal AI Computer Agent Foundation

A security-first core, deterministic browser layer, and bounded agent-brain planning layer for a personal AI computer agent. Desktop, terminal, filesystem, administrator, and network automation remain unimplemented.

## Development

```powershell
py -m pip install -e .
py -m playwright install chromium
py -m pip install pytest ruff mypy
py -m pytest
ruff check src tests
mypy src
```

The default configuration is deny-by-default. Integrations must implement the interfaces in `src/agent_core/ports.py` and be explicitly allowlisted and tested.

## Persistent task state

Pass a `SQLiteTaskStore` to `AgentRuntime`, `AbilityRouter`, `AgentExecutionLoop`, or `BrowserTaskRunner` to enable durable task/action journals. `SQLiteTaskStore()` stores data at `%LOCALAPPDATA%\bolt\agent-state.sqlite3` on Windows, `$XDG_DATA_HOME/bolt/agent-state.sqlite3` when configured, or `~/.local/share/bolt/agent-state.sqlite3` otherwise. Pass an explicit database path to override it, or `":memory:"` for a deliberately ephemeral store (for example, isolated tests). The runtime does not silently create a store when `state_store` is omitted. These low-level constructors are useful for isolated tests and in-process integrations; they do not acquire application process ownership on their own. For production processes that share a durable database, use `AgentApplication` so the exclusive process lock and lifecycle are held around all components. Playwright has no restart-safe independent reconciliation capability; browser actions left uncertain remain blocked unless an application supplies a separately validated reconciler.

## Agent brain milestone

The project now includes a project-owned agent-brain planner layer that:

- interprets user requests into typed intents
- builds deterministic plans from the available ability registry
- preserves trust provenance across system, user, and untrusted data
- validates generated plans before execution
- routes actions through the existing runtime and approval abstractions
- enforces plan/replan and model-call budgets

The model is a planner/reasoner, not the execution authority. Execution remains under the existing runtime, policy, approval, and kill-switch controls.

## Durable task scheduling

`TaskScheduler` supports one-time (`run_at`) and fixed-interval schedules. Cron expressions are intentionally rejected until their timezone and daylight-saving semantics are explicitly supported. Construct the scheduler with the same `SQLiteTaskStore` and `AgentRuntime` used by the application; scheduled actions are dispatched only through `AgentRuntime.run_async`, so current policy, approval, verification, and kill-switch checks remain in force.

Call `await scheduler.run_once()` from an application-owned loop, or `await scheduler.run_forever(stop_event=...)` to poll until stopped. `max_concurrent_tasks` bounds active occurrences. Misfires beyond `misfire_grace_seconds` are recorded and skipped rather than replayed as a burst. Interval schedules skip elapsed intervals and run at most one occurrence per poll.

Schedule definitions and occurrences use the configured SQLite store. Occurrence IDs and action execution IDs are stable and persisted before dispatch. On startup, in-flight occurrences are reconciled against the runtime action journal; unresolved executions remain uncertain and are not automatically dispatched again. Provider timeouts and cancellation likewise preserve uncertainty rather than claiming that external execution stopped. SQLite cannot atomically commit with an external provider side effect, so an unresolved occurrence may require an application-supported reconciliation path or operator intervention; the scheduler does not invent provider reconciliation capability.

Scheduling is opt-in: applications must create and run a `TaskScheduler` and provide a durable store. Use `SQLiteTaskStore(":memory:")` or an injected temporary database in tests. The default SQLite path and overrides are documented above under Persistent task state.

## Agent service facade

`agent_core.service.AgentService` is the backend-independent application boundary for a future CLI, local UI, or automation adapter. Construct it with the existing `SQLiteTaskStore`, an `AgentExecutionLoop`, the same live `AgentRuntime`, and the existing `TaskScheduler`. It provides task submission/status/cancellation, action history and uncertainty inspection, schedule management, audit queries, safety status, reconciliation requests, and controlled scheduler start/stop/shutdown. It does not expose SQLite rows or action-provider results.

Service requests are untrusted. Submission delegates to the agent execution loop, schedules to `TaskScheduler`, and reconciliation to the runtime's independently configured reconciler. Only the runtime controls policy, approval, kill-switch, execution, and verification. The service has no operation to approve, alter risk/policy, disable the kill switch, retry uncertain work, or mark verification.

Task submission accepts an optional caller ID and idempotency key. The pair and sanitized request fingerprint are persisted (caller/key values themselves are hashed); reusing the same pair for the same objective returns the original task, while reusing it for a different objective returns a typed conflict. A per-service lock serializes local submissions, and the SQLite reservation is transactional. This is not a distributed execution lease: callers should use one service/store owner for a local database and must not infer exactly-once external side effects across process crashes.

Typed status responses contain sanitized task/action state and verification state, not provider output, browser content, model prompts, or credentials. Audit reads are read-only and filterable; their response details use an allowlist. An uncertain action remains blocked unless `request_reconciliation` goes through the runtime's current kill-switch, policy, approval, identity-integrity, and independent-reconciler checks. Inconclusive reconciliation leaves the action uncertain. Cancellation reports a request, not successful completion; in-flight provider work is not forcibly interrupted, and uncertain work cannot be cancelled into a terminal success state.

The service owns at most one scheduler polling loop. `start_scheduler()` is idempotent, `stop_scheduler()` waits for an active polling cycle and can be followed by a restart, and `shutdown()` performs final scheduler closure. Cron remains an explicit unsupported-capability error. Typed service errors distinguish invalid requests, missing records, policy/approval/kill-switch blocks, conflicts, uncertainty, cancellation errors, unsupported scheduling capabilities, and internal failures. No authentication or remote transport is provided; a future network adapter must add its own caller authentication and authorization.

## Application lifecycle and process ownership

Production composition is owned by `agent_core.application.AgentApplication`. It constructs exactly one SQLite store, runtime, execution loop, scheduler, and service; an optional API receives that same service. The CLI uses a short-lived application instance for each command; `bolt-api` owns one application until the server exits. Consequently, a CLI command that opens the same durable database while `bolt-api` is running fails closed with an ownership error rather than opening a competing scheduler/runtime.

Startup order is deterministic: acquire exclusive database ownership, open SQLite, construct the runtime (which performs task recovery), construct the execution loop and the one scheduler (which performs occurrence recovery), construct `AgentService`, construct the optional API, inspect unresolved journal state, then publish `READY` or `DEGRADED`. A degraded start means unresolved action/occurrence uncertainty was found; it is reported through authenticated `GET /application/status`, and application-bound API operations other than that status route are rejected. Recovery never replays uncertain provider actions.

The bundled default composition remains providerless and deny-by-default. It does not install a live kill-switch integration; the application status reports `kill_switch_available: false` rather than implying one exists. This lifecycle change does not add providers or replace an application's responsibility to supply a real kill switch before enabling external execution.

For file-backed databases, ownership is enforced with a kernel-managed nonblocking file lock in a sibling `<database-name>.lock` file (by default next to the database in per-user app data). Windows uses the Microsoft CRT byte-range file lock; POSIX systems use `flock`. The lock file may remain after a crash, but it does not represent ownership: the OS releases the lock when the process exits, so the file is reusable. An in-process guard also prevents duplicate application owners. `:memory:` databases are isolated instances and do not use a cross-process lock. The lock is keyed by the resolved database pathname; opening one database through a separate hard-link pathname is not supported. Low-level runners used outside `AgentApplication` do not independently acquire this application lock. This is local single-writer protection, not a distributed lock or multi-host lease. Network filesystems and filesystems that do not honor the platform locking primitive are outside the guarantee. **Bolt does not claim distributed multi-worker support.**

Shutdown first changes the lifecycle to `STOPPING` so application-bound API middleware rejects new requests, then stops and drains the scheduler through `AgentService`, records lifecycle audit where available, closes SQLite, releases OS ownership last, and moves to `STOPPED`. Shutdown is idempotent. A provider call that cannot be cancelled remains subject to existing uncertainty/reconciliation rules; releasing process ownership never asserts that an external effect was cancelled.

The scheduler is dormant by default. Constructing or starting the API does not start its polling loop. To explicitly run scheduled work with the API, use `bolt-api --start-scheduler`; startup occurs in the server event loop only after application readiness and while ownership is held. `AgentApplication.start_scheduler()` provides the same readiness/ownership gate to embedding applications. The application status DTO is distinct from the existing runtime safety endpoint.

## Local CLI

Install the project in editable mode to add the `bolt` command:

```powershell
py -m pip install -e .
bolt --help
```

The CLI is a thin local operator interface over `AgentService`; it does not connect directly to providers, change policy, grant approval, change risk, disable the kill switch, or retry uncertain actions. Its default bootstrap has an empty ability registry and deny-by-default configuration, so execution providers must be deliberately wired by an application rather than inferred by the CLI.

Examples:

```powershell
bolt task submit "Inspect the current page" --idempotency-key request-42 --json
bolt task list --limit 20
bolt task get <task-uuid>
bolt action uncertain --json
bolt action reconcile <execution-id>
bolt schedule create --objective "Inspect status" --action-name browser.observe --action-kind read_only --run-at 2030-01-02T03:04:05Z --parameters-json '{"url":"https://example.invalid"}'
bolt scheduler status
bolt audit list --task-id <task-uuid> --limit 50 --json
bolt safety status --json
```

The persistent database defaults to the documented local application-data location. Override it for a specific invocation by placing `--database <path>` before the command, for example `bolt --database .\agent-state.sqlite3 task list`. Use `--json` on a leaf command for machine-readable DTO output; public strings and errors are sanitized. Exit code `0` means the requested operation completed, `2` indicates invalid CLI input, `3` a missing record, `4` an authorization or policy block, `5` an active kill switch, `6` uncertain/blocked execution, `7` an idempotency conflict, `8` an unsupported capability, and `1` an internal or rejected operation.

`bolt scheduler start` runs the scheduler in the foreground until interrupted. The scheduler lifecycle belongs to that process: because no daemon or IPC control plane is provided, a separate CLI invocation cannot stop or control a scheduler started elsewhere. Use the embedding application's `AgentService` lifecycle methods when in-process control is required.

## Authenticated API

The optional HTTP adapter in `agent_core.api` is a transport boundary over `AgentService`; it does not access the task database, providers, browser abilities, or runtime controls directly. Start the local server with:

```powershell
bolt-auth create --scope task.submit --scope task.read --scope task.cancel
bolt-api
```

Credential creation and maintenance are local operator operations only:

```powershell
bolt-auth status
bolt-auth rotate <credential-id>
bolt-auth revoke <credential-id>
bolt-auth create --scope schedule.read --scope scheduler.read --scope safety.read
```

The `create` and `rotate` commands display the newly generated bearer token once so the operator can store it in an appropriate local secret manager; the token is never written to the credential file and cannot be retrieved later. The credential file stores only a random salt and SHA-256 digest for high-entropy random tokens, plus scopes, revocation status, and resource ownership metadata. The API has no remote credential-management endpoint and no hard-coded/default credential. Create a token with only the scopes needed by that client.

Requests use `Authorization: Bearer <token>`. Authenticated caller identity is derived from the credential ID; caller identity fields in request bodies are rejected. Task submission requires `Idempotency-Key`; the authenticated identity and key are passed to `AgentService`'s existing transactional idempotency mechanism. The same caller/key/objective returns the original task, a different objective conflicts, and another caller has an independent key namespace. Other mutating operations retain their existing service semantics; no second API idempotency database is introduced.

The exact scope strings are `application.read`, `task.read`, `task.read:any`, `task.submit`, `task.cancel`, `task.cancel:any`, `action.read`, `action.read:any`, `action.reconcile`, `action.reconcile:any`, `schedule.read`, `schedule.read:any`, `schedule.create`, `schedule.modify`, `schedule.modify:any`, `schedule.cancel`, `schedule.cancel:any`, `scheduler.read`, `scheduler.control`, `audit.read`, `audit.read:any`, and `safety.read`. There is no generic administrator scope. The `*:any` scopes are explicit cross-resource grants and do not grant unrelated operations; they supplement, rather than replace, the matching base operation scope. For example, `task.read:any` does not allow cancelling another caller's task; cross-caller cancellation requires both `task.cancel` and `task.cancel:any`. Resources submitted through the API are associated with the authenticated credential identity; callers without matching ownership receive not-found responses.

Routes:

- Tasks: `POST /tasks`, `GET /tasks`, `GET /tasks/{task_id}`, `POST /tasks/{task_id}/cancel`.
- Actions: `GET /actions/{action_id}`, `GET /actions/{action_id}/history`, `GET /actions/uncertain`, `POST /actions/{action_id}/reconcile`.
- Schedules: `POST /schedules`, `GET /schedules`, `GET /schedules/{schedule_id}`, and `POST /schedules/{schedule_id}/{enable|disable|cancel}`.
- Scheduler: `GET /scheduler/status` and `POST /scheduler/{run-once|start|stop|shutdown}`.
- Audit and safety: `GET /audit`, `GET /safety/status`.

The FastAPI-generated schema is available at authenticated `GET /openapi.json`, with Swagger UI at `/docs`. Each request receives an `X-Request-ID` response header (a caller-supplied value is accepted only when it is a UUID); structured errors use `{"error":{"code":"...","message":"...","request_id":"..."}}`. Error codes include `INVALID_REQUEST`, `AUTHENTICATION_FAILED`, `AUTHORIZATION_DENIED`, `NOT_FOUND`, `APPROVAL_REQUIRED`, `POLICY_DENIED`, `KILL_SWITCH_ACTIVE`, `UNCERTAIN`, `CONFLICT`, `UNSUPPORTED_CAPABILITY`, `TIMEOUT`, `RATE_LIMITED`, and `INTERNAL_FAILURE`. Authentication failures are rate-limited in-process to five consecutive failures per peer per 60-second window. This is local abuse protection, not a distributed rate limiter.

The default credential metadata path is `%LOCALAPPDATA%\\bolt\\api-credentials.json` on Windows, `$XDG_DATA_HOME/bolt/api-credentials.json` when configured, or `~/.local/share/bolt/api-credentials.json` otherwise. The default `bolt-api` listener binds only to `127.0.0.1:8765`; non-loopback binding is refused. CORS is disabled by default. Embedders may explicitly pass an origin allowlist to `create_api_app`; wildcard origins are rejected. For remote access, keep Bolt bound to loopback and put a separately secured TLS-terminating reverse proxy in front of it. Configure the proxy to restrict upstream access to the local Bolt listener and protect bearer tokens in transit. Bolt does not implement TLS termination, public-network binding, or a trusted-proxy protocol itself. Do not expose the HTTP listener directly to a LAN or the Internet. Credential/rate-limit layers are designed for one process, and the database ownership lock prevents multiple Bolt application processes from operating the same local database.

Starting the API does not start the scheduler by default. `--start-scheduler` is an explicit opt-in. Scheduler controls require `scheduler.control` and still delegate to the existing `AgentService`; its single-loop lifecycle protections remain authoritative. Reconciliation delegates to the existing runtime path and rejects request payloads and query parameters; it cannot force verification or re-execute an uncertain action.

**Authentication and API authorization do not replace the runtime's policy, approval, kill-switch, verification, or recovery controls.** `task.submit` only permits a request to reach `AgentService`; it does not approve the plan or authorize provider execution. Current runtime policy, approval, kill switch, action validation, verification, recovery, and reconciliation remain final.
