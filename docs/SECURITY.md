# Security boundaries

## Authority and execution

Models and external content may propose work but do not authorize it. The runtime validates structured plans and action identity, then applies current policy, approval, kill-switch, task-state, and verification controls before recording outcomes. Persisted records are inputs to recovery, not permission grants. Persisted approval or risk data does not supersede current runtime policy.

An action with an unresolved external outcome remains blocked until an independently configured reconciler supplies evidence. Reconciliation is a separate observational interface; an ordinary provider `execute` operation is never used to check whether an action happened. Playwright does not currently provide a safe independent reconciler, so uncertain browser actions remain blocked. SQLite transactions protect related local journal and audit updates, but cannot make an external side effect atomic with the database.

## Provider credentials

The provider credential broker keeps value handling separate from metadata:

- SQLite records the credential ID, type, caller/ability/provider scope, timestamps, version, revocation state, and sanitized metadata. It has no provider-secret column.
- A `CredentialValueBackend` is required to store values outside SQLite and independently bind each stored value to its original credential scope. Runtime-provided caller, registered ability, provider, and credential identity are checked at handle issuance and again at reveal. The stored scope in SQLite alone cannot widen the backend-bound scope.
- Only trusted ability registration chooses a credential binding. Models receive neither the broker nor credential handles. Handles are non-serializable and reveal only from a live, matching runtime provider call after current kill-switch, journal, policy, and approval checks.
- Metadata changes and their audit entries are written in one SQLite transaction. Backend operations remain external and are not transactionally atomic with SQLite. A cleanup failure is surfaced; revoked metadata still denies subsequent access.
- On Windows, the application uses Windows Credential Manager through `pywin32`, storing generic credentials in the current user's OS-protected credential store. The payload binds credential ID, version, caller, ability, and provider; reads reject any scope or identity mismatch. Bolt does not implement encryption or key management. If the Windows API binding or store is unavailable, operations fail closed. Other operating systems use the unavailable backend by default.
- A volatile in-memory backend exists only in tests. Embedding code may explicitly inject a backend through local `AgentApplication` composition; API clients cannot select one. Application status reports only a boolean availability value, never a store location or credential content.
- Provider credential values have no HTTP API or secret-bearing CLI entry/display command. Local CLI operations list, inspect, and revoke metadata only; value creation and rotation remain unsupported until a secure interactive input flow is implemented. Browser login, authenticated browser sessions, persistent profiles, and remote secret injection are unsupported.

Secret wrappers and handles prevent common accidental logging and serialization. They do not provide secure memory erasure or isolation from malicious Python code already executing in the same process. A value backend and provider adapter are trusted components and must avoid logging revealed values.

## Local persistence and deployment

The application uses a durable local SQLite database by default, with the path and override documented in the README. `:memory:` is intentionally ephemeral and suitable for tests, not crash recovery. The application holds a process ownership lock for the configured database. Protect the database file and its containing directory using operating-system account permissions; SQLite metadata does not encrypt the database.

The API binds to loopback by default and has no TLS termination. Do not expose it directly to a network. For remote access, use a separately secured reverse proxy as described in the README. API bearer credentials are distinct from provider credentials and are stored as salted digests, not recoverable token values.

## Built-in local abilities

Public web reads use `SafeWebFetcher`, not browser navigation or a general HTTP client. It accepts only HTTP(S), resolves every URL and redirect hop, rejects non-global and special IPv6 destinations, and connects to a selected validated IP while retaining the original host for TLS SNI and certificate checks. It does not use environment proxies or accept caller headers/cookies, rejects compressed or non-text responses, and applies redirect, response-size, header-size, and elapsed-time bounds. HTTP remains available only as an explicitly allowlisted network-read action and is marked insecure in its result. The search adapter is isolated behind `WebSearchProvider`; the default implementation uses Bing RSS and must only be used under its personal non-commercial terms. Search result text and fetched page content are always untrusted.

The workspace ability is absent unless the operator explicitly configures a root. It denies absolute paths, parent traversal, and symlink components; reads and listings are bounded, writes are create-only, and writes remain separately gated by `write_file` policy and approval. Its post-write verifier compares actual file bytes with the intended create-only content. On restart, its reconciler confirms an exact content match, confirms non-execution if the target is absent, and leaves mismatches uncertain. These checks do not eliminate time-of-check/time-of-use races against a hostile process running as the same OS user; use a workspace that other processes cannot mutate concurrently.

The effective kill switch is active when either the persistent local operator control in SQLite is engaged or `BOLT_KILL_SWITCH_ACTIVE` is asserted. The database control survives application restarts and is available through `bolt safety kill-switch engage|release|status`; the environment variable is an additional fail-safe override and cannot be cleared by the CLI. Both the task runtime and scheduler query the same kill-switch object on every check. The control is local-only and is not exposed over the API. Protect the database and process environment with the operating-system account; SQLite metadata is not tamper-proof against a same-user attacker. `bolt doctor` reports switch state and whether model, approval, and verification providers are configured.

## Known limitations

- The production OS-backed provider credential integration currently supports Windows Credential Manager only. Other platforms remain unavailable unless an embedding application supplies a suitable backend.
- Playwright cannot independently determine whether arbitrary external browser side effects occurred after a crash; those actions remain uncertain and require operator or future provider-specific reconciliation.
- Exactly-once execution of an external side effect cannot be guaranteed by a local SQLite transaction. The runtime instead journals before execution and blocks uncertain work from automatic replay.
- The built-in web reader is limited to anonymous public text reads; it is not a safe way to submit forms, access authenticated services, or replace a browser-specific reconciliation adapter.
- No model provider is configured by default. Web/workspace postconditions are verified when those abilities are registered, but no general external-side-effect verifier is configured. The CLI injects a synchronous, sanitized approval prompt only when attached to an interactive terminal; a missing/noninteractive approver fails closed. Pending approvals are not durable and there is no approve/deny API workflow. Embedding applications must inject a current approval provider.
- Scheduled objectives do not yet run through the model/ability loop. The scheduler currently dispatches direct runtime actions, so model-backed research/report schedules are unsupported.
- SQLite is local durable metadata storage, not an encrypted vault or a defense against an attacker who can replace the configured value backend. The Windows Credential Manager binding protects stored values using Windows facilities, but does not defend against malicious code executing as the same Windows user. Deployments must protect the application, database, OS account, and injected backends.
