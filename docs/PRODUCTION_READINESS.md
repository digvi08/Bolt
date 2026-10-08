# Local Personal Agent Readiness

## Verdict

**BLOCKED — this project provides a useful, bounded local agent foundation, but it is not a complete general-purpose computer-use agent.** The safe built-in capability set is intentionally narrow: optional public web search/fetch and rooted workspace read/create-only-write operations. Browser interaction, authenticated services, desktop control, terminal execution, and automatic verification of external effects are not enabled.

Do not interpret a passing test suite as evidence that unsupported integrations are safe or production-ready.

## What is implemented

- Model-backed planning and synthesis through a configurable OpenAI-compatible chat-completions endpoint. The model proposes typed plans; registry validation, current runtime policy, approval, kill switch, action identity, and verification remain outside model authority.
- Bounded planning, tool-call, model-call, token, response-size, and task-duration limits. Remote model endpoints require TLS and a configured API key; loopback HTTP is available for local model servers. Provider keys are process-memory values and are not written to the task journal.
- Public, anonymous web search/fetch behind explicit allowlist and external-integration gates. Fetch validates and pins each public destination, follows bounded redirects, rejects unsupported response types and applies size/time limits. Web results are untrusted data.
- Workspace reads/listing and create-only writes under an operator-configured root. Writes cannot overwrite existing files and require current policy and approval. Same-user filesystem races remain outside the guarantee.
- Durable SQLite task/action/schedule/audit state at the per-user application-data path documented in the README, plus exclusive process ownership for the composed application. `:memory:` is for isolated tests, not recovery.
- Restart recovery that marks interrupted external actions uncertain and blocks automatic replay. A separate reconciler protocol can resolve outcomes when a provider supplies independent evidence; unsupported providers remain blocked.
- A persistent local kill switch with CLI engage/release/status commands and an additional environment fail-safe override.
- A fresh synchronous approval prompt for CLI actions requiring approval when the CLI has an interactive terminal. Prompt details are sanitized. Embedding applications can inject an approval provider. A missing or noninteractive approver denies the action.
- Windows Credential Manager integration for scoped provider credentials where the OS binding is available. Provider credential metadata is kept separately from values.

## CURRENT CAPABILITIES

With explicit configuration, the current executable flows support natural-language requests through the service/executor into the bounded public-web and rooted-workspace abilities. Model orchestration is enabled when the CLI model environment is configured; deterministic planning remains available otherwise. The application also supports local action inspection, reconciliation requests, task/schedule inspection, and operator kill-switch control.

## END-TO-END EXECUTION

For web and workspace abilities the path is:

```text
CLI/API -> AgentService -> AgentExecutionLoop -> AbilityRouter
       -> AgentRuntime -> current policy/approval/kill switch
       -> registered ability -> verification -> SQLite/audit
       -> optional bounded model synthesis
```

The model does not call a provider directly. Each action has to be supported by the currently registered ability, pass its fixed argument schema, and pass the runtime's current policy. The API is a request boundary, not a provider boundary.

## MODEL

Set `BOLT_MODEL_BASE_URL` and `BOLT_MODEL_NAME`; remote hosts require HTTPS and `BOLT_MODEL_API_KEY`. Loopback HTTP is allowed for local model servers. `bolt doctor --json` reports only whether a provider is configured and the provider count; it does not print the endpoint or key. The key is never placed in SQLite or audit records. A live provider credential has not been exercised as part of local validation; model behavior is tested with deterministic fakes.

## WEB

Web search and fetch require both `network_read` in `BOLT_ALLOWED_ACTIONS` and `BOLT_ENABLE_EXTERNAL_INTEGRATIONS=true`. Search is behind a provider interface (default Bing RSS, subject to its personal non-commercial terms). Fetch uses the shared bounded HTTP implementation with public-IP DNS validation and connection pinning, redirect validation, TLS verification for HTTPS, response size/time limits, content-type restrictions, and no caller headers, cookies, or credentials. Results are explicitly marked untrusted. Application-level postcondition checks validate response status, size, type/trust metadata and result count.

## BROWSER

**Browser execution is disabled and not registered.** The repository has Playwright adapter code, but it does not yet provide enforceable DNS-pinned navigation and continuous redirect/subresource controls suitable for arbitrary pages. `bolt doctor` reports it as `unsupported_not_registered`. No model or user request can route to Playwright through the application. Do not treat the existing browser unit tests as proof that production browser navigation is safe.

## WORKSPACE

Set `BOLT_WORKSPACE_ROOT` to an existing directory and allow `read_only` for listing/reading; separately allow `write_file` for create-only writes. Paths are relative and checked against the configured root; symlink components are rejected, reads/writes are bounded, and existing files are not overwritten. Current verification checks the resulting write content against the requested bytes and the path against the configured root. On restart, the workspace reconciler compares the target file with the persisted write intent: exact content confirms completion, absent target confirms no write, and a mismatch or unsafe path remains uncertain. This does not make the filesystem and SQLite transaction atomic or defend against hostile same-user races.

## APPROVAL

The CLI injects an explicit synchronous prompt only when connected to an interactive terminal. It displays sanitized action details and requires the exact answer `y`; EOF, `yes`, or noninteractive use denies. The same current provider is used for restart reconciliation when current policy requires approval. There is no durable pending-approval queue or API approval endpoint. Remote callers cannot approve actions.

## KILL SWITCH

`bolt safety kill-switch status|engage|release` controls the one persistent local SQLite kill-switch record. The runtime and scheduler use the same switch object. `BOLT_KILL_SWITCH_ACTIVE=true` is an emergency additive override; while it is asserted, a CLI release command cannot make the effective switch inactive. There is no remote/API control endpoint.

## RECOVERY

Interrupted in-flight actions become uncertain and are not automatically replayed. The workspace create-only writer has an independent read-only reconciliation check; web requests and unsupported provider actions do not have an outcome reconciler and remain blocked when their outcome is uncertain. An exact file match can be confirmed; an absent target can be safely reported as not executed, but the runtime still requires a fresh authorized execution attempt. A local SQLite transaction cannot make an external side effect atomic.

## SCHEDULING

The existing scheduler persists schedules and occurrences, bounds concurrency, enforces deadlines and kill-switch checks, and recovers interrupted occurrences conservatively. Its current application composition dispatches direct `ActionRequest` values through the runtime, not natural-language objectives through `AgentExecutionLoop`; built-in web/workspace model workflows are therefore **not yet available as scheduled jobs**. Do not create a schedule expecting model planning or a web report until that execution-path gap is implemented.

## SECURITY

The model is a proposer only. External web and workspace text is untrusted. The runtime rechecks policy and kill switch immediately before provider execution, including after approval; unknown or unsupported abilities fail closed. Credentials remain broker-scoped and are not available to the model. Browser, shell, desktop, unrestricted filesystem, authenticated browsing, and remote kill-switch control are disabled. The local database is not encrypted or tamper-proof against malicious code executing as the same OS user.

## TESTS

Run `python -m pytest --collect-only -q`, `python -m pytest -q`, `ruff check src tests`, `mypy src`, and `git diff --check`. Current validation collected 270 tests and completed with **269 passed, 1 skipped**; Ruff, mypy, and the diff check passed. These checks do not certify unsupported browser, durable-approval, or scheduled-model workflows.

## LIMITATIONS

- Browser functionality is intentionally unavailable pending a defensible network-isolation implementation and end-to-end tests.
- Durable pending approvals and authenticated remote approval are not implemented.
- Model-driven scheduled research/report jobs do not use the model ability loop.
- No live model endpoint or production verification provider is configured by default.
- Exactly-once external execution cannot be guaranteed by local SQLite.
- OS permissions, database backup, monitoring, and secure model-provider deployment require operator configuration.

## SETUP

In PowerShell, from the repository:

```powershell
py -m pip install -e .
$env:BOLT_ALLOWED_ACTIONS = "network_read,read_only"
$env:BOLT_ENABLE_EXTERNAL_INTEGRATIONS = "true"
$env:BOLT_WORKSPACE_ROOT = "C:\Users\you\project"
bolt doctor
bolt safety kill-switch status
```

Add `$env:BOLT_MODEL_BASE_URL`, `$env:BOLT_MODEL_NAME`, and (for remote HTTPS providers) `$env:BOLT_MODEL_API_KEY` to opt into model planning. Do not put the key in command arguments or task text. Attach a terminal for approval prompts. The default database is under the current user's local application-data directory; `--database <path>` overrides it per command.

## EXAMPLES

Assuming the settings above:

```powershell
bolt task submit "search the web for official Python 3.13 release notes"
bolt task submit "fetch https://docs.python.org/3/whatsnew/3.13.html"
bolt task submit "list files"
bolt task submit "read file README.md"
bolt task submit "create file research-notes.txt with key findings"
bolt action uncertain --json
bolt safety kill-switch engage
bolt safety kill-switch release
```

The file-creation example prompts for current approval in an interactive terminal. The final two examples are local operator controls. Browser actions and scheduled model-research workflows are not examples because those features are not currently supported.

## What is deliberately unsupported

- **Browser execution:** Playwright code exists as an adapter, but it is not registered as a normal application ability. Its current navigation path does not provide the complete destination pinning and subresource policy required for safe model-directed browsing. Do not expose it to model plans or use it against arbitrary sites.
- **Authenticated browser sessions:** login, cookie/profile persistence, and automatic credential injection are unsupported.
- **Desktop, terminal, administrator, arbitrary filesystem, and destructive actions:** these are not built-in execution capabilities.
- **Reliable verification by default:** no production verification provider is configured. A provider's successful return or a local journal flag is not independent evidence of an external effect.
- **Provider-specific browser reconciliation:** the application cannot infer a remote side effect from a page still being open. Browser actions interrupted during execution remain uncertain and blocked.
- **Durable approval workflow:** CLI confirmation is synchronous, not a pending approval queue. No authenticated API operation can approve or deny an action.
- **Distributed execution:** SQLite and the process lock support one local application owner, not multi-host workers or distributed leases.

## Operating guidance

1. Install the package and Playwright Chromium only if needed for local browser-layer tests; do not treat installing a browser as enabling a safe browser ability.
2. Use the documented per-user SQLite location or an explicit protected local path. Back up the database using an application-consistent procedure. Do not use network filesystems or multiple application processes against one database.
3. Enable only required action kinds. Public network reads require both `network_read` allowlisting and `BOLT_ENABLE_EXTERNAL_INTEGRATIONS=true`; workspace writes additionally need the configured root and `write_file`.
4. Configure a model endpoint only when needed. Use HTTPS for remote endpoints and inject the API key through a protected process environment. Never place credentials in task prompts or model output.
5. Run `bolt doctor` and `bolt safety kill-switch status` before enabling work. Use `bolt safety kill-switch engage` for the persistent local stop. The emergency environment override takes precedence and must be changed by the process supervisor.
6. Inspect uncertain actions with `bolt action uncertain` and reconcile only through an independently validated provider. Do not manually edit journal records to force completion or retry.
7. Treat audit records as operational evidence, not a tamper-proof forensic log. The local database is not encrypted or protected from malicious code running as the same OS user.

## Readiness gaps and classification

| Gap | Classification | Consequence |
|---|---|---|
| Browser route/subresource enforcement and a registered, safe browser capability | Implementation work still needed | Browser ability remains unavailable; enabling the existing raw Playwright navigation path would be unsafe. |
| Browser-specific independent verification/reconciliation | Provider capability limitation and implementation work still needed | Interrupted browser side effects cannot be safely resolved automatically and remain blocked. |
| Atomicity across an external provider side effect and SQLite journal commit | Fundamentally impossible to guarantee with a local transaction | A crash can always leave an uncertain outcome; provider idempotency or independent reconciliation is needed to resolve it. |
| Durable pending approvals and an authenticated approve/deny workflow | Implementation work still needed | API/noninteractive high-impact actions fail closed; only interactive CLI confirmation is available. |
| Natural-language scheduler dispatch through the model/ability loop | Implementation work still needed | Current scheduler stores and dispatches direct runtime actions; do not expect it to run model-planned research tasks. |
| Production verification adapters for actual external effects | Provider capability limitation and deployment/configuration work | Completion is not independently verified unless the application injects a trustworthy verifier. |
| OS-backed credential backend outside supported Windows configuration | Deployment/configuration work | Credential-value operations fail closed on unsupported platforms. |
| Hardened service installation, backup, OS permissions, monitoring, and model endpoint configuration | Deployment/configuration work | Operators must supply and maintain host-level controls; the repository does not set them up automatically. |
