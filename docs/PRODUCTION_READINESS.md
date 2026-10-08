# Local Personal Agent Readiness

## Verdict

**PRODUCTION-READY FOR LOCAL PERSONAL USE** — when configured with the documented local controls and only the required allowlisted capabilities. This is not a general-purpose computer-use agent: browser interaction is deliberately limited to public HTTPS documents and consequential actions require durable operator approval. Review the exact limitations below and configure only the capabilities you need before enabling them.

Do not interpret a passing test suite as evidence that unsupported integrations are safe or production-ready.

## What is implemented

- Model-backed planning and synthesis through a configurable OpenAI-compatible chat-completions endpoint. The model proposes typed plans; registry validation, current runtime policy, approval, kill switch, action identity, and verification remain outside model authority.
- Bounded planning, tool-call, model-call, token, response-size, and task-duration limits. Remote model endpoints require TLS and a configured API key; loopback HTTP is available for local model servers. Provider keys are process-memory values and are not written to the task journal.
- Public, anonymous web search/fetch behind explicit allowlist and external-integration gates. Fetch validates and pins each public destination, follows bounded redirects, rejects unsupported response types and applies size/time limits. Web results are untrusted data.
- Workspace reads/listing and create-only writes under an operator-configured root. Writes cannot overwrite existing files and require current policy and approval. Same-user filesystem races remain outside the guarantee.
- Durable SQLite task/action/schedule/audit state at the per-user application-data path documented in the README, plus exclusive process ownership for the composed application. `:memory:` is for isolated tests, not recovery.
- Restart recovery that marks interrupted external actions uncertain and blocks automatic replay. A separate reconciler protocol can resolve outcomes when a provider supplies independent evidence; unsupported providers remain blocked.
- A persistent local kill switch with CLI engage/release/status commands and an additional environment fail-safe override.
- Durable SQLite-backed action approvals with expiration and action fingerprinting. The CLI and authenticated API let an operator list, inspect, approve, or deny a pending action; approval resumes the waiting task through the execution loop. The application creates this provider by default, and embedding applications may inject another approval provider.
- Windows Credential Manager integration for scoped provider credentials where the OS binding is available. Provider credential metadata is kept separately from values.
- A restricted Playwright browser ability routed through the same service, execution loop, registry/router, runtime policy, durable approval, verification, and audit path as other abilities. Its DNS-pinned egress proxy, request filtering, and disabled JavaScript/subresources enforce a deliberately narrow public-document subset.
- Persistent natural-language scheduled objectives dispatched through `AgentService` into the same bounded model/ability execution pipeline as manual tasks. Schedule occurrences retain caller ownership and unique identities; consequential work waits for operator approval and is not auto-approved.

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

The model does not call a provider directly. Each action has to be supported by the currently registered ability, pass its fixed argument schema, and pass the runtime's current policy. The scheduler dispatches an objective through `AgentService`; it does not call model or ability providers. The API is a request boundary, not a provider boundary.

## MODEL

Set `BOLT_MODEL_BASE_URL` and `BOLT_MODEL_NAME`; remote hosts require HTTPS and `BOLT_MODEL_API_KEY`. Loopback HTTP is allowed for local model servers. `bolt doctor --json` reports only whether a provider is configured and the provider count; it does not print the endpoint or key. The key is never placed in SQLite or audit records. A live provider credential has not been exercised as part of local validation; model behavior is tested with deterministic fakes.

## WEB

Web search and fetch require both `network_read` in `BOLT_ALLOWED_ACTIONS` and `BOLT_ENABLE_EXTERNAL_INTEGRATIONS=true`. Search is behind a provider interface (default Bing RSS, subject to its personal non-commercial terms). Fetch uses the shared bounded HTTP implementation with public-IP DNS validation and connection pinning, redirect validation, TLS verification for HTTPS, response size/time limits, content-type restrictions, and no caller headers, cookies, or credentials. Results are explicitly marked untrusted. Application-level postcondition checks validate response status, size, type/trust metadata and result count.

## BROWSER

Browser execution is registered only when `browser` is explicitly allowlisted and external integrations are enabled. The usable subset supports bounded HTTPS document navigation on port 443, inspection/extraction, accessible-target click, non-sensitive field fill, bounded wait, and explicitly permitted form submission. JavaScript, frames, subresources, downloads/uploads, cookies, credentials, persistent profiles, and authenticated sessions are unavailable. Outbound browser TCP uses a local SOCKS5 proxy that resolves, rejects non-public addresses, and connects to the validated IP; requests and redirects are filtered, with all non-document traffic denied. Page data is always untrusted. Clicks and submissions use the existing durable approval workflow. See [BROWSER.md](BROWSER.md) for the enforcement boundary and limitations. This is not safe general browsing and does not defend against a compromised browser/runtime or malicious same-user process.

## WORKSPACE

Set `BOLT_WORKSPACE_ROOT` to an existing directory and allow `read_only` for listing/reading; separately allow `write_file` for create-only writes. Paths are relative and checked against the configured root; symlink components are rejected, reads/writes are bounded, and existing files are not overwritten. Current verification checks the resulting write content against the requested bytes and the path against the configured root. On restart, the workspace reconciler compares the target file with the persisted write intent: exact content confirms completion, absent target confirms no write, and a mismatch or unsafe path remains uncertain. This does not make the filesystem and SQLite transaction atomic or defend against hostile same-user races.

## APPROVAL

The application persists pending approvals in SQLite and binds each approval to a fingerprint of the task, caller, action, ability, provider, risk, and parameters. The default decision window is 15 minutes. Operators can use `bolt approval list`, `bolt approval show <approval-id>`, `bolt approval approve <approval-id>`, and `bolt approval deny <approval-id>`. Approval re-enters the task execution loop, where current runtime policy, kill-switch, and action checks still apply; a decision does not bypass those controls. The authenticated API exposes `GET /approvals`, `GET /approvals/{approval_id}`, `POST /approvals/{approval_id}/approve`, and `POST /approvals/{approval_id}/deny`. These operations require `approval.read`, `approval.approve`, or `approval.deny`; corresponding `:any` scopes explicitly grant cross-caller access. The default API listener is local-only. This is a single-operator decision workflow, not a multi-person quorum or distributed worker lease.

## KILL SWITCH

`bolt safety kill-switch status|engage|release` controls the one persistent local SQLite kill-switch record. The runtime and scheduler use the same switch object. `BOLT_KILL_SWITCH_ACTIVE=true` is an emergency additive override; while it is asserted, a CLI release command cannot make the effective switch inactive. There is no remote/API control endpoint.

## RECOVERY

Interrupted in-flight actions become uncertain and are not automatically replayed. The workspace create-only writer has an independent read-only reconciliation check; web requests and unsupported provider actions do not have an outcome reconciler and remain blocked when their outcome is uncertain. An exact file match can be confirmed; an absent target can be safely reported as not executed, but the runtime still requires a fresh authorized execution attempt. A local SQLite transaction cannot make an external side effect atomic.

## SCHEDULING

The scheduler persists caller-owned objective schedules and occurrences, bounds concurrency, enforces deadlines and kill-switch checks, and recovers interrupted occurrences conservatively. It dispatches each objective through `AgentService` into the same `AgentExecutionLoop` used by manual tasks; model planning, ability validation, runtime policy, credential broker, kill switch, approval, verification, audit, and persistence are shared. Model/tool limits are fresh but bounded per occurrence. A high-risk action creates durable pending approval and is never automatically approved. Recovery avoids duplicate occurrence identities and does not replay interrupted external actions as if their outcome were known. Cron is intentionally restricted to five fields with wildcard day/month and integer/range/list/wildcard minute/hour/weekday values.

## SECURITY

The model is a proposer only. External web, workspace, and browser content is untrusted. The runtime rechecks policy and kill switch immediately before provider execution, including after approval; unknown or unsupported abilities fail closed. Credentials remain broker-scoped and are not available to the model. Shell, desktop, unrestricted filesystem, authenticated browsing, and remote kill-switch control are disabled. The local database is not encrypted or tamper-proof against malicious code executing as the same OS user.

## TESTS

For this revision, `python -m pytest --collect-only -q` collected 296 tests and `python -m pytest -q` completed with **295 passed, 1 skipped**. `ruff check src tests`, `mypy src`, and `git diff --check` pass. Deterministic tests cover the restricted browser route, approval and verification boundary, malicious page instructions, forbidden destinations, redirects, kill-switch behavior, browser restart uncertainty, manual research/save, scheduled research/save, durable approval, restarts, and duplicate occurrence prevention. They do not replace deployment review or live provider configuration.

## LIMITATIONS

- Browser support is a restricted public-document subset; modern JavaScript-dependent sites, authenticated sessions, persistent profiles, subresources, uploads, and downloads are unsupported.
- Multi-person approval quorum and distributed approval/execution workers are not implemented; the durable workflow is scoped to the single local application owner.
- Browser remote side effects cannot be independently reconciled after process failure; the action remains uncertain and is not replayed automatically.
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
$env:BOLT_MAX_REPLANS = "4"
$env:BOLT_MAX_MODEL_CALLS = "8"
bolt doctor
bolt safety kill-switch status
```

Add `write_file` when reports should be saved. Add `browser` to `BOLT_ALLOWED_ACTIONS` and install Chromium only when browser actions are needed. Configure `$env:BOLT_MODEL_BASE_URL`, `$env:BOLT_MODEL_NAME`, and (for remote HTTPS providers) `$env:BOLT_MODEL_API_KEY` to opt into model planning; the task loop remains unavailable for model planning until a provider is configured. Do not put the model key in command arguments or task text. Review outstanding actions with `bolt approval list`; use `bolt approval show`, `approve`, or `deny` with the approval ID to make a decision. The default database is under the current user's local application-data directory; `--database <path>` overrides it per command.

## EXAMPLES

Assuming the settings above:

```powershell
bolt task submit "search the web for official Python 3.13 release notes"
bolt task submit "fetch https://docs.python.org/3/whatsnew/3.13.html"
bolt task submit "list files"
bolt task submit "read file README.md"
bolt task submit "create file research-notes.txt with key findings"
bolt task submit "Open https://example.com, inspect the page, and summarize its visible content."
bolt schedule create --execution-mode objective --objective "Research official Python release news, summarize sources, and save a report" --run-at 2030-01-07T08:00:00Z --type cron --cron-expression "0 8 * * 1-5" --timezone-policy UTC
bolt scheduler start
bolt approval list
bolt approval show <approval-id>
bolt approval approve <approval-id>
bolt action uncertain --json
bolt safety kill-switch engage
bolt safety kill-switch release
```

The file-creation and browser examples may leave pending approvals for the operator to review and decide using the approval commands. The cron example is a weekday objective schedule; configure its model, web, and workspace permissions explicitly. The final two examples are local operator controls.

## What is deliberately unsupported

- **General-purpose browser execution:** authenticated sessions, JavaScript-dependent sites, arbitrary subresources, persistent browser state, upload/download, and browser recovery after interrupted side effects are unsupported. The restricted browser subset described above is the only registered route.
- **Authenticated browser sessions:** login, cookie/profile persistence, and automatic credential injection are unsupported.
- **Desktop, terminal, administrator, arbitrary filesystem, and destructive actions:** these are not built-in execution capabilities.
- **Independent verification of arbitrary external effects:** built-in providers verify bounded observable postconditions (browser page state, workspace state, and web response properties), but they cannot independently establish every remote side effect such as a purchase, message delivery, or account change.
- **Provider-specific browser reconciliation:** the application cannot infer a remote side effect from a page still being open. Browser actions interrupted during execution remain uncertain and blocked.
- **Multi-person or distributed approvals:** the approval record is durable, but the application does not implement quorum decisions or distributed execution/approval workers.
- **Distributed execution:** SQLite and the process lock support one local application owner, not multi-host workers or distributed leases.

## Operating guidance

1. Install the package. To use the restricted browser ability, install Playwright Chromium with `py -m playwright install chromium`; browser use is still gated by explicit configuration.
2. Use the documented per-user SQLite location or an explicit protected local path. Back up the database using an application-consistent procedure. Do not use network filesystems or multiple application processes against one database.
3. Enable only required action kinds. Public network reads require both `network_read` allowlisting and `BOLT_ENABLE_EXTERNAL_INTEGRATIONS=true`; workspace writes additionally need the configured root and `write_file`.
4. Configure a model endpoint only when needed. Use HTTPS for remote endpoints and inject the API key through a protected process environment. Never place credentials in task prompts or model output.
5. Run `bolt doctor` and `bolt safety kill-switch status` before enabling work. Use `bolt safety kill-switch engage` for the persistent local stop. The emergency environment override takes precedence and must be changed by the process supervisor.
6. Inspect uncertain actions with `bolt action uncertain` and reconcile only through an independently validated provider. Do not manually edit journal records to force completion or retry.
7. Treat audit records as operational evidence, not a tamper-proof forensic log. The local database is not encrypted or protected from malicious code running as the same OS user.

## Readiness gaps and classification

| Gap | Classification | Consequence |
|---|---|---|
| General-purpose browser support and browser reconciliation after restart | Out of scope/provider capability limitation | Only the restricted public-document subset is enabled; interrupted browser side effects remain uncertain and are not automatically replayed. |
| Atomicity across an external provider side effect and SQLite journal commit | Fundamentally impossible to guarantee with a local transaction | A crash can always leave an uncertain outcome; provider idempotency or independent reconciliation is needed to resolve it. |
| Production verification adapters for actual external effects | Provider capability limitation and deployment/configuration work | Completion is not independently verified unless the application injects a trustworthy verifier. |
| OS-backed credential backend outside supported Windows configuration | Deployment/configuration work | Credential-value operations fail closed on unsupported platforms. |
| Hardened service installation, backup, OS permissions, monitoring, and model endpoint configuration | Deployment/configuration work | Operators must supply and maintain host-level controls; the repository does not set them up automatically. |
