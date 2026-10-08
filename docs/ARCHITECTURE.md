# Architecture and Security Model

## Core flow

A trusted system or user instruction creates a `Task`. External material is represented separately as `UntrustedContent`; it is context, never an instruction or permission grant. A proposed `ActionRequest` passes through `DefaultPolicyEngine`, then the kill-switch gate and (when required) an `ApprovalProvider`. Only then does an `ActionProvider` execute it. Optional verification runs afterward; failures are sent to the recovery boundary. Every state and policy decision is written to an `AuditSink`.

## Security invariants

- Unknown and high-risk actions fail closed.
- No action kind is allowed by default.
- Browser, desktop, terminal/process, filesystem writes, administrator operations, and general network access have no built-in permission. Bounded public web-read, restricted public-document browser, and explicitly rooted workspace abilities are available only when configured and allowlisted.
- Credentials are never represented as values in task or action models. A `CredentialBroker` may issue only an opaque `CredentialHandle` to a trusted adapter.
- The model cannot bypass policy, approval, the kill switch, verification, or audit requirements.
- Untrusted external content cannot become trusted instructions through type conversion in the core.
- Audit records omit action parameters by default; adapters must avoid recording secrets.

## Threat assumptions

The planner/model may be confused, prompt-injected, compromised, or wrong. External web, document, process, and tool output is hostile or malformed. Providers may fail or return false success. The host, Python runtime, and deployment credentials are trusted infrastructure; hardening those is an operational responsibility. This foundation does not claim to prevent a malicious provider implementation from violating its contract.

## Browser control layer

The restricted browser capability is routed through `AgentService`, `AgentExecutionLoop`, the ability registry/router, `AgentRuntime`, `BrowserAbilityProvider`, and `PlaywrightBrowserProvider`. Playwright objects remain private to the adapter. The registered subset supports bounded navigation, inspect/extract, accessible-target click, non-sensitive field fill, bounded waits, and explicitly authorized form submission. It is available only with explicit browser allowlisting and external integration enablement. See [BROWSER.md](BROWSER.md).

The planner/executor split is mandatory: planning is untrusted with respect to execution authority, while the runtime, policy engine, approval gate, and provider boundary remain the trusted execution path. Browser tasks are stateful, auditable, and bounded. External webpage text remains `UNTRUSTED_WEB` and never becomes trusted instructions; only trusted system or user instructions may grant capability.

Browser data is tagged `UNTRUSTED_WEB`; page text, hidden HTML, metadata, accessibility names, redirects, and tool output cannot become trusted instructions. Read actions are low risk, field filling is medium risk, and clicks/submissions are high risk and require existing durable approval plus typed outcome verification. The browser has no persistent profile, credential login, cookies, uploads, downloads, JavaScript, frames, or subresource access. A local SOCKS5 egress proxy resolves and pins public destinations; navigation permits only HTTPS on port 443, while request filtering rejects subresources and revalidates redirects. Interrupted browser side effects remain uncertain and are not replayed automatically.

The model may propose typed browser operations, but browser plans cannot grant risk, approval, policy, or verification authority. No arbitrary JavaScript, Browser Use, Midscene, visual CUA, vector database, or computer-use model is included.

## Extension points

Implement `ActionProvider`, `ApprovalProvider`, `VerificationProvider`, `RecoveryProvider`, `AuditSink`, `KillSwitch`, and `CredentialBroker` in separate trusted-adapter packages. Each adapter should have its own least-privilege permissions, contract tests, timeout policy, redaction rules, and integration tests. Add new action kinds only with an explicit risk classification, policy tests, and documentation.

## Agent-brain control layer

The agent-brain package sits above the runtime as a planner and orchestration layer. It is intentionally not an execution authority. The flow is:

User Request
  -> Task Interpreter
  -> Context Compiler
  -> Model Router
  -> Planner
  -> Plan Validator
  -> Ability Registry lookup
  -> Policy / Approval / Runtime
  -> Provider execution
  -> Verification / Recovery

The planner produces typed steps with ability names, actions, arguments, verification requirements, and risk metadata. The runtime and policy engine remain the authoritative guardrails. Unknown abilities, unsupported actions, prompt injection, and missing verification fail closed.

## Scheduled objectives

The scheduler persists objective, caller ownership, schedule, enabled state, and occurrence identities. For objective schedules, each due occurrence invokes the `AgentService` task executor, which enters the same `AgentExecutionLoop` used by manual submissions. Planning, model/tool budgets, ability validation, runtime policy, credential broker, approval, kill switch, verification, persistence, and audit therefore remain shared; the scheduler has no direct provider invocation path. High-risk actions remain pending until operator approval. Recovery uses durable occurrence/task state and does not automatically replay uncertain external effects.

## Current scope

This is the control-plane foundation, deterministic browser layer, bounded agent-brain planning layer, bounded public web-read ability, and explicitly rooted workspace file ability. There is no desktop, unrestricted filesystem, shell/process, administrator, authenticated web access, general network client, credential retrieval, AI browser, or visual-CUA implementation. The application composition root does not configure a model provider or interactive approval provider by default.
