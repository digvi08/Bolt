# Architecture and Security Model

## Core flow

A trusted system or user instruction creates a `Task`. External material is represented separately as `UntrustedContent`; it is context, never an instruction or permission grant. A proposed `ActionRequest` passes through `DefaultPolicyEngine`, then the kill-switch gate and (when required) an `ApprovalProvider`. Only then does an `ActionProvider` execute it. Optional verification runs afterward; failures are sent to the recovery boundary. Every state and policy decision is written to an `AuditSink`.

## Security invariants

- Unknown and high-risk actions fail closed.
- No action kind is allowed by default.
- Browser, desktop, terminal/process, filesystem writes, administrator operations, and network access have no built-in implementation or permission.
- Credentials are never represented as values in task or action models. A `CredentialBroker` may issue only an opaque `CredentialHandle` to a trusted adapter.
- The model cannot bypass policy, approval, the kill switch, verification, or audit requirements.
- Untrusted external content cannot become trusted instructions through type conversion in the core.
- Audit records omit action parameters by default; adapters must avoid recording secrets.

## Threat assumptions

The planner/model may be confused, prompt-injected, compromised, or wrong. External web, document, process, and tool output is hostile or malformed. Providers may fail or return false success. The host, Python runtime, and deployment credentials are trusted infrastructure; hardening those is an operational responsibility. This foundation does not claim to prevent a malicious provider implementation from violating its contract.

## Browser control layer

The browser capability is a separate typed layer: `AgentRuntime` gates a registered `BrowserActionProvider`, which delegates to `PlaywrightBrowserProvider`. Playwright objects remain private to the adapter. The provider exposes sessions, tabs, navigation, DOM/accessibility-first observations, form actions, structured extraction, and explicit screenshots. A project-owned `BrowserPlanner` composes deterministic `BrowserAction` objects without direct Playwright access. See [BROWSER.md](BROWSER.md).

The planner/executor split is mandatory: planning is untrusted with respect to execution authority, while the runtime, policy engine, approval gate, and provider boundary remain the trusted execution path. Browser tasks are stateful, auditable, and bounded. External webpage text remains `UNTRUSTED_WEB` and never becomes trusted instructions; only trusted system or user instructions may grant capability.

Browser data is tagged `UNTRUSTED_WEB`; page text, hidden HTML, metadata, accessibility names, redirects, and tool output cannot become trusted instructions. Read actions are low risk, reversible interactions are medium risk, and submit/sensitive actions are high risk requiring explicit browser allowlisting, approval, and verification. Persistent sessions are opt-in and credential login is only a contract at this milestone.

The intended strategy is deterministic Playwright automation first, a future AI browser adapter second, and visual computer-use fallback last. No Browser Use, Midscene, visual CUA, vector database, or computer-use model is included.

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

## Current scope

This is the control-plane foundation, deterministic browser layer, and bounded agent-brain planning layer. There is no desktop, unrestricted filesystem, shell/process, administrator, network, credential retrieval, AI browser, or visual-CUA implementation.
