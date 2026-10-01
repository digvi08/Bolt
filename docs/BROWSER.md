# Browser Control Layer

## Trust and execution flow

```text
Trusted Task
  -> AgentRuntime policy / kill switch / approval
  -> BrowserActionProvider (typed action registry)
  -> PlaywrightBrowserProvider
  -> DOM and accessibility observation
  -> browser verification
  -> audit and bounded recovery
```

The forbidden flow is `LLM -> unrestricted Playwright`. The runtime owns the final execution gate. Browser actions are registered as project-owned `BrowserAction` values and converted to policy requests; Playwright page, context, locator, and browser objects never leave the adapter.

## Deterministic-first strategy

The initial backend is Playwright and observations prefer visible DOM/accessibility data. Screenshots are explicit observation values for verification or future visual reasoning, not the default model input. Future `BrowserUseProvider`, `MidsceneProvider`, and `VisualCUAProvider` implementations can satisfy the same provider boundary without changing the task manager, policy, audit, or runtime.

## Trust boundary

Every page-derived string is wrapped as `UntrustedContent` and tagged with `untrusted_web`. Page text, hidden attributes, metadata, accessibility names, redirects, and tool output cannot become trusted instructions. Prompt-injection text is data and cannot change policy decisions.

## Planner/executor separation

The planner produces typed `BrowserAction` objects and a `BrowserPlan`, but never calls Playwright directly. The execution boundary remains `BrowserAction -> BrowserActionProvider -> AgentRuntime -> Policy -> Approval -> PlaywrightBrowserProvider`. A future `BrowserPlanner` implementation may be model-backed, but the trusted runtime remains the final authority.

## Action lifecycle

Each action may declare preconditions and verification. Planning is deterministic and auditable; before execution the runtime observes the page, validates preconditions, checks policy, requests approval for consequential actions, executes the action, and then verifies the resulting state. If a page no longer matches the expectation, execution stops and the system re-observes or aborts.

## Preconditions and stale-page protection

`BrowserPrecondition` captures expected role, name, label, URL domain, text, or type. If the page changes unexpectedly, the runtime treats the state as mismatched instead of clicking a possibly wrong element. Recovery is bounded and every invalidation is auditable.

## Verification

Typed verification specs such as `ExpectedURL`, `ExpectedText`, `ExpectedElement`, `ExpectedElementAbsent`, `ExpectedFormValue`, and `ExpectedDownload` allow deterministic confirmation. Consequential actions require state-level verification; a successful Playwright click alone is not a successful task.

## Consequential actions and approval timing

High-impact actions require approval immediately before execution. The approval prompt contains a plain-language description of the action but excludes credentials, cookies, tokens, and other secrets. The system never approves stale plans after assumptions change.

## Popup and download handling

Popup creation is represented as a typed tab transition and downloads are represented as untrusted `BrowserDownload` artifacts. Downloaded files are never executed automatically and can only be handled by an explicit allowlisted policy path.

## Bounded execution and trust boundary

Browser tasks have bounded action, recovery, and duration limits. Unknown or high-risk actions fail closed. External webpage content is wrapped as `UNTRUSTED_WEB` and can never become trusted instructions merely because a model or planner observed it.

The invariant is: External webpage content NEVER becomes trusted instructions merely because the planner/model observed it.

## Credentials and sessions

`login` and `use_authenticated_session` exist as capability contracts but are intentionally unimplemented. Browser observations redact password, OTP, token, secret, and file fields. Persistent browser context is opt-in through `start_session(persistent_state_path=...)`; the path is recorded as configuration metadata, but authentication state is never written to normal audit records. Deployments must protect that path with OS-level permissions and encryption at rest where appropriate.

## Recovery and verification

`BoundedBrowserRecovery` permits only a finite number of retries and classifies transient, stale-element, and navigation-timeout failures. Consequential actions require a `BrowserVerificationProvider`; verification failure enters the existing runtime recovery path. Site-specific adapters should verify URL, state, confirmation text, downloads, or other expected effects without recording sensitive data.

## Testing

Tests use only local fixture HTML served by an in-process deterministic HTTP server. No third-party websites or live credentials are needed.
