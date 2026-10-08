# Restricted Browser

Browser actions are registered only when both `browser` is explicitly allowlisted and external integrations are enabled. They are routed through the same `AgentService` → `AgentExecutionLoop` → `AbilityRouter` → `AgentRuntime` path as other actions; no task runner or model has a direct Playwright execution path.

```text
user/model proposal
  -> typed, schema-checked browser action
  -> AgentService / AgentExecutionLoop
  -> AbilityRegistry / AbilityRouter
  -> AgentRuntime policy, kill switch, durable approval, audit
  -> BrowserAbilityProvider
  -> restricted Playwright provider and pinned egress proxy
  -> typed state verification and persisted action outcome
```

## Supported subset

The registered operations are `navigate`, `inspect`, `extract`, `click`, `fill`, `wait`, and `submit`. There is no arbitrary JavaScript, shell, cookie or credential access, file upload, download, unrestricted file access, persistent browser profile, or authenticated login. Playwright runs headless with JavaScript, service workers, downloads, frames, and non-document network requests disabled. Only a bounded HTTPS document navigation and a specifically authorized form submission can leave the browser context.

Observations are capped at 20,000 characters and 200 elements. Waits are bounded to two seconds; page operations have a timeout. Form filling rejects password, file, hidden, and fields whose labels suggest passwords, secrets, one-time codes, or tokens. Form submission is limited to GET/POST and is authorized for one request to the observed form destination. `click` and `submit` are high risk and require the existing durable operator approval; `fill` is medium risk under the default approval policy.

## Network boundary

The browser does not rely on checking only its starting URL:

- URL validation permits HTTPS on port 443 only and rejects credentials in URLs and literal non-public IP addresses.
- Every browser request is intercepted. Only main-frame HTTPS documents to the validated current host are permitted; subresources, frames, and other requests fail closed.
- Browser TCP egress uses a local SOCKS5 proxy. The proxy resolves the requested host itself, rejects non-global addresses (including loopback, private, link-local, mapped, and special addresses), and connects to the validated IP rather than resolving it again at connect time.
- The proxy permits port 443 only and bounds concurrent connections, bytes per connection, idle time, and tunnel lifetime. Redirects are new intercepted document requests and must independently pass the same checks.
- Chromium is configured to use the proxy without its loopback bypass, with non-proxied WebRTC UDP and QUIC disabled.

This is a deliberately narrow public-document browser, not a general-purpose browser or a substitute for a host firewall. It cannot prove safety against a compromised browser/runtime or malicious same-user process, and it does not provide an independent reconciliation source for remote side effects. On a crash, an interrupted browser action remains uncertain and is not replayed automatically.

## Trust, authority, and verification

All page text, titles, URLs, labels, attributes, and extracted content are `UNTRUSTED_WEB`. Page content is supplied to the planner only as untrusted tool output. It cannot modify risk or policy, approve actions, disable the kill switch, access credentials, or call another provider. A proposed click or submission still passes trusted registry validation and runtime policy; high-risk interactions stop for durable approval.

Verification examines typed observations rather than treating a successful Playwright call as task completion. It can check the requested and landed HTTPS destination, expected page text or element, the observed non-sensitive form value, and the state after a click or submission. Click and submit plans must specify an observable expected outcome. A mismatch or missing observation fails verification; an interrupted external side effect remains uncertain.

## Setup and example

Install Chromium once, configure a model provider for model-directed form interaction, and explicitly enable the restricted browser:

```powershell
py -m pip install -e .
py -m playwright install chromium
$env:BOLT_ALLOWED_ACTIONS = "browser"
$env:BOLT_ENABLE_EXTERNAL_INTEGRATIONS = "true"
$env:BOLT_MODEL_BASE_URL = "https://model.example/v1"
$env:BOLT_MODEL_NAME = "your-model"
$env:BOLT_MODEL_API_KEY = "<provide through a protected environment>"
$env:BOLT_MAX_REPLANS = "4"
$env:BOLT_MAX_MODEL_CALLS = "8"
bolt doctor
bolt task submit "Open https://example.com, inspect the page, and summarize its visible content."
```

For a consequential form operation, submit the task and inspect each pending approval before allowing the next consequential action:

```powershell
bolt task submit "Open https://your-approved-fixture.example, inspect the form, fill the requested non-sensitive fields, then submit and verify the confirmation."
bolt approval list
bolt approval show <approval-id>
bolt approval approve <approval-id>
```

Filling a field may pause for approval under the default medium-risk threshold; click and submit actions have separate high-risk approvals. An approval is action-bound and single-use. Approval does not bypass a later kill-switch or policy check. Do not put passwords, tokens, or other secrets in browser prompts.

## Tests and known limitations

Browser tests use deterministic Playwright page fixtures and exercise the registered ability/runtime path, navigation, extraction, click, filling, durable approval/resumption, verification, restart behavior, prompt-injection containment, private-address rejection, dangerous redirects, and kill-switch blocking. The fixtures intercept a fixed test host in memory; they do not weaken production egress restrictions.

Modern sites that require JavaScript, subresources, authentication, uploads, or persistent cookies will not work. Browser-specific reconciliation of a remote side effect after process failure is not available, so uncertainty remains blocked for operator/provider review.
