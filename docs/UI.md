# Bolt local dashboard

Run `bolt ui` to start the dashboard and authenticated API on `127.0.0.1:8765`. Optional arguments are `--host` (loopback only), `--port`, `--credential-store`, and the global `--database` option (`bolt --database PATH ui`). The UI startup explicitly starts the existing durable scheduler. The API server is single-process and uses the existing application ownership lock; Ctrl+C shuts down the scheduler, browser provider, database, and ownership lock cleanly.

The HTML, CSS, and JavaScript shell is served locally. It does not authorize operations. API data and actions remain behind the existing bearer authentication, resource ownership checks, and per-route scopes. Create a token in a trusted terminal with `bolt-auth create --scope SCOPE` (repeat `--scope` for each capability); the raw token is shown once. Paste it in Connect API. The page keeps it in memory only, sends it only to same-origin API paths, and discards it on disconnect or tab close. Do not paste the token into a shared or untrusted browser profile.

For all dashboard pages and controls, a local operator can issue a token with:

```powershell
bolt-auth create `
  --scope application.read `
  --scope task.read `
  --scope task.submit `
  --scope approval.read `
  --scope approval.approve `
  --scope approval.deny `
  --scope schedule.read `
  --scope schedule.create `
  --scope schedule.modify `
  --scope schedule.cancel `
  --scope scheduler.read `
  --scope audit.read `
  --scope safety.read `
  --scope safety.control
```

These permissions do not bypass runtime policy, resource ownership, approval, verification, recovery, or the kill switch. Keep separate lower-scope credentials for read-only use. The API does not enable permissive CORS.

## Pages

- **Dashboard** reads application diagnostics, scheduler status, visible tasks, and pending approvals.
- **Tasks / New Task** list, filter, inspect, and submit through the authenticated AgentService API.
- **Research / Browser** are objective-submission helpers over the same execution pipeline; they do not add providers or direct execution paths. Browser capability remains the restricted, policy-allowlisted browser documented in [BROWSER.md](BROWSER.md).
- **Approvals** call the durable approve/deny API endpoints. Decisions are backend-authenticated and resume or deny the existing task.
- **Schedules** create persisted objective schedules, show the actual occurrence records returned by the API, and enable, disable, or cancel schedules.
- **Activity & Audit** shows event type, task identifier, and time, deliberately omitting free-form event details.
- **Safety** reads the authoritative backend status and submits a confirmed kill-switch transition requiring `safety.control`.
- **Settings & Diagnostics** displays non-secret configuration readiness. It never reads or displays model keys, API tokens, authorization headers, or provider output.

The token must include the corresponding existing API scopes; a page reports authorization failures rather than substituting mock data. Schedules show persisted occurrence status and approval waits; actions that require approval remain pending until an operator decides through the durable approval system. Browser navigation and external side effects retain the existing documented limitations.
