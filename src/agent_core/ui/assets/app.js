(() => {
  "use strict";

  const content = document.querySelector("#content");
  const notice = document.querySelector("#notice");
  const credentialDialog = document.querySelector("#credential-dialog");
  const tokenInput = document.querySelector("#api-token");
  const connectionLabel = document.querySelector("#connection-label");
  const statusDot = document.querySelector(".status-dot");
  const approvalCount = document.querySelector("#approval-count");
  let token = "";
  let currentPage = "dashboard";
  let messageTimer;

  const pageTitles = {
    dashboard: ["Overview", "Your local agent at a glance."],
    tasks: ["Tasks", "Inspect real task state from the secured application API."],
    "new-task": ["New task", "Submit a natural-language objective to the existing execution pipeline."],
    research: ["Research", "Run bounded public web research through your configured agent."],
    browser: ["Browser", "Use only the restricted browser capability configured in Bolt."],
    approvals: ["Approvals", "Review consequential actions waiting in the durable approval queue."],
    schedules: ["Schedules", "Create and manage persisted natural-language objectives."],
    activity: ["Activity & audit", "Review sanitized audit records from the local application."],
    safety: ["Safety", "Inspect the authoritative kill switch and scheduler state."],
    settings: ["Settings & diagnostics", "Check readiness and diagnose local configuration without exposing secrets."]
  };

  function node(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  }

  function button(label, className, handler) {
    const item = node("button", `button ${className || "button-light"}`, label);
    item.type = "button";
    item.addEventListener("click", handler);
    return item;
  }

  function card(title, extra) {
    const section = node("section", "card");
    const header = node("div", "card-heading");
    header.append(node("h2", "", title));
    if (extra) header.append(node("span", "muted", extra));
    section.append(header);
    return section;
  }

  function heading(title, description, action) {
    const root = node("div", "page-heading");
    const left = node("div");
    left.append(node("p", "eyebrow", "BOLT / LOCAL"));
    left.append(node("h1", "", title));
    left.append(node("p", "", description));
    root.append(left);
    if (action) root.append(action);
    return root;
  }

  function badge(value, status) {
    const text = String(value || "unknown").replaceAll("_", " ");
    const normalized = String(status || value || "").toLowerCase();
    const tone = ["succeeded", "completed", "verified", "approved", "enabled", "ready"].includes(normalized)
      ? "badge-good"
      : ["failed", "denied", "uncertain", "active", "engaged"].includes(normalized)
        ? "badge-bad"
        : ["waiting approval", "awaiting approval", "pending", "degraded", "disabled"].includes(normalized)
          ? "badge-warn" : "";
    return node("span", `badge ${tone}`, text);
  }

  function showNotice(text, isError) {
    clearTimeout(messageTimer);
    notice.textContent = text;
    notice.className = `notice${isError ? " error" : ""}`;
    notice.hidden = false;
    messageTimer = setTimeout(() => { notice.hidden = true; }, 6500);
  }

  async function api(path, options) {
    if (!token) throw new Error("Connect with a local API token to continue.");
    const headers = new Headers(options && options.headers ? options.headers : {});
    headers.set("Authorization", `Bearer ${token}`);
    if (options && options.body) headers.set("Content-Type", "application/json");
    const response = await fetch(path, { ...options, headers, credentials: "omit", cache: "no-store" });
    if (response.status === 401) {
      disconnect();
      throw new Error("Authentication failed. Check the token, then connect again.");
    }
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const message = payload && payload.error && payload.error.message
        ? payload.error.message : `Request failed (${response.status}).`;
      throw new Error(message);
    }
    return payload;
  }

  function disconnect() {
    token = "";
    connectionLabel.textContent = "Not connected";
    statusDot.classList.remove("connected");
    document.querySelector("#credential-button").textContent = "Connect API";
    approvalCount.hidden = true;
  }

  async function connect(value) {
    token = value.trim();
    try {
      await api("/application/status");
      connectionLabel.textContent = "Connected to local API";
      statusDot.classList.add("connected");
      document.querySelector("#credential-button").textContent = "Disconnect";
      credentialDialog.close();
      tokenInput.value = "";
      showNotice("Connected. The token is held in memory only.", false);
      await render();
    } catch (error) {
      disconnect();
      showNotice(error.message, true);
    }
  }

  async function attempt(work) {
    try {
      return await work();
    } catch (error) {
      showNotice(error.message || "The operation failed.", true);
      return null;
    }
  }

  function setContent(children) {
    content.replaceChildren(...children);
  }

  function safeTime(value) {
    if (!value) return "Not available";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }

  function row(title, subtitle, status, rightAction) {
    const item = node("div", "row");
    const main = node("div", "row-main");
    main.append(node("div", "row-title", title || "Untitled"));
    if (subtitle) main.append(node("div", "row-sub", subtitle));
    item.append(main);
    if (rightAction) item.append(rightAction);
    else item.append(badge(status));
    return item;
  }

  async function load(path) {
    try { return { data: await api(path), error: "" }; }
    catch (error) {
      return { data: null, error: error.message || "Request failed." };
    }
  }

  async function renderDashboard() {
    const [statusResult, tasksResult, approvalsResult, schedulerResult] = await Promise.all([
      load("/application/status"),
      load("/tasks?limit=8"),
      load("/approvals?limit=100"),
      load("/scheduler/status")
    ]);
    const status = statusResult.data;
    const tasks = tasksResult.data;
    const approvals = approvalsResult.data;
    const scheduler = schedulerResult.data;
    if (!status && !tasks && !approvals && !scheduler) {
      const panel = card("Connect to your local agent");
      panel.append(node("p", "muted", "Use a scoped bearer token to read application state and operate the pages available to that credential."));
      if (token) {
        panel.append(node("p", "form-help", statusResult.error || tasksResult.error || approvalsResult.error || schedulerResult.error));
      }
      panel.append(button("Connect API", "button-primary", () => credentialDialog.showModal()));
      setContent([heading(...pageTitles.dashboard), panel]);
      return;
    }
    const recent = Array.isArray(tasks) ? tasks.slice(0, 5) : [];
    const approvalsList = Array.isArray(approvals) ? approvals : [];
    const stats = node("div", "grid stats");
    const statValues = [
      ["Recent tasks", Array.isArray(tasks) ? tasks.length : "—", tasks ? "Visible to this credential" : tasksResult.error],
      ["Pending approvals", approvals ? approvalsList.filter(item => item.status === "pending").length : "—", approvals ? "Durable operator decisions" : approvalsResult.error],
      ["Scheduler", scheduler ? (scheduler.running ? "Running" : "Stopped") : "—", scheduler ? `${scheduler.active_occurrences || 0} active occurrences` : schedulerResult.error],
      ["Kill switch", status ? (status.kill_switch_active ? "Engaged" : "Released") : "—", status ? "Authoritative local control" : statusResult.error]
    ];
    for (const [label, value, note] of statValues) {
      const panel = node("section", "card stat-card");
      panel.append(node("div", "stat-label", label), node("div", "stat-value", value), node("div", "stat-note", note));
      stats.append(panel);
    }
    approvalCount.textContent = String(approvalsList.filter(item => item.status === "pending").length);
    approvalCount.hidden = !approvalsList.some(item => item.status === "pending");

    const recentCard = card("Recent tasks", "Latest visible");
    if (!recent.length) recentCard.append(node("div", "empty", tasks ? "No tasks yet." : tasksResult.error));
    for (const task of recent) {
      recentCard.append(row(task.objective, `${String(task.task_id || "").slice(0, 12)} · ${safeTime(task.updated_at)}`, task.status,
        button("View", "button-light", () => { location.hash = `#tasks/${encodeURIComponent(task.task_id)}`; })));
    }
    const health = card("Application state");
    if (status) {
      health.append(row("Application", status.application_state, status.application_state));
      const modelStatus = status.model_provider || {};
      health.append(row("Model provider", modelStatus.ready ? `${modelStatus.provider_count} configured · reachable` : (modelStatus.configured ? modelStatus.diagnostic : "Not configured"), modelStatus.ready ? "ready" : (modelStatus.available === false ? "failed" : "pending")));
      health.append(row("Workspace", status.workspace && status.workspace.configured ? status.workspace.diagnostic : "Not configured", status.workspace && status.workspace.valid ? "ready" : "pending"));
      const browserReady = Boolean(status.browser && status.browser.available && status.browser.playwright_installed && status.browser.chromium_installed);
      health.append(row("Restricted browser", browserReady ? "Registered · Playwright and Chromium available" : (status.browser && status.browser.available ? status.browser.diagnostic : "Unavailable by policy/configuration"), browserReady ? "ready" : "pending"));
      health.append(row("Persistence", status.persistence_available ? "Available" : "Unavailable", status.persistence_available ? "ready" : "failed"));
    } else health.append(node("div", "empty", statusResult.error));
    setContent([heading(...pageTitles.dashboard), stats, node("div", "grid two-col", ""), recentCard, health]);
    content.children[2].append(recentCard, health);
  }

  async function renderTasks(taskId) {
    if (taskId) {
      const task = await api(`/tasks/${encodeURIComponent(taskId)}`);
      const details = card("Task details", String(task.task_id || ""));
      const fields = [
        ["Objective", task.objective], ["Status", task.status], ["Verification", task.verification_state],
        ["Approval required", task.approval_required ? "Yes" : "No"], ["Uncertain", task.uncertain ? "Yes" : "No"],
        ["Created", safeTime(task.created_at)], ["Updated", safeTime(task.updated_at)],
        ["Failure", task.last_error || "None"]
      ];
      const list = node("dl", "detail-list");
      for (const [key, value] of fields) {
        list.append(node("dt", "", key), node("dd", "", value));
      }
      details.append(list);
      if (Array.isArray(task.actions) && task.actions.length) {
        const actions = card("Action verification", "Sanitized status only");
        for (const action of task.actions) actions.append(row(action.name, `Verification: ${action.verification_status || "pending"}`, action.status));
        setContent([heading("Task details", "Task state returned by the authenticated API."), details, actions]);
      } else setContent([heading("Task details", "Task state returned by the authenticated API."), details]);
      return;
    }
    const shell = heading(...pageTitles.tasks);
    const filter = node("select");
    filter.setAttribute("aria-label", "Filter tasks by status");
    for (const value of [
      "all", "created", "planned", "planning", "running", "waiting_approval",
      "awaiting_approval", "executing", "verifying", "recovering", "succeeded",
      "completed", "failed", "denied", "stopped", "aborted", "uncertain"
    ]) {
      const option = node("option", "", value.replaceAll("_", " "));
      option.value = value;
      filter.append(option);
    }
    const refresh = button("Refresh", "button-light", () => render());
    const toolbar = node("div", "toolbar");
    toolbar.append(filter, refresh);
    const panel = card("Task history");
    const tasks = await api("/tasks?limit=100");
    const list = Array.isArray(tasks) ? tasks : [];
    const populate = () => {
      panel.replaceChildren(panel.firstChild);
      const visible = filter.value === "all"
        ? list
        : filter.value === "uncertain"
          ? list.filter(item => item.uncertain)
          : list.filter(item => item.status === filter.value);
      if (!visible.length) panel.append(node("div", "empty", "No tasks match this filter."));
      for (const task of visible) {
        panel.append(row(task.objective, `${task.task_id} · ${safeTime(task.updated_at)}`, task.status,
          button("Inspect", "button-light", () => { location.hash = `#tasks/${encodeURIComponent(task.task_id)}`; })));
      }
    };
    filter.addEventListener("change", populate);
    populate();
    setContent([shell, toolbar, panel]);
  }

  async function submitObjective(objective, label) {
    if (!objective.trim()) throw new Error("Enter an objective first.");
    const result = await api("/tasks", {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ objective: objective.trim() })
    });
    const task = result && result.task ? result.task : result;
    const panel = card(`${label} submitted`);
    panel.append(row(String(task.task_id || "Task id unavailable"), `Verification: ${task.verification_state || "pending"} · Approval required: ${task.approval_required ? "yes" : "no"}`, task.status));
    panel.append(node("p", "form-help", task.uncertain ? "The outcome is uncertain. Do not retry the external action until it has been reconciled." : (task.last_error || "The task status shown above is the actual API response. Refresh Tasks to inspect later updates.")));
    if (typeof result.output === "string" && result.output) {
      const output = card("Task result", "Untrusted text · rendered as plain text");
      output.append(node("pre", "result-text", result.output.slice(0, 12000)));
      panel.append(output);
    }
    setContent([heading(label, "Submitted through the authenticated AgentService execution path."), panel]);
    showNotice("Task submitted to Bolt.", false);
  }

  function objectiveForm(title, description, initial, submitLabel) {
    const form = node("form", "card");
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const text = form.querySelector("textarea").value;
      await attempt(() => submitObjective(text, title));
    });
    form.append(node("p", "eyebrow", "NATURAL LANGUAGE OBJECTIVE"));
    form.append(node("p", "muted", description));
    const label = node("label", "", "What should Bolt do?");
    const textarea = node("textarea");
    const textareaId = `objective-${crypto.randomUUID()}`;
    textarea.id = textareaId;
    label.htmlFor = textareaId;
    textarea.required = true;
    textarea.maxLength = 8000;
    textarea.value = initial || "";
    textarea.setAttribute("aria-label", "Task objective");
    form.append(label, textarea);
    const actions = node("div", "form-actions");
    const submit = node("button", "button button-primary", submitLabel || "Submit task");
    submit.type = "submit";
    actions.append(submit);
    form.append(actions);
    return form;
  }

  async function renderNewTask() {
    setContent([heading(...pageTitles["new-task"]), objectiveForm("Task", "Bolt plans and executes only actions permitted by current policy, approval, verification, and safety controls.", "", "Submit task")]);
  }

  async function renderResearch() {
    setContent([
      heading(...pageTitles.research),
      node("div", "callout", "Research uses the existing model and public web abilities. Model and external integration configuration are required; all retrieved page content remains untrusted."),
      objectiveForm("Research", "Example: Compare official sources on the latest Python release, summarize the differences, and save the report to my workspace.", "Research the latest Python release. Compare several official sources, summarize the key changes, and save the report to my workspace.", "Start research")
    ]);
  }

  async function renderBrowser() {
    const status = await api("/application/status");
    const browser = status.browser || {};
    const panel = card("Restricted browser status");
    panel.append(row("Capability", browser.available ? "Registered with the runtime" : "Not available", browser.available ? "ready" : "disabled"));
    panel.append(row("Playwright", browser.playwright_installed ? "Installed" : "Missing", browser.playwright_installed ? "ready" : "failed"));
    panel.append(row("Chromium", browser.chromium_installed ? "Installed" : "Missing", browser.chromium_installed ? "ready" : "failed"));
    panel.append(node("p", "form-help", browser.diagnostic || "Browser availability is determined by application configuration."));
    const warning = node("div", "callout callout-warn", "This is not general browsing. The backend permits only the configured restricted public HTTPS subset. Consequential actions stop for durable approval. No page can approve its own actions.");
    setContent([heading(...pageTitles.browser), warning, panel, objectiveForm("Browser task", "Describe a restricted browser operation. Availability and execution remain controlled by the backend runtime.", "Open https://example.org and summarize the page.", "Submit browser task")]);
  }

  async function renderApprovals() {
    const approvals = await api("/approvals?limit=100");
    const panel = card("Durable approval queue", "Backend decisions only");
    const list = Array.isArray(approvals) ? approvals : [];
    const pending = list.filter(item => item.status === "pending");
    if (!pending.length) panel.append(node("div", "empty", "No pending approvals visible to this credential."));
    for (const item of list) {
      const controls = node("div", "top-actions");
      if (item.status === "pending") {
        controls.append(button("Approve", "button-success", async () => {
          if (!confirm("Approve this exact pending action? Bolt will resume execution under its existing policy and verification controls.")) return;
          const response = await attempt(() => api(`/approvals/${encodeURIComponent(item.approval_id)}/approve`, { method: "POST" }));
          if (response) { showNotice("Approval decision recorded by Bolt.", false); await render(); }
        }));
        controls.append(button("Deny", "button-danger-light", async () => {
          if (!confirm("Deny this action?")) return;
          const response = await attempt(() => api(`/approvals/${encodeURIComponent(item.approval_id)}/deny`, { method: "POST" }));
          if (response) { showNotice("Denial recorded by Bolt.", false); await render(); }
        }));
      }
      panel.append(row(item.summary || item.action_kind || "Action requires review", `${item.approval_id} · task ${item.task_id} · expires ${safeTime(item.expires_at)}`, item.status, controls));
    }
    setContent([heading(...pageTitles.approvals), panel]);
  }

  async function renderSchedules() {
    const schedules = await api("/schedules?limit=100");
    const createPanel = card("Create objective schedule");
    const form = node("form", "stack");
    const objectiveLabel = node("label", "", "Natural-language objective");
    const objective = node("textarea");
    objective.id = "schedule-objective";
    objectiveLabel.htmlFor = objective.id;
    objective.required = true;
    objective.maxLength = 8000;
    objective.placeholder = "Research official Python release notes and save a concise report.";
    const firstRunLabel = node("label", "", "First run (local time)");
    const firstRun = node("input");
    firstRun.id = "schedule-first-run";
    firstRunLabel.htmlFor = firstRun.id;
    firstRun.type = "datetime-local";
    firstRun.required = true;
    const cadenceLabel = node("label", "", "Cadence");
    const cadence = node("select");
    cadence.id = "schedule-cadence";
    cadenceLabel.htmlFor = cadence.id;
    for (const [value, text] of [["run_at", "Once"], ["interval", "Repeat every N seconds"], ["cron", "Cron expression"]]) {
      const option = node("option", "", text); option.value = value; cadence.append(option);
    }
    const intervalLabel = node("label", "", "Interval (seconds)");
    const interval = node("input"); interval.type = "number"; interval.min = "60"; interval.value = "86400";
    interval.id = "schedule-interval";
    intervalLabel.htmlFor = interval.id;
    const cronLabel = node("label", "", "Cron expression (UTC)");
    const cron = node("input"); cron.placeholder = "0 8 * * 1-5";
    cron.id = "schedule-cron";
    cronLabel.htmlFor = cron.id;
    const fields = node("div", "form-grid");
    fields.append(firstRunLabel, firstRun, cadenceLabel, cadence, intervalLabel, interval, cronLabel, cron);
    cadence.addEventListener("change", () => {
      interval.disabled = cadence.value !== "interval";
      cron.disabled = cadence.value !== "cron";
    });
    cadence.dispatchEvent(new Event("change"));
    form.append(objectiveLabel, objective, fields);
    form.append(node("p", "form-help", "Schedules use the existing scheduler and model task pipeline. They never gain extra permissions or auto-approve actions."));
    const create = node("button", "button button-primary", "Create schedule"); create.type = "submit";
    const actions = node("div", "form-actions"); actions.append(create); form.append(actions);
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const when = new Date(firstRun.value);
      if (Number.isNaN(when.getTime())) { showNotice("Choose a valid first-run time.", true); return; }
      const scheduleType = cadence.value;
      const body = {
        objective: objective.value.trim(),
        execution_mode: "objective",
        run_at: when.toISOString(),
        schedule_type: scheduleType,
        timezone_policy: "UTC"
      };
      if (scheduleType === "interval") body.interval_seconds = Number(interval.value);
      if (scheduleType === "cron") body.cron_expression = cron.value.trim();
      const created = await attempt(() => api("/schedules", { method: "POST", body: JSON.stringify(body) }));
      if (created) { showNotice(`Schedule created: ${created.schedule_id}`, false); await render(); }
    });
    createPanel.append(form);
    const listPanel = card("Persisted schedules", "Actual API schedule records");
    const list = Array.isArray(schedules) ? schedules : [];
    if (!list.length) listPanel.append(node("div", "empty", "No schedules visible to this credential."));
    const occurrenceGroups = await Promise.all(list.map(async schedule => {
      try {
        return { items: await api(`/schedules/${encodeURIComponent(schedule.schedule_id)}/occurrences?limit=20`), error: "" };
      } catch (error) {
        return { items: [], error: error.message || "Occurrence state is unavailable." };
      }
    }));
    for (const [index, schedule] of list.entries()) {
      const actions = node("div", "top-actions");
      actions.append(button(schedule.enabled ? "Disable" : "Enable", "button-light", async () => {
        const changed = await attempt(() => api(`/schedules/${encodeURIComponent(schedule.schedule_id)}/${schedule.enabled ? "disable" : "enable"}`, { method: "POST" }));
        if (changed) await render();
      }));
      if (schedule.status !== "cancelled" && schedule.status !== "completed") actions.append(button("Cancel", "button-danger-light", async () => {
        if (!confirm("Cancel this persisted schedule?")) return;
        const changed = await attempt(() => api(`/schedules/${encodeURIComponent(schedule.schedule_id)}/cancel`, { method: "POST" }));
        if (changed) await render();
      }));
      listPanel.append(row(schedule.objective, `${schedule.schedule_id} · ${schedule.schedule_type} · ${schedule.occurrence_count} occurrences · next ${safeTime(schedule.next_occurrence)}`, schedule.status, actions));
      const occurrences = occurrenceGroups[index].items;
      for (const occurrence of occurrences) {
        listPanel.append(row(
          `Occurrence ${occurrence.occurrence_id}`,
          `Scheduled ${safeTime(occurrence.scheduled_for)} · updated ${safeTime(occurrence.updated_at)} · ${occurrence.uncertain ? "uncertain outcome" : `success: ${occurrence.success === null ? "pending" : occurrence.success}`}`,
          occurrence.status
        ));
      }
      if (occurrenceGroups[index].error) {
        listPanel.append(node("div", "form-help", `Occurrence status unavailable: ${occurrenceGroups[index].error}`));
      }
    }
    setContent([heading(...pageTitles.schedules), createPanel, listPanel]);
  }

  async function renderActivity() {
    const events = await api("/audit?limit=100");
    const panel = card("Recent audit events", "Sensitive details omitted");
    const list = Array.isArray(events) ? events.slice().reverse() : [];
    if (!list.length) panel.append(node("div", "empty", "No audit events visible to this credential."));
    for (const event of list) {
      panel.append(row(event.event_type, `${safeTime(event.occurred_at)} · task ${event.task_id || "—"}`, "recorded"));
    }
    setContent([heading(...pageTitles.activity), node("div", "callout", "Audit data is displayed as text. Event details, provider output, and untrusted page content are intentionally not rendered here."), panel]);
  }

  async function renderSafety() {
    const [status, application] = await Promise.all([api("/safety/status"), api("/application/status")]);
    const active = Boolean(application.kill_switch_active || status.kill_switch_active);
    const panel = card("Persistent kill switch", "Authoritative backend state");
    panel.append(row("State", active ? "Engaged — new actions blocked" : "Released — policy still applies", active ? "active" : "ready"));
    panel.append(row("Scheduler", status.running ? "Running" : "Stopped", status.running ? "ready" : "pending"));
    panel.append(row("Uncertain actions", status.uncertain_actions, status.uncertain_actions ? "uncertain" : "verified"));
    const control = button(active ? "Release kill switch" : "Engage kill switch", active ? "button button-success" : "button button-danger", async () => {
      const changeTo = !active;
      const prompt = changeTo
        ? "Engage the persistent kill switch? New runtime actions will be blocked."
        : "Release the persistent kill switch? Runtime policy and approvals still apply.";
      if (!confirm(prompt)) return;
      const result = await attempt(() => api("/safety/kill-switch", { method: "POST", body: JSON.stringify({ active: changeTo }) }));
      if (result) { showNotice(`Kill switch ${result.active ? "engaged" : "released"} by the backend.`, false); await render(); }
    });
    const box = node("div", "form-actions"); box.append(control); panel.append(box);
    setContent([heading(...pageTitles.safety), node("div", "callout callout-warn", "This control changes the application’s persistent kill switch. It does not change policy, grant permissions, or approve pending actions."), panel]);
  }

  async function renderSettings() {
    const status = await api("/application/status");
    const panel = card("Configuration diagnostics", `Application state: ${status.application_state || "unknown"}`);
    const modelStatus = status.model_provider || {};
    const records = [
      ["Model provider", modelStatus.ready ? `${modelStatus.provider_count} provider(s) reachable` : (modelStatus.configured ? modelStatus.diagnostic : "Not configured — set BOLT_MODEL_BASE_URL and BOLT_MODEL_NAME; remote endpoints also require BOLT_MODEL_API_KEY.")],
      ["Workspace root", status.workspace && status.workspace.diagnostic],
      ["Browser provider", status.browser && (status.browser.available ? "Registered by current policy and integration settings" : "Unavailable; allowlist browser and enable external integrations.")],
      ["Playwright", status.browser && (status.browser.playwright_installed ? "Installed" : "Missing from this Python environment")],
      ["Chromium", status.browser && status.browser.diagnostic],
      ["Scheduler", status.scheduler && (status.scheduler.running ? "Running" : "Stopped")],
      ["Approval provider", status.approval_provider_available ? "Durable approvals configured" : "Unavailable"],
      ["Verification provider", status.verification_provider_available ? "Configured" : "Provider-specific verification only; general verification unavailable"],
      ["External integrations", status.external_integrations_enabled ? "Enabled explicitly" : "Disabled (default)"],
      ["Allowed action kinds", Array.isArray(status.allowed_action_kinds) ? status.allowed_action_kinds.join(", ") || "None" : "Unavailable"],
      ["Application ownership", status.single_process_owner_held ? "Held by this process" : "Not held"],
      ["Persistence", status.persistence_available ? "Available" : "Unavailable"]
    ];
    const list = node("dl", "detail-list");
    for (const [name, value] of records) list.append(node("dt", "", name), node("dd", "", value || "Not available"));
    panel.append(list);
    const scopes = [
      "application.read", "task.read", "task.submit", "approval.read", "approval.approve", "approval.deny",
      "schedule.read", "schedule.create", "schedule.modify", "schedule.cancel", "scheduler.read",
      "audit.read", "safety.read", "safety.control"
    ];
    const command = node("div", "command-box");
    command.textContent = `Create a token with only the capabilities you need:\nbolt-auth create ${scopes.map(scope => `--scope ${scope}`).join(" ")}`;
    const help = node("div", "callout callout-warn", "Startup/authentication problems: confirm the local process is running, then check the terminal output. If Chromium is missing, run `py -m playwright install chromium`. Invalid BOLT_* values stop startup and are reported in the terminal; secret values are never shown here.");
    setContent([heading(...pageTitles.settings), panel, command, help]);
  }

  async function render() {
    const hash = location.hash.slice(1) || "dashboard";
    const [page, ...parts] = hash.split("/");
    currentPage = pageTitles[page] ? page : "dashboard";
    document.querySelectorAll("#navigation a[data-page]").forEach(link => {
      link.classList.toggle("active", link.dataset.page === currentPage);
      link.setAttribute("aria-current", link.dataset.page === currentPage ? "page" : "false");
    });
    content.setAttribute("aria-busy", "true");
    content.replaceChildren(node("div", "empty", "Loading live application state…"));
    try {
      if (!token && !["dashboard"].includes(currentPage)) {
        setContent([heading(...pageTitles[currentPage]), node("div", "callout callout-warn", "Connect a bearer token with the matching API scopes to use this page.")]);
        return;
      }
      if (currentPage === "dashboard") await renderDashboard();
      else if (currentPage === "tasks") await renderTasks(parts.length ? decodeURIComponent(parts.join("/")) : null);
      else if (currentPage === "new-task") await renderNewTask();
      else if (currentPage === "research") await renderResearch();
      else if (currentPage === "browser") await renderBrowser();
      else if (currentPage === "approvals") await renderApprovals();
      else if (currentPage === "schedules") await renderSchedules();
      else if (currentPage === "activity") await renderActivity();
      else if (currentPage === "safety") await renderSafety();
      else if (currentPage === "settings") await renderSettings();
    } catch (error) {
      setContent([heading(...pageTitles[currentPage]), node("div", "callout callout-error", error.message || "Unable to load this page.")]);
    } finally {
      content.setAttribute("aria-busy", "false");
    }
  }

  document.querySelector("#credential-button").addEventListener("click", () => {
    if (token) {
      disconnect();
      showNotice("Disconnected. The in-memory token was cleared.", false);
      render();
    } else credentialDialog.showModal();
  });
  document.querySelector("#connect-button").addEventListener("click", () => connect(tokenInput.value));
  document.querySelector("#refresh-button").addEventListener("click", () => render());
  document.querySelector("#credential-form").addEventListener("submit", event => event.preventDefault());
  window.addEventListener("hashchange", () => render());
  render();
})();
