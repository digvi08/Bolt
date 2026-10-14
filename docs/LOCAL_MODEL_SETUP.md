# Local model setup with Ollama

Bolt can use an OpenAI-compatible local model without a cloud API key. The verified setup on this Windows machine is:

- Ollama executable: `%LOCALAPPDATA%\Programs\Ollama\ollama.exe`
- Ollama version: `0.40.4`
- Model identifier: `qwen2.5:3b` (Q4_K_M, approximately 1.9 GB)
- Endpoint: `http://127.0.0.1:11434/v1`
- API key: omitted

Bolt permits plain HTTP only for loopback model endpoints. Remote endpoints must use HTTPS and require `BOLT_MODEL_API_KEY`.

## Verify Ollama and the model

In PowerShell:

```powershell
$ollama = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'
& $ollama --version
& $ollama list
Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 5
Invoke-RestMethod -Uri 'http://127.0.0.1:11434/v1/models' -TimeoutSec 5
```

The Windows Ollama application normally starts the local service. If the endpoint is not responding, run `& $ollama serve` in a dedicated PowerShell window and leave it running. `ollama pull qwen2.5:3b` installs the model if it is not listed.

## Persist Bolt's model configuration

The provider reads these variables from the process environment at startup. Persist the non-secret values at Windows user scope:

```powershell
[Environment]::SetEnvironmentVariable('BOLT_MODEL_BASE_URL', 'http://127.0.0.1:11434/v1', 'User')
[Environment]::SetEnvironmentVariable('BOLT_MODEL_NAME', 'qwen2.5:3b', 'User')
```

No `BOLT_MODEL_API_KEY` is needed for this loopback configuration; leave it unset. Reopen PowerShell (or sign out and back in) after changing user-scope variables. To load the persisted values into an already-open shell:

```powershell
$env:BOLT_MODEL_BASE_URL = [Environment]::GetEnvironmentVariable('BOLT_MODEL_BASE_URL', 'User')
$env:BOLT_MODEL_NAME = [Environment]::GetEnvironmentVariable('BOLT_MODEL_NAME', 'User')
```

The provider configuration is held in memory. The endpoint and model name are not written to task records, and no API key is persisted for this local setup.

## Verify the actual provider and application

The model-list check is a bounded, non-generative `GET /v1/models` request. The dashboard and application diagnostics mark the provider ready only when the configured model identifier is returned by the endpoint; diagnostics do not generate model output on refresh.

```powershell
bolt doctor --json
```

Start the dashboard/API with the existing single-process application lifecycle:

```powershell
bolt ui
```

It binds to `127.0.0.1:8765` by default. The HTML shell may load without a token, but API operations require a bearer credential and their existing per-route scopes. See [UI.md](UI.md) for secure credential setup.

## Reproduce the harmless real-model task

Create a disposable workspace and allow only read-only actions for this PowerShell session:

```powershell
$workspace = Join-Path $env:TEMP 'bolt-local-model-workspace'
New-Item -ItemType Directory -Path $workspace -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $workspace 'probe.txt'), 'LOCAL_MODEL_READ_VERIFIED')
$env:BOLT_WORKSPACE_ROOT = $workspace
$env:BOLT_ALLOWED_ACTIONS = 'read_only'
bolt task submit 'Read the workspace file named probe.txt through the registered workspace provider. Fetch its contents from the file and return them verbatim.'
```

The task uses the configured model to select a registered action, then the ordinary ability router, runtime policy, workspace verification, task persistence, and audit path. The dashboard displays the task status and verification result. The `bolt doctor --json` readiness check is independent of this inference/execution test.

## Troubleshooting

- If `ollama list` works but `/v1/models` fails, start Ollama with `& $ollama serve` and confirm it is bound to `127.0.0.1:11434`.
- If `/v1/models` responds but does not list `qwen2.5:3b`, pull the model and verify the exact identifier returned by the endpoint.
- If diagnostics report the provider as unavailable, they mean the endpoint could not be queried within two seconds or did not list the configured model. This check does not send a generation request.
- If a task fails before creating an action, inspect its persisted task and audit state before retrying. A failed task with no action record is a planning/provider failure; an uncertain action must be reconciled rather than repeated.
- The local model is untrusted: its structured output is normalized only through explicit aliases, validated against registered capabilities and argument schemas, and still subject to runtime policy and verification.
- Never expose the Ollama port beyond loopback, put cloud credentials in source control, or use a model plan as evidence of approval or task verification.
