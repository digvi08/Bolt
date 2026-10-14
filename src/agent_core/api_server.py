"""Conservative local Uvicorn entry point for the authenticated API."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import socket
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from .api_auth import ApiCredentialStore
from .application import AgentApplication, AgentApplicationError
from .config import AgentConfig, load_config


def _environment_config() -> AgentConfig:
    return load_config(
        {
            "allowed_actions": os.environ.get("BOLT_ALLOWED_ACTIONS", ""),
            "approval_required_at": os.environ.get("BOLT_APPROVAL_REQUIRED_AT", "medium"),
            "max_automatic_risk": os.environ.get("BOLT_MAX_AUTOMATIC_RISK", "low"),
            "enable_external_integrations": os.environ.get(
                "BOLT_ENABLE_EXTERNAL_INTEGRATIONS", "false"
            ),
            "max_replans": os.environ.get("BOLT_MAX_REPLANS", "2"),
            "max_tool_calls": os.environ.get("BOLT_MAX_TOOL_CALLS", "8"),
            "max_model_calls": os.environ.get("BOLT_MAX_MODEL_CALLS", "3"),
            "max_total_tokens": os.environ.get("BOLT_MAX_TOTAL_TOKENS", "4096"),
        }
    )


def create_default_app(
    database_path: str | Path | None = None,
    credential_path: str | Path | None = None,
    *,
    start_scheduler: bool = False,
) -> FastAPI:
    config = _environment_config()
    from agent_brain.model_router import ModelRouter
    from agent_brain.remote_model import create_model_provider_from_environment

    model_provider = create_model_provider_from_environment()
    model_router = (
        ModelRouter(
            providers=[model_provider],
            fallback_to_deterministic=False,
            max_model_calls=config.max_model_calls,
            max_total_tokens=config.max_total_tokens,
        )
        if model_provider is not None
        else None
    )
    application = AgentApplication(
        database_path,
        config=config,
        workspace_root=os.environ.get("BOLT_WORKSPACE_ROOT") or None,
        model_router=model_router,
    )
    credential_store = ApiCredentialStore(credential_path)
    application.start(
        api_credentials=credential_store,
        start_scheduler_on_api_start=start_scheduler,
    )
    app = application.api
    app.state.agent_application = application
    assets = Path(__file__).with_name("ui")

    @app.middleware("http")
    async def dashboard_security_headers(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)
        if request.url.path in {"/", "/ui"} or request.url.path.startswith("/assets/"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
            )
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
        return response

    app.mount("/assets", StaticFiles(directory=assets / "assets"), name="ui-assets")

    @app.get("/", include_in_schema=False)
    @app.get("/ui", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(assets / "index.html")

    return app


def _loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bolt-api")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--database")
    parser.add_argument("--credential-store")
    parser.add_argument(
        "--start-scheduler",
        action="store_true",
        help="explicitly start the durable scheduler with the API process",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not _loopback_host(args.host):
        parser.error(
            "non-loopback binding is disabled; expose the loopback listener only through "
            "a separately secured TLS reverse proxy"
        )
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    try:
        app = create_default_app(
            args.database,
            args.credential_store,
            start_scheduler=args.start_scheduler,
        )
    except AgentApplicationError as error:
        parser.exit(1, f"ERROR: {error.message}\n")
    except (OSError, ValueError) as error:
        if isinstance(error, ValueError):
            parser.exit(
                2,
                "ERROR: invalid local configuration; check BOLT_ALLOWED_ACTIONS, "
                "BOLT_APPROVAL_REQUIRED_AT, BOLT_MAX_AUTOMATIC_RISK, BOLT_MAX_REPLANS, "
                "BOLT_MAX_TOOL_CALLS, BOLT_MAX_MODEL_CALLS, BOLT_MAX_TOTAL_TOKENS, "
                "BOLT_MODEL_BASE_URL, BOLT_MODEL_NAME, and BOLT_MODEL_API_KEY.\n",
            )
        parser.exit(1, f"ERROR: application startup failed ({type(error).__name__})\n")
    listener: socket.socket | None = None
    try:
        config = uvicorn.Config(
            app,
            host=args.host,
            port=args.port,
            workers=1,
            access_log=False,
        )
        listener = config.bind_socket()
        uvicorn.Server(config).run(sockets=[listener])
    except KeyboardInterrupt:
        return 0
    except OSError:
        parser.exit(
            1,
            f"ERROR: could not bind Bolt UI to {args.host}:{args.port}; "
            "check whether the port is already in use.\n",
        )
    finally:
        if listener is not None:
            listener.close()
        application = getattr(app.state, "agent_application", None)
        if isinstance(application, AgentApplication):
            asyncio.run(application.shutdown())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["create_default_app", "main"]
