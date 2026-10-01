"""Conservative local Uvicorn entry point for the authenticated API."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from .api_auth import ApiCredentialStore
from .application import AgentApplication, AgentApplicationError


def create_default_app(
    database_path: str | Path | None = None,
    credential_path: str | Path | None = None,
    *,
    start_scheduler: bool = False,
) -> FastAPI:
    application = AgentApplication(database_path)
    credential_store = ApiCredentialStore(credential_path)
    application.start(
        api_credentials=credential_store,
        start_scheduler_on_api_start=start_scheduler,
    )
    app = application.api
    app.state.agent_application = application
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
    try:
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            workers=1,
            access_log=False,
        )
    except KeyboardInterrupt:
        return 0
    finally:
        application = getattr(app.state, "agent_application", None)
        if isinstance(application, AgentApplication):
            asyncio.run(application.shutdown())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["create_default_app", "main"]
