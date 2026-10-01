"""Trusted local credential management; generated secrets are displayed exactly once."""

from __future__ import annotations

import argparse
import json
import sys

from .api_auth import ApiCredentialStore, ApiScope, CredentialStoreError, default_credential_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bolt-auth")
    parser.add_argument(
        "--store",
        default=str(default_credential_path()),
        help="credential metadata file (contains hashes only)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="create a credential")
    create.add_argument("--scope", action="append", choices=[scope.value for scope in ApiScope], required=True)
    rotate = commands.add_parser("rotate", help="rotate a credential; prior token becomes invalid")
    rotate.add_argument("credential_id")
    revoke = commands.add_parser("revoke", help="revoke a credential")
    revoke.add_argument("credential_id")
    commands.add_parser("status", help="list credential IDs, scopes, and revocation status")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        store = ApiCredentialStore(args.store)
        if args.command == "create":
            credential = store.create(frozenset(ApiScope(scope) for scope in args.scope))
            print(
                json.dumps(
                    {
                        "credential_id": credential.credential_id,
                        "scopes": sorted(scope.value for scope in credential.scopes),
                        "token": credential.token,
                        "warning": "Save this token now; it will not be displayed again.",
                    },
                    separators=(",", ":"),
                )
            )
        elif args.command == "rotate":
            credential = store.rotate(args.credential_id)
            print(
                json.dumps(
                    {
                        "credential_id": credential.credential_id,
                        "scopes": sorted(scope.value for scope in credential.scopes),
                        "token": credential.token,
                        "warning": "Save this token now; it will not be displayed again.",
                    },
                    separators=(",", ":"),
                )
            )
        elif args.command == "revoke":
            store.revoke(args.credential_id)
            print("Credential revoked.")
        else:
            print(
                json.dumps(
                    [
                        {
                            "credential_id": item.credential_id,
                            "scopes": [scope.value for scope in item.scopes],
                            "created_at": item.created_at,
                            "revoked": item.revoked,
                        }
                        for item in store.list_status()
                    ],
                    separators=(",", ":"),
                )
            )
        return 0
    except (CredentialStoreError, KeyError, ValueError):
        sys.stderr.write("ERROR: credential operation failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
