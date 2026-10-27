from __future__ import annotations

import argparse
import asyncio
import json
import ssl
from dataclasses import asdict

from .gateway import Gateway
from .store import SQLiteStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WorkBuddy Gateway administration and server CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    bootstrap = subparsers.add_parser("bootstrap", help="create a Team, User, and Agent")
    bootstrap.add_argument("--db", default="gateway.db")
    bootstrap.add_argument("--team-name", required=True)
    bootstrap.add_argument("--user-name", required=True)
    bootstrap.add_argument("--agent-name", required=True)

    pairing = subparsers.add_parser("pairing-code", help="create a one-time Worker pairing code")
    pairing.add_argument("--db", default="gateway.db")
    pairing.add_argument("--team-id", required=True)
    pairing.add_argument("--agent-id", required=True)
    pairing.add_argument("--ttl-seconds", type=int, default=600)
    pairing.add_argument("--max-attempts", type=int, default=5)

    revoke = subparsers.add_parser("revoke-worker", help="revoke a Worker device")
    revoke.add_argument("--db", default="gateway.db")
    revoke.add_argument("--worker-id", required=True)

    serve = subparsers.add_parser("serve", help="run the Gateway HTTP/WSS server")
    serve.add_argument("--db", default="gateway.db")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--cert-file")
    serve.add_argument("--key-file")

    return parser


async def _serve(args: argparse.Namespace, gateway: Gateway) -> None:
    context = None
    if bool(args.cert_file) != bool(args.key_file):
        raise SystemExit("--cert-file and --key-file must be supplied together")
    if args.cert_file:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert_file, args.key_file)
    await gateway.start(host=args.host, port=args.port, ssl_context=context)
    print(json.dumps({"worker_url": gateway.worker_url}), flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await gateway.stop()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    store = SQLiteStore(args.db)
    try:
        if args.command == "bootstrap":
            result = store.bootstrap(args.team_name, args.user_name, args.agent_name)
            print(
                json.dumps(
                    {
                        "team": asdict(result.team),
                        "user": asdict(result.user),
                        "agent": asdict(result.agent),
                    }
                )
            )
            return 0
        if args.command == "pairing-code":
            result = store.create_pairing_code(
                args.team_id,
                args.agent_id,
                ttl_seconds=args.ttl_seconds,
                max_attempts=args.max_attempts,
            )
            print(json.dumps(asdict(result)))
            return 0
        if args.command == "revoke-worker":
            result = store.revoke_worker(args.worker_id)
            print(json.dumps(asdict(result)))
            return 0
        if args.command == "serve":
            asyncio.run(_serve(args, Gateway(store)))
            return 0
    finally:
        store.close()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
