"""Loopback-only synthetic broker fixture; imports real infra authority handlers."""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import time
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pyotp
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))
gateway = import_module("broker_gateway")
oauth = import_module("broker_oauth")
store = import_module("policy_store")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="coding-broker-smoke-") as temporary:
        directory = Path(temporary)
        secret = pyotp.random_base32()
        seed = directory / "totp.seed"
        seed.write_text(secret)
        seed.chmod(0o600)
        os.environ["MCP_PROXY_TOTP_SEED"] = str(seed)
        conn = store.init_db(directory / "policy.db")
        conn.execute("INSERT INTO profiles (name) VALUES ('coding')")
        conn.execute(
            "INSERT INTO servers (server_id, url) VALUES ('nexus', 'https://unused.example/mcp')"
        )
        conn.execute("INSERT INTO profile_servers VALUES ('coding', 'nexus')")
        conn.execute(
            "INSERT INTO profile_tool_rules VALUES ('coding', 'allow', 'nexus.get_*')"
        )
        conn.execute(
            "INSERT INTO capabilities (key, trusted_title, trusted_description, max_ttl_seconds, default_ttl_seconds) VALUES ('extra', 'Extra', 'Synthetic extra grant', 3600, 3600)"
        )
        conn.execute("INSERT INTO capability_servers VALUES ('extra', 'nexus')")
        conn.execute("INSERT INTO capability_tools VALUES ('extra', 'nexus.extra')")
        conn.execute(
            "INSERT INTO catalogue_versions (hash, source) VALUES ('smoke', 'test')"
        )
        conn.commit()
        presence = SimpleNamespace(enabled=True)
        credential, reference = store.coding_authorization.create(
            conn, oauth.CODING_OWNER, presence=presence
        )

        async def initial(_request: Request) -> JSONResponse:
            issued: dict[str, Any] = store.coding_authorization.issue(
                conn, credential, oauth.CODING_OWNER
            )
            issued["cohort_credential"] = credential
            sid = store.authenticate(conn, issued["access_token"])["id"]
            store.create_grant(
                conn, sid, "extra", approved_via="cli", presence=presence
            )
            return JSONResponse(issued, headers={"Cache-Control": "no-store"})

        forwards: dict[str, int] = {}
        pause_on_call = False
        rejected_calls = 0

        async def control(request: Request) -> JSONResponse:
            nonlocal pause_on_call
            action = request.path_params["action"]
            if action == "pause-on-call":
                pause_on_call = True
                return JSONResponse({"reference": reference})
            if action == "pause-only":
                conn.execute("UPDATE coding_authorizations SET expires_at = '2000-01-01T00:00:00.000Z'")
                conn.commit()
                return JSONResponse({"reference": reference})
            if action == "pause":
                conn.execute(
                    "UPDATE coding_authorizations SET expires_at = '2000-01-01T00:00:00.000Z'"
                )
                sessions = conn.execute(
                    "SELECT id FROM sessions ORDER BY id"
                ).fetchall()
                conn.execute(
                    "UPDATE sessions SET idle_expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?",
                    (sessions[0][0],),
                )
                conn.execute(
                    "UPDATE sessions SET expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?",
                    (sessions[1][0],),
                )
                conn.execute(
                    "UPDATE session_grants SET expires_at = '2000-01-01T00:00:00.000Z'"
                )
                conn.commit()
                store.revoke_session(conn, sessions[-1][0])
                return JSONResponse({"status": "paused", "reference": reference})
            if action == "totp":
                return JSONResponse(
                    {"totp": pyotp.TOTP(secret).at(int(time.time()) + 30)}
                )
            if action == "counts":
                return JSONResponse(
                    {
                        "forwards": forwards,
                        "rejected_calls": rejected_calls,
                        "renewals": conn.execute(
                            "SELECT count(*) FROM coding_authorization_events WHERE event_type = 'renewed'"
                        ).fetchone()[0]
                    }
                )
            return JSONResponse({"error": "unknown"}, status_code=400)

        async def mcp(request: Request) -> Response:
            nonlocal pause_on_call, rejected_calls
            bearer = request.headers.get("authorization", "").removeprefix("Bearer ")
            message = await request.json()
            method = message.get("method")
            if "id" not in message:
                return Response(status_code=202)
            if method == "initialize":
                return JSONResponse({"jsonrpc": "2.0", "id": message["id"], "result": {
                    "protocolVersion": message["params"]["protocolVersion"], "capabilities": {"tools": {}},
                    "serverInfo": {"name": "synthetic-coding-broker", "version": "1"},
                }})
            if method == "tools/list":
                return JSONResponse({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": [{
                    "name": "nexus.get_task", "inputSchema": {"type": "object", "properties": {}},
                }]}})
            if method in ("resources/list", "prompts/list"):
                return JSONResponse({"jsonrpc": "2.0", "id": message["id"], "result": {method.split("/")[0]: []}})
            if method == "tools/call" and pause_on_call:
                pause_on_call = False
                conn.execute("UPDATE coding_authorizations SET expires_at = '2000-01-01T00:00:00.000Z'")
                conn.commit()
            outcome = gateway.handle_tools_call(message, bearer, conn)
            if outcome.response and outcome.response.get("error", {}).get("data", {}).get("status") == "authorization_paused":
                rejected_calls += 1
            if outcome.forward is not None:
                key = str(message.get("params", {}).get("arguments", {}).get("operation", "legacy"))
                forwards[key] = forwards.get(key, 0) + 1
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": "synthetic downstream accepted",
                                }
                            ]
                        },
                    }
                )
            return JSONResponse(outcome.response, status_code=outcome.http_status)

        app = Starlette(
            routes=[
                *[
                    Route(
                        f"/broker/coding/{operation}",
                        oauth.coding_credentials,
                        methods=["POST"],
                    )
                    for operation in ("enroll", "replace", "status")
                ],
                Route("/broker/coding/renew", oauth.coding_renew_get, methods=["GET"]),
                Route(
                    "/broker/coding/renew", oauth.coding_renew_post, methods=["POST"]
                ),
                Route("/__test/initial", initial, methods=["POST"]),
                Route("/__test/{action}", control, methods=["POST"]),
                Route("/broker/mcp", mcp, methods=["POST"]),
            ]
        )
        app.state.policy_conn = conn
        app.state.broker_oauth = oauth.BrokerOAuthState()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
            port = listener.getsockname()[1]
            app.state.broker_oauth.resource = f"http://127.0.0.1:{port}/broker/mcp"
            print(f"http://127.0.0.1:{port}", flush=True)
            server = uvicorn.Server(
                uvicorn.Config(app, log_level="critical", access_log=False)
            )
            try:
                server.run(sockets=[listener])
            finally:
                conn.close()


if __name__ == "__main__":
    main()
