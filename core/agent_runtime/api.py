"""Read-only Web/API handlers for agent runtime views.

This module exposes pure handler functions plus an optional aiohttp route
registrar. Importing it does not start a server or bind a port.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Mapping
from urllib.parse import urlparse

from core.agent_runtime.models import AgentRunState
from core.agent_runtime.registry import GLOBAL_RUNTIME_RUN_REGISTRY
from core.agent_runtime.views import build_run_view, build_runs_index

RunStore = Mapping[str, AgentRunState]


def _resolve_run_store(run_store: RunStore | None = None) -> RunStore:
    return run_store if run_store is not None else GLOBAL_RUNTIME_RUN_REGISTRY


def get_run_view_response(run_id: str, run_store: RunStore | None = None) -> Dict[str, Any]:
    """Return a read-only run view response for Web/API use."""
    store = _resolve_run_store(run_store)
    run_state = store.get(run_id)
    if not run_state:
        return {
            "success": False,
            "error": "run_not_found",
            "run_id": run_id,
        }
    return {
        "success": True,
        "data": build_run_view(run_state),
    }


def get_runs_index_response(run_store: RunStore | None = None) -> Dict[str, Any]:
    """Return a read-only index response for all known runs."""
    store = _resolve_run_store(run_store)
    return get_runs_index_response_from_states(list(store.values()))


def get_runs_index_response_from_states(run_states: list[AgentRunState]) -> Dict[str, Any]:
    """Return a read-only index response from an explicit state list."""
    return get_runs_index(run_states)


def get_runs_index(run_states: list[AgentRunState]) -> Dict[str, Any]:
    """Compatibility wrapper around build_runs_index."""
    return build_runs_index(run_states)


def register_aiohttp_routes(
    app: Any, run_store: RunStore | None = None, prefix: str = "/api/runs"
) -> Any:
    """Register read-only aiohttp routes on an existing app.

    The caller owns app creation, auth, transport, and server startup.
    """
    from aiohttp import web

    async def list_runs(_request):
        return web.json_response(get_runs_index_response(run_store))

    async def get_run(request):
        return web.json_response(get_run_view_response(request.match_info["run_id"], run_store))

    app.router.add_get(prefix, list_runs)
    app.router.add_get(f"{prefix}/{{run_id}}", get_run)
    return app


def make_runtime_http_handler(run_store: RunStore | None = None, prefix: str = "/api/runs"):
    """Create a stdlib read-only HTTP handler for runtime views."""
    store = _resolve_run_store(run_store)

    class RuntimeAPIHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler API
            parsed = urlparse(self.path)
            if parsed.path == prefix:
                self._send_json(get_runs_index_response(store))
                return
            if parsed.path.startswith(f"{prefix}/"):
                run_id = parsed.path[len(prefix) + 1 :]
                status = 200 if store.get(run_id) else 404
                self._send_json(get_run_view_response(run_id, store), status=status)
                return
            self._send_json({"success": False, "error": "not_found"}, status=404)

        def log_message(self, _format, *_args):
            return

        def _send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return RuntimeAPIHandler


def serve_runtime_http(
    run_store: RunStore | None = None, host: str = "127.0.0.1", port: int = 8765
):
    """Serve read-only runtime views with Python stdlib HTTP server."""
    server = ThreadingHTTPServer((host, port), make_runtime_http_handler(run_store))
    server.serve_forever()
