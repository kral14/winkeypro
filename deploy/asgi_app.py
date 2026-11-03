"""
WinKey Pro — Async Starlette & Uvicorn ASGI Application
Spesifikasiya: plan/GEMINI_WEBSOCKET_BATCH.md (Paket A, B, D)

Eyni port üzərində (PORT=8080/8788) həm HTTP, həm də daimi WebSocket xidməti:
1. Starlette ASGI əsaslı qeyri-bloklayıcı arxitektura.
2. PostgreSQL və SQLite üçün threadpool izolyasiyası (asyncio.to_thread).
3. /ws və /api/ws üzərindən Agent, Mobil və Admin daimi bağlantıları.
4. Sıfır HTTP sorğusu: Sağlam WS vaxtı status və nəticə push vasitəsilə çatdırılır.
"""

import asyncio
import json
import os
import secrets
import time
from typing import Dict, Any, Optional

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, JSONResponse, HTMLResponse
from starlette.responses import FileResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from deploy.gateway_service import GatewayService
from deploy.websocket_hub import (
    hub,
    ClientConnection,
    AUTH_DEADLINE_SECONDS,
    MAX_FRAME_BYTES
)

def is_newer_semver(candidate_ver: str, active_ver: str) -> bool:
    try:
        def parse(v):
            return tuple(int(re.match(r'^\d+', part).group(0)) if re.match(r'^\d+', part) else 0 for part in str(v).split('.'))
        return parse(candidate_ver) > parse(active_ver)
    except Exception:
        return True

def build_asgi_app(service: GatewayService, dashboard_html_path: Optional[str] = None) -> Starlette:
    from deploy.update_repository import UpdateRepository, MAX_PACKAGE
    repository = UpdateRepository()
    publication_lock = asyncio.Lock()



    async def broadcast_release(release):
        if not release:
            return
        payload = {'type':'update_available', 'version':release['version'], 'release_id':release['release_id']}
        for connections in list(hub._agents.values()):
            for connection in list(connections):
                if connection.is_active:
                    agent_ver = connection.metadata.get('version')
                    if agent_ver and not is_newer_semver(release['version'], agent_ver):
                        continue
                    connection.enqueue(payload)

    async def handle_update_latest(request):
        release = await asyncio.to_thread(repository.current)
        if not release:
            return JSONResponse({'error':'E_NO_UPDATES_AVAILABLE'},status_code=404)
        return JSONResponse(release,headers={'Cache-Control':'no-store'})

    async def handle_update_download(request):
        path = await asyncio.to_thread(repository.download,request.path_params['release'],request.path_params['name'])
        if not path:
            return JSONResponse({'error':'E_UPDATE_FILE_NOT_FOUND'},status_code=404)
        return FileResponse(path,media_type='application/octet-stream',headers={'Cache-Control':'public, max-age=31536000, immutable'})

    async def handle_update_publish(request):
        import hmac
        token = _get_bearer(request)
        if not token or not hmac.compare_digest(token,service.get_admin_secret()):
            return JSONResponse({'error':'E_FORBIDDEN_ADMIN'},status_code=403)
        body = bytearray()
        async for chunk in request.stream():
            if len(body)+len(chunk)>MAX_PACKAGE:
                return JSONResponse({'error':'E_PACKAGE_TOO_LARGE'},status_code=413)
            body.extend(chunk)
        async with publication_lock:
            try:
                release = await asyncio.to_thread(repository.publish,bytes(body))
            except Exception:
                return JSONResponse({'error':'E_SIGNED_RELEASE_REJECTED'},status_code=400)
        await broadcast_release(release)
        print('[UPDATE_PUBLISHED] version='+release['version'],flush=True)
        return JSONResponse({'published':True,'version':release['version'],'release_id':release['release_id']})

    def _security_headers(response: Response, duration_ms: int = 0) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; media-src 'self' blob:; img-src 'self' blob: data:;"
        )
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Owner-Admin-Secret"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        if duration_ms > 0:
            response.headers["X-App-Duration-Ms"] = str(duration_ms)
        return response

    def _json_resp(status: int, data: Dict[str, Any], start_mono: float) -> Response:
        duration_ms = round((time.monotonic() - start_mono) * 1000)
        resp = JSONResponse(data, status_code=status)
        return _security_headers(resp, duration_ms)

    def _get_bearer(request: Request) -> Optional[str]:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return None

    async def dispatch_claimed(device_id, cmd_id, action, created_at, timings=None):
        try:
            return await hub.push_command_to_agent(device_id, cmd_id, action, created_at, timings=timings)
        except RuntimeError:
            await asyncio.to_thread(service.fail_uncertain_delivery, cmd_id)
            await hub.push_command_result(device_id, cmd_id, False, "INDETERMINATE_DELIVERY", time.time())
            return False

    # --- HTTP HANDLERS ---

    async def handle_options(request: Request) -> Response:
        resp = Response(status_code=204)
        return _security_headers(resp)

    async def handle_healthz(request: Request) -> Response:
        start = time.monotonic()
        def _check():
            try:
                with service.db.get_conn() as conn:
                    conn.execute("SELECT 1").fetchone()
                return True
            except Exception:
                return False

        ok = await asyncio.to_thread(_check)
        if ok:
            return _json_resp(200, {"status": "ONLINE"}, start)
        return _json_resp(503, {"error": "E_DATABASE_UNAVAILABLE"}, start)

    async def handle_dashboard(request: Request) -> Response:
        start = time.monotonic()
        path = dashboard_html_path
        if not path or not os.path.isfile(path):
            fallback_dir = os.path.dirname(os.path.abspath(__file__))
            candidate = os.path.join(fallback_dir, "vm", "dashboard.html")
            if os.path.isfile(candidate):
                path = candidate
        if path and os.path.isfile(path):
            with open(path, "rb") as f:
                content = f.read().decode("utf-8")
        else:
            content = "<h1>WinKey Pro — Dashboard</h1>"
        resp = HTMLResponse(content, status_code=200)
        resp.headers["Cache-Control"] = "no-store"
        return _security_headers(resp, round((time.monotonic() - start) * 1000))

    async def handle_mobile_page(request: Request) -> Response:
        from deploy.gateway_production_server import get_mobile_html
        start = time.monotonic()
        html = get_mobile_html()
        resp = HTMLResponse(html, status_code=200)
        resp.headers["Cache-Control"] = "no-store"
        return _security_headers(resp, round((time.monotonic() - start) * 1000))

    async def handle_feature(request):
        from deploy.mobile_install import feature_request
        start = time.monotonic()
        try:
            body = await request.json()
            if not isinstance(body, dict): raise ValueError()
        except Exception:
            return _json_resp(400, {'error': 'E_INPUT'}, start)
        status, data = await asyncio.to_thread(feature_request, service, request.url.path, body, _get_bearer(request))
        if status == 200 and request.url.path in ('/accounts/device-action','/accounts/logout'):
            snapshot = await asyncio.to_thread(service.device_snapshot,body.get('device_id'))
            if snapshot:
                await hub.push_device_state(snapshot['device_id'],bool(snapshot['locked']),bool(snapshot['pin_ready']),online=snapshot['online'])
            if body.get('action') == 'delete':
                await hub.disconnect_device_mobiles(body.get('device_id'))
        response = _json_resp(status, data, start)
        response.headers['Cache-Control'] = 'no-store'
        return response

    async def handle_mobile_asset(request):
        from deploy.mobile_install import manifest
        from pathlib import Path
        asset = request.path_params['asset']
        if asset == 'manifest.webmanifest':
            response = JSONResponse(manifest(request.query_params.get('install', '')), media_type='application/manifest+json')
            response.headers['Cache-Control'] = 'no-store'
            return _security_headers(response)
        if asset in ('devices.js', 'jsQR.js', 'icon.png'):
            return _security_headers(FileResponse(Path(__file__).parent / 'static' / asset, media_type='image/png' if asset == 'icon.png' else 'application/javascript'))
        return Response(status_code=404)

    async def handle_admin_page(request: Request) -> Response:
        from deploy.gateway_production_server import get_admin_html
        start = time.monotonic()
        html = get_admin_html()
        resp = HTMLResponse(html, status_code=200)
        resp.headers["Cache-Control"] = "no-store"
        return _security_headers(resp, round((time.monotonic() - start) * 1000))

    async def handle_admin_devices(request: Request) -> Response:
        start = time.monotonic()
        admin_sec = request.headers.get("x-owner-admin-secret")
        status, data = await asyncio.to_thread(service.admin_get_devices, admin_sec)
        if status == 200:
            release = await asyncio.to_thread(repository.current)
            for device in data.get('devices',[]):
                device['latest_version'] = release['version'] if release else None
        return _json_resp(status, data, start)

    async def handle_admin_telemetry(request: Request) -> Response:
        start = time.monotonic()
        admin_sec = request.headers.get("x-owner-admin-secret")
        status, data = await asyncio.to_thread(service.admin_get_telemetry, admin_sec)
        return _json_resp(status, data, start)

    async def handle_device_status(request: Request) -> Response:
        start = time.monotonic()
        device_id = request.path_params.get("device_id", "")
        token = _get_bearer(request)
        status, data = await asyncio.to_thread(service.get_device_status, device_id, token)
        return _json_resp(status, data, start)

    async def handle_command_status(request: Request) -> Response:
        start = time.monotonic()
        cmd_id = request.path_params.get("command_id", "")
        token = _get_bearer(request)
        status, data = await asyncio.to_thread(service.get_command_status, cmd_id, token)
        return _json_resp(status, data, start)

    async def handle_agent_challenge(request: Request) -> Response:
        start = time.monotonic()
        try:
            body = await request.json()
        except Exception:
            body = {}
        purpose = body.get("purpose", "register")
        device_id = body.get("device_id", "")
        res = await asyncio.to_thread(service.create_challenge, purpose, device_id)
        return _json_resp(200, res, start)

    async def handle_agent_register(request: Request) -> Response:
        start = time.monotonic()
        try:
            body = await request.json()
        except Exception:
            body = {}
        token = _get_bearer(request)
        status, data = await asyncio.to_thread(service.register_device, body, token)
        return _json_resp(status, data, start)

    async def handle_pair(request: Request) -> Response:
        start = time.monotonic()
        try:
            body = await request.json()
        except Exception:
            body = {}
        pair_code = body.get("pair_code") or body.get("code")
        status, data = await asyncio.to_thread(service.claim_pair, pair_code, _get_bearer(request))
        return _json_resp(status, data, start)

    async def handle_pair_request(request: Request) -> Response:
        start = time.monotonic()
        try:
            body = await request.json()
        except Exception:
            body = {}
        device_id = body.get("device_id", "")
        token = _get_bearer(request)
        status, data = await asyncio.to_thread(service.create_pair_request, device_id, token)
        return _json_resp(status, data, start)

    async def handle_revoke(request: Request) -> Response:
        start = time.monotonic()
        token = _get_bearer(request)
        status, data, device_id = await asyncio.to_thread(service.revoke_mobile_session, token)
        if status == 200 and token:
            await hub.disconnect_mobile_session(token)
        return _json_resp(status, data, start)

    async def handle_commands(request: Request) -> Response:
        start = time.monotonic()
        t_http_recv = time.time()
        try:
            body = await request.json()
        except Exception:
            body = {}

        device_id = request.path_params.get("device_id") or body.get("device_id", "")
        action = body.get("action", "")
        request_id = body.get("request_id")
        token = _get_bearer(request)
        client_timings = body.get("timings", {})

        status, data = await asyncio.to_thread(
            service.enqueue_command, device_id, action, request_id, token, body
        )
        t_enqueue_commit = time.time()
        if status == 200 and data.get("command_id") and data.get("is_new", False) and data.get("status") in ("queued", "pending"):
            cmd_id = data["command_id"]
            claim_owner = f"ws:{cmd_id}"

            # Controlled dispatch gate hook for test deterministic race simulation
            if getattr(service, "dispatch_gate_hook", None) is not None:
                hook = service.dispatch_gate_hook
                if asyncio.iscoroutinefunction(hook):
                    await hook(cmd_id)
                elif callable(hook):
                    await asyncio.to_thread(hook, cmd_id)

            # Atomic DB claim BEFORE pushing frame!
            claimed = await asyncio.to_thread(service.claim_command_for_ws, device_id, cmd_id, claim_owner)
            t_claim_commit = time.time()
            if claimed:
                created_at = time.time()
                corr_timings = {
                    **client_timings,
                    "t_server_recv": t_http_recv,
                    "t_enqueue_commit": t_enqueue_commit,
                    "t_claim_commit": t_claim_commit,
                    "t_dispatch_sent": created_at
                } if client_timings else None
                delivered = await dispatch_claimed(device_id, cmd_id, action, created_at, timings=corr_timings)
                if delivered:
                    await asyncio.to_thread(service.mark_command_delivered, cmd_id, claim_owner)
                else:
                    await asyncio.to_thread(service.release_command_claim, cmd_id, claim_owner)

        return _json_resp(status, data, start)

    async def handle_agent_poll(request: Request) -> Response:
        hub.http_poll_count += 1
        start = time.monotonic()
        try:
            body = await request.json()
        except Exception:
            body = {}
        device_id = body.get("device_id", "")
        locked = body.get("locked", False)
        pin_ready = body.get("pin_ready", False)
        token = _get_bearer(request)
        status, data = await asyncio.to_thread(service.poll_agent, device_id, locked, pin_ready, token)
        return _json_resp(status, data, start)

    async def handle_agent_result(request: Request) -> Response:
        start = time.monotonic()
        try:
            body = await request.json()
        except Exception:
            body = {}
        cmd_id = body.get("command_id", "")
        device_id = body.get("device_id", "")
        success = body.get("success", False)
        status_str = body.get("status", "")
        token = _get_bearer(request)
        status, data = await asyncio.to_thread(
            service.submit_agent_result, cmd_id, device_id, success, status_str, token
        )
        if status == 200:
            if data.get('already_terminal'):
                success = data.get('status') == 'completed'
                status_str = data.get('result') or data.get('status')
            await hub.push_command_result(device_id, cmd_id, success, status_str, time.time())
        return _json_resp(status, data, start)

    async def handle_agent_telemetry(request: Request) -> Response:
        start = time.monotonic()
        try:
            body = await request.json()
        except Exception:
            body = {}
        device_id = body.get("device_id")
        token = _get_bearer(request)
        def _check_auth():
            with service.db.get_conn() as conn:
                return service.authenticate_agent(conn, device_id, token)

        is_auth = await asyncio.to_thread(_check_auth)
        if not is_auth:
            return _json_resp(401, {"error": "E_UNAUTHORIZED_AGENT"}, start)

        event_id = body.get("event_id") or secrets.token_hex(12)
        def _insert():
            with service.db.get_conn() as conn:
                conn.execute(
                    "INSERT INTO telemetry_events (event_id, install_run_id, device_id, component, version, stage, event_type, severity, error_code, duration_ms, local_time, received_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (event_id, body.get("install_run_id"), device_id,
                     str(body.get("component", "agent"))[:32], str(body.get("version", "0.1.0"))[:32],
                     str(body.get("stage", "UNKNOWN"))[:32], str(body.get("event_type", "heartbeat"))[:32],
                     str(body.get("severity", "INFO"))[:16], str(body.get("error_code") or "")[:64],
                     body.get("duration_ms"), body.get("local_time"), time.time())
                )
                conn.commit()

        await asyncio.to_thread(_insert)
        return _json_resp(200, {"success": True, "event_id": event_id}, start)

    async def handle_mobile_telemetry(request: Request) -> Response:
        start = time.monotonic()
        token = _get_bearer(request)
        try:
            body = await request.json()
        except Exception:
            body = {}

        req_device_id = body.get("device_id")
        events = body.get("events")
        if not isinstance(events, list) or not 1 <= len(events) <= 200:
            return _json_resp(400, {"error": "E_INVALID_MOBILE_EVENTS"}, start)

        def _process():
            with service.db.get_conn() as conn:
                sess = service.authenticate_mobile_session(conn, token)
                if not sess or (req_device_id and sess["device_id"] != req_device_id):
                    return 401, {"error": "E_INVALID_SESSION"}

                device_id = sess["device_id"]
                accepted = []
                for ev in events:
                    if not isinstance(ev, dict):
                        continue
                    event_id = ev.get("id") or ev.get("event_id", "")
                    code = ev.get("code") or ev.get("error_code", "")
                    stage = ev.get("stage", "request")
                    duration = ev.get("duration_ms")
                    correlation = ev.get("request_id") or ev.get("install_run_id", "")
                    if not isinstance(event_id, str) or len(event_id) != 32 or any(c not in '0123456789abcdef' for c in event_id):
                        continue
                    if stage not in ('tap', 'request', 'server', 'total', 'display', 'runtime', 'telemetry'):
                        continue
                    if not isinstance(code, str) or not 1 <= len(code) <= 80 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in code):
                        continue
                    if duration is not None and (type(duration) not in (int, float) or not 0 <= duration <= 600000):
                        continue
                    if not isinstance(correlation, str) or (correlation and (len(correlation) != 32 or any(c not in '0123456789abcdef' for c in correlation))):
                        continue
                    local_time = ev.get('local_time')
                    if type(local_time) not in (int, float) or not 0 <= local_time <= 4102444800:
                        continue
                    action = ev.get('action') if ev.get('action') in ('lock', 'unlock') else 'phone'
                    severity = 'ERROR' if ev.get('error') is True or ev.get('severity') == 'ERROR' else 'INFO'
                    conn.execute(
                        "INSERT INTO telemetry_events (event_id, install_run_id, device_id, component, version, stage, event_type, severity, error_code, duration_ms, local_time, received_at) "
                        "VALUES (?, ?, ?, 'mobile', 'web-1', ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (event_id) DO NOTHING",
                        ('mob_' + event_id, correlation or None, device_id, stage, action, severity, code, int(duration) if duration is not None else None, local_time, time.time())
                    )
                    accepted.append(event_id)
                conn.commit()
                return 200, {"accepted": accepted}

        status, data = await asyncio.to_thread(_process)
        return _json_resp(status, data, start)

    async def handle_admin_status_change(request: Request) -> Response:
        start = time.monotonic()
        try:
            body = await request.json()
        except Exception:
            body = {}
        device_id = body.get("device_id", "")
        admin_sec = request.headers.get("x-owner-admin-secret")
        path = request.url.path
        target_status = 'ACTIVE' if path.endswith('/activate') else 'REVOKED'
        status, data = await asyncio.to_thread(
            service.admin_set_device_status, device_id, target_status, admin_sec
        )
        if status == 200 and target_status == 'REVOKED':
            await hub.disconnect_device(device_id)
        return _json_resp(status, data, start)


    async def handle_admin_delete(request: Request) -> Response:
        start = time.monotonic()
        try:
            body = await request.json()
        except Exception:
            body = {}
        device_id = body.get("device_id", "")
        admin_sec = request.headers.get("x-owner-admin-secret")
        status, data = await asyncio.to_thread(service.admin_delete_device, device_id, admin_sec)
        if status == 200:
            await hub.disconnect_device(device_id)
        return _json_resp(status, data, start)

    async def handle_device_unregister(request: Request) -> Response:
        start = time.monotonic()
        try:
            body = await request.json()
        except Exception:
            body = {}
        device_id = request.path_params.get("device_id") or body.get("device_id", "")
        status, data = await asyncio.to_thread(service.unregister_device, device_id)
        if status == 200:
            await hub.disconnect_device(device_id)
        return _json_resp(status, data, start)

    # --- WEBSOCKET HANDLER ---

    async def ws_endpoint(ws: WebSocket):
        # 1. ORIGIN POLICY ENFORCEMENT (R2-04)
        origin = ws.headers.get("origin")
        if origin:
            from urllib.parse import urlparse
            parsed_origin = urlparse(origin.strip().lower())
            orig_host = (parsed_origin.hostname or "").lower()
            # Same-origin works for any public IP/domain without deployment-specific code.
            # Additional trusted frontends must be explicit scheme/host/port origins.
            def origin_key(value):
                try:
                    p = urlparse(value)
                    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ("", "/"):
                        return None
                    return (p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == "https" else 80))
                except ValueError:
                    return None
            configured = os.environ.get("WINKEY_ALLOWED_ORIGINS", "http://158.101.172.228:8080")
            trusted = {origin_key(v.strip()) for v in configured.split(",") if v.strip()}
            scheme = "https" if ws.url.scheme == "wss" else "http"
            trusted.add(origin_key(f"{scheme}://{ws.headers.get('host', '')}"))
            requested = origin_key(origin)
            # Loopback development UI is on a separate port.
            trusted.update(origin_key(v) for v in ("http://localhost:3000", "http://127.0.0.1:3000"))
            allowed_origin = requested is not None and requested in trusted
            if not allowed_origin:
                await ws.accept()
                await ws.close(code=4003, reason="ORIGIN_NOT_ALLOWED")
                return

        # 2. ZERO-TOKEN URL QUERY ENFORCEMENT
        query_str = ws.scope.get("query_string", b"").decode("utf-8", errors="ignore").lower()
        if any(b in query_str for b in ["token=", "secret=", "auth=", "key=", "session="]):
            await ws.accept()
            await ws.close(code=4003, reason="QUERY_TOKEN_FORBIDDEN")
            return

        await ws.accept()
        client_conn: Optional[ClientConnection] = None
        try:
            # 1. Auth frame gözlənilir (deadline 5 saniyə)
            try:
                raw_frame = await asyncio.wait_for(ws.receive_text(), timeout=AUTH_DEADLINE_SECONDS)
            except asyncio.TimeoutError:
                await ws.close(code=4001, reason="AUTH_TIMEOUT")
                return

            if len(raw_frame.encode("utf-8")) > MAX_FRAME_BYTES:
                await ws.close(code=4009, reason="MESSAGE_TOO_LARGE")
                return

            try:
                auth_data = json.loads(raw_frame)
            except Exception:
                await ws.close(code=4000, reason="INVALID_JSON")
                return

            if auth_data.get("type") != "auth":
                await ws.close(code=4401, reason="AUTH_FRAME_REQUIRED")
                return

            role = str(auth_data.get("role", "")).lower()

            # --- AGENT ROLE AUTH ---
            if role == "agent":
                device_id = str(auth_data.get("device_id", "")).strip()
                token = str(auth_data.get("token", "")).strip()

                def _verify_agent():
                    with service.db.get_conn() as conn:
                        return service.authenticate_agent(conn, device_id, token)

                is_ok = await asyncio.to_thread(_verify_agent)
                if not is_ok:
                    await ws.close(code=4401, reason="UNAUTHORIZED_AGENT")
                    return

                agent_ver = str(auth_data.get("version", "")).strip() or None
                client_conn = ClientConnection(ws, "agent", device_id, {"device_id": device_id, "device_secret": token, "version": agent_ver})
                await hub.register_agent(client_conn)

                # Auth uğurlu oldu cavabı
                await ws.send_text(json.dumps({
                    "type": "auth_ok",
                    "role": "agent",
                    "device_id": device_id,
                    "server_time": time.time()
                }))
                release = await asyncio.to_thread(repository.current)
                if release:
                    should_send = True
                    if agent_ver:
                        should_send = is_newer_semver(release['version'], agent_ver)
                    if should_send:
                        client_conn.enqueue({'type':'update_available','version':release['version'],'release_id':release['release_id']})

                # Mövcud gözləyən əmr varsa, atomik DB claim ilə agentə çatdırılır (R2-01)
                claim_owner = f"ws:{device_id}:{secrets.token_hex(4)}"
                def _claim_pending():
                    now = time.time()
                    with service.db.get_conn() as conn:
                        cmd = conn.execute(
                            """SELECT command_id, action, created_at FROM commands
                               WHERE device_id = ? AND status = 'pending'
                               ORDER BY created_at ASC LIMIT 1""",
                            (device_id,)
                        ).fetchone()
                        if cmd:
                            cid = cmd["command_id"]
                            res = conn.execute(
                                """UPDATE commands
                                   SET status = 'claimed', claim_owner = ?, claim_expires_at = ?
                                   WHERE command_id = ? AND status = 'pending'""",
                                (claim_owner, now + 60.0, cid)
                            )
                            conn.commit()
                            if res.rowcount == 1:
                                return dict(cmd)
                        conn.commit()
                        return None

                for _ in range(32):
                    claimed_pending = await asyncio.to_thread(_claim_pending)
                    if not claimed_pending:
                        break
                    if claimed_pending:
                        cmd_id = claimed_pending["command_id"]
                        act = claimed_pending["action"]
                        c_at = claimed_pending["created_at"]
                        delivered = await dispatch_claimed(device_id, cmd_id, act, c_at)
                        if delivered:
                            await asyncio.to_thread(service.mark_command_delivered, cmd_id, claim_owner)
                        else:
                            await asyncio.to_thread(service.release_command_claim, cmd_id, claim_owner)

            # --- MOBILE ROLE AUTH ---
            elif role == "mobile":
                session_token = str(auth_data.get("session_token", "")).strip()

                def _verify_sess():
                    with service.db.get_conn() as conn:
                        return service.authenticate_mobile_session(conn, session_token)

                sess = await asyncio.to_thread(_verify_sess)
                if not sess:
                    await ws.close(code=4401, reason="INVALID_SESSION")
                    return

                device_id = sess["device_id"]
                client_conn = ClientConnection(ws, "mobile", device_id, {"session_token": session_token, "device_id": device_id})
                await hub.register_mobile(client_conn)

                await ws.send_text(json.dumps({
                    "type": "auth_ok",
                    "role": "mobile",
                    "device_id": device_id,
                    "server_time": time.time()
                }))

                # Cari cihaz statusunu dərhal mobilə göndəririk
                def _dev_info():
                    with service.db.get_conn() as conn:
                        from deploy.account_service import device_presence
                        d = conn.execute("SELECT device_id,computer_name,status,locked,pin_ready,last_seen_at FROM devices WHERE device_id = ?", (device_id,)).fetchone()
                        return device_presence(conn,d) if d else None

                dev_row = await asyncio.to_thread(_dev_info)
                if dev_row:
                    await ws.send_text(json.dumps({
                        "type": "device_state",
                        "device_id": device_id,
                        "computer_name": dev_row.get("computer_name"),
                        "locked": bool(dev_row.get("locked")),
                        "pin_ready": bool(dev_row.get("pin_ready")),
                        "online": dev_row['online']
                    }))

            # --- ADMIN ROLE AUTH ---
            elif role == "admin":
                admin_sec = str(auth_data.get("admin_secret", "")).strip()
                if not admin_sec or admin_sec != service.get_admin_secret():
                    await ws.close(code=4403, reason="FORBIDDEN_ADMIN")
                    return

                client_conn = ClientConnection(ws, "admin", "admin", {})
                await hub.register_admin(client_conn)
                await ws.send_text(json.dumps({
                    "type": "auth_ok",
                    "role": "admin",
                    "server_time": time.time(),
                    "metrics": hub.get_metrics()
                }))

            else:
                await ws.close(code=4003, reason="UNKNOWN_ROLE")
                return

            # 2. Main WebSocket Message Handling Loop
            rate_window_start = time.monotonic()
            rate_msg_count = 0
            MAX_MSGS_PER_SEC = 50

            while client_conn.is_active:
                text = await ws.receive_text()
                # Rate limit check (R2-04)
                rate_msg_count += 1
                now_mono = time.monotonic()
                if now_mono - rate_window_start < 1.0:
                    if rate_msg_count > MAX_MSGS_PER_SEC:
                        await ws.close(code=4029, reason="RATE_LIMIT_EXCEEDED")
                        break
                else:
                    rate_window_start = now_mono
                    rate_msg_count = 1
                if len(text.encode("utf-8")) > MAX_FRAME_BYTES:
                    await ws.close(code=4009, reason="MESSAGE_TOO_LARGE")
                    break

                try:
                    msg = json.loads(text)
                except Exception:
                    continue

                m_type = msg.get("type")

                # --- AGENT FRAMES ---
                if client_conn.role == "agent":
                    did = client_conn.identifier
                    if m_type == "state" or m_type == "heartbeat":
                        locked = bool(msg.get("locked", False))
                        pin_ready = bool(msg.get("pin_ready", False))
                        import re
                        worker_version = msg.get('worker_version')
                        if not isinstance(worker_version,str) or not re.fullmatch(r'\d+\.\d+\.\d+',worker_version):
                            worker_version = None
                        else:
                            client_conn.metadata['version'] = worker_version

                        def _update_state():
                            with service.db.get_conn() as conn:
                                conn.execute(
                                    "UPDATE devices SET last_seen_at = ?, locked = ?, pin_ready = ? WHERE device_id = ?",
                                    (time.time(), 1 if locked else 0, 1 if pin_ready else 0, did)
                                )
                                if worker_version:
                                    conn.execute("INSERT INTO device_versions (device_id,worker_version,reported_at) VALUES (?,?,?) ON CONFLICT(device_id) DO UPDATE SET worker_version=excluded.worker_version,reported_at=excluded.reported_at",
                                        (did,worker_version,time.time()))
                                conn.commit()

                        await asyncio.to_thread(_update_state)
                        snapshot = await asyncio.to_thread(service.device_snapshot,did)
                        await hub.push_device_state(did, locked, pin_ready, online=bool(snapshot and snapshot['online']))

                    elif m_type == "result":
                        t_result_recv = time.time()
                        cmd_id = msg.get("command_id", "")
                        success = bool(msg.get("success", False))
                        status_str = str(msg.get("status", ""))
                        device_secret = client_conn.metadata.get("device_secret")
                        incoming_timings = msg.get("timings", {})

                        # Server commit via service layer (handles terminal idempotency & device ownership)
                        status, data = await asyncio.to_thread(
                            service.submit_agent_result, cmd_id, did, success, status_str, device_secret
                        )
                        t_result_commit = time.time()
                        if status == 200:
                            if data.get('already_terminal'):
                                success = data.get('status') == 'completed'
                                status_str = data.get('result') or data.get('status')
                            res_timings = {
                                **incoming_timings,
                                "t_result_recv": t_result_recv,
                                "t_result_commit": t_result_commit
                            } if incoming_timings else None
                            # Push result to mobile and send result_ack to source agent ONLY (WS-03)
                            await hub.push_command_result(did, cmd_id, success, status_str, time.time(), source_agent=client_conn, timings=res_timings)

                # --- MOBILE FRAMES ---
                elif client_conn.role == "mobile":
                    did = client_conn.identifier
                    session_token = client_conn.metadata.get("session_token", "")

                    if m_type == "command":
                        t_server_recv = time.time()
                        action = msg.get("action", "")
                        request_id = msg.get("request_id")
                        client_timings = msg.get("timings", {})

                        # Enqueue via shared service
                        status, data = await asyncio.to_thread(
                            service.enqueue_command, did, action, request_id, session_token, msg
                        )
                        t_enqueue_commit = time.time()
                        delivered = False
                        if status == 200 and data.get("command_id"):
                            cmd_id = data["command_id"]
                            is_new = data.get("is_new", False)
                            cmd_status = data.get("status", "pending")
                            if is_new and cmd_status in ("queued", "pending"):
                                claim_owner = f"ws:{cmd_id}"
                                if getattr(service, "dispatch_gate_hook", None) is not None:
                                    hook = service.dispatch_gate_hook
                                    if asyncio.iscoroutinefunction(hook):
                                        await hook(cmd_id)
                                    elif callable(hook):
                                        await asyncio.to_thread(hook, cmd_id)

                                claimed = await asyncio.to_thread(service.claim_command_for_ws, did, cmd_id, claim_owner)
                                t_claim_commit = time.time()
                                if claimed:
                                    c_at = time.time()
                                    corr_timings = {
                                        **client_timings,
                                        "t_server_recv": t_server_recv,
                                        "t_enqueue_commit": t_enqueue_commit,
                                        "t_claim_commit": t_claim_commit,
                                        "t_dispatch_sent": c_at
                                    } if client_timings else None
                                    delivered = await dispatch_claimed(did, cmd_id, action, c_at, timings=corr_timings)
                                    if delivered:
                                        await asyncio.to_thread(service.mark_command_delivered, cmd_id, claim_owner)
                                    else:
                                        await asyncio.to_thread(service.release_command_claim, cmd_id, claim_owner)

                            await ws.send_text(json.dumps({
                                "type": "command_ack",
                                "command_id": cmd_id,
                                "request_id": request_id,
                                "action": action,
                                "status": "delivered" if delivered else cmd_status
                            }))
                        else:
                            await ws.send_text(json.dumps({
                                "type": "command_error",
                                "error": data.get("error", "E_COMMAND_REJECTED"),
                                "message": data.get("message", "")
                            }))

                    elif m_type == "ping":
                        await ws.send_text(json.dumps({"type": "pong", "ts": time.time()}))

                # --- ADMIN FRAMES ---
                elif client_conn.role == "admin":
                    if m_type == "ping":
                        await ws.send_text(json.dumps({"type": "pong", "metrics": hub.get_metrics()}))

        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            if client_conn:
                await hub.unregister(client_conn)
                if client_conn.role == 'agent' and not hub.has_active_agent(client_conn.identifier):
                    def disconnected():
                        with service.db.get_conn() as conn:
                            conn.execute('UPDATE devices SET last_seen_at=0 WHERE device_id=?',(client_conn.identifier,))
                            conn.commit()
                    await asyncio.to_thread(disconnected)
                    snapshot = await asyncio.to_thread(service.device_snapshot,client_conn.identifier)
                    if snapshot:
                        await hub.push_device_state(snapshot['device_id'],bool(snapshot['locked']),bool(snapshot['pin_ready']),online=False)

    # Routes list
    routes = [
        Route('/updates/latest',handle_update_latest,methods=['GET']),
        Route('/updates/download/{release}/{name:path}',handle_update_download,methods=['GET']),
        Route('/admin/updates/publish',handle_update_publish,methods=['POST']),
        # Health & Core Pages
        Route("/healthz", handle_healthz, methods=["GET"]),
        Route("/", handle_dashboard, methods=["GET"]),
        Route("/dashboard", handle_dashboard, methods=["GET"]),
        Route("/mobile", handle_mobile_page, methods=["GET"]),
        Route("/mobile-assets/{asset}", handle_mobile_asset, methods=["GET"]),
        Route("/accounts/{action}", handle_feature, methods=["POST"]),
        Route("/mobile/install", handle_feature, methods=["POST"]),
        Route("/mobile/restore", handle_feature, methods=["POST"]),
        Route("/mobile/pair", handle_feature, methods=["POST"]),
        Route("/mobile/devices", handle_feature, methods=["POST"]),
        Route("/remote", handle_mobile_page, methods=["GET"]),
        Route("/admin", handle_admin_page, methods=["GET"]),

        # Admin API
        Route("/admin/devices", handle_admin_devices, methods=["GET"]),
        Route("/admin/telemetry", handle_admin_telemetry, methods=["GET"]),
        Route("/admin/revoke", handle_admin_status_change, methods=["POST"]),
        Route("/admin/activate", handle_admin_status_change, methods=["POST"]),
        Route("/admin/delete", handle_admin_delete, methods=["POST"]),
        Route("/devices/unregister", handle_device_unregister, methods=["POST"]),

        # Device & Command Status
        Route("/devices/{device_id}/status", handle_device_status, methods=["GET"]),
        Route("/commands/{command_id}", handle_command_status, methods=["GET"]),

        # Agent Registration & Pairing
        Route("/agent/challenge", handle_agent_challenge, methods=["POST"]),
        Route("/agent/register", handle_agent_register, methods=["POST"]),
        Route("/pair", handle_pair, methods=["POST"]),
        Route("/devices/pair-request", handle_pair_request, methods=["POST"]),

        # Revocation
        Route("/mobile/revoke", handle_revoke, methods=["POST"]),
        Route("/devices/revoke", handle_revoke, methods=["POST"]),

        # Commands (both /commands and /devices/{device_id}/command)
        Route("/commands", handle_commands, methods=["POST"]),
        Route("/devices/{device_id}/command", handle_commands, methods=["POST"]),

        # Agent HTTP Polling & Result (Legacy Compatibility)
        Route("/agent/poll", handle_agent_poll, methods=["POST"]),
        Route("/agent/result", handle_agent_result, methods=["POST"]),
        Route("/agent/telemetry", handle_agent_telemetry, methods=["POST"]),

        # Mobile Telemetry
        Route("/mobile/telemetry", handle_mobile_telemetry, methods=["POST"]),

        # WebSocket Routes (both /ws and /api/ws)
        WebSocketRoute("/ws", ws_endpoint),
        WebSocketRoute("/api/ws", ws_endpoint),
    ]

    from contextlib import asynccontextmanager, suppress

    @asynccontextmanager
    async def lifespan(app):
        # The Git commit carries its Windows release. On VM auto-deploy the
        # verified archive becomes current; no second upload or admin login is needed.
        from pathlib import Path
        bundled = Path(os.environ.get('WINKEY_BUNDLED_UPDATE','/app/windows_update.zip'))
        if bundled.is_file():
            try:
                async with publication_lock:
                    release = await asyncio.to_thread(repository.publish,bundled.read_bytes())
                print('[BUNDLED_UPDATE_READY] version='+release['version'],flush=True)
            except ValueError as error:
                if str(error)=='E_RELEASE_NOT_NEWER':
                    print('[BUNDLED_UPDATE_SKIP] Serverdə daha yeni buraxılış qorundu',flush=True)
                else:
                    print('[BUNDLED_UPDATE_REJECTED] E_INVALID_PACKAGE',flush=True)
            except Exception:
                print('[BUNDLED_UPDATE_REJECTED] E_IMPORT_FAILED',flush=True)
        async def sweep():
            last_release = None
            while True:
                try:
                    release = await asyncio.to_thread(repository.current)
                    if release and release['release_id'] != last_release:
                        last_release = release['release_id']
                        await broadcast_release(release)
                    for row in await asyncio.to_thread(service.expire_uncertain_commands):
                        await hub.push_command_result(row['device_id'], row['command_id'], False,
                            'INDETERMINATE_DELIVERY_TIMEOUT', time.time())
                except Exception:
                    print('[COMMAND_RECOVERY] E_SWEEP_FAILED', flush=True)
                await asyncio.sleep(2)
        async def monitor_lag():
            while True:
                start = time.monotonic()
                await asyncio.sleep(.1)
                hub.loop_lag_ms = round(max(0, time.monotonic() - start - .1) * 1000, 2)
        task = asyncio.create_task(sweep())
        lag_task = asyncio.create_task(monitor_lag())
        try:
            yield
        finally:
            task.cancel()
            lag_task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            with suppress(asyncio.CancelledError):
                await lag_task

    return Starlette(routes=routes, lifespan=lifespan)
