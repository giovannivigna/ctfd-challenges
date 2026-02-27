import json
import os
from typing import Any

from flask import Flask, make_response, request

from vuln_app import AppConfig, Request as PortalRequest, build_app


def _lower_headers(h: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in h.items()}


cfg = AppConfig(
    db_path=os.environ.get("PORTAL_DB", "/tmp/portal.db"),
    password_pepper=os.environ.get("PORTAL_PEPPER", "demo-pepper"),
    session_signing_key=os.environ.get("SESSION_KEY", "dev-session-key"),
    session_ttl_seconds=int(os.environ.get("SESSION_TTL", str(7 * 24 * 60 * 60))),
    max_login_attempts_per_minute=int(os.environ.get("LOGIN_RPM", "10")),
    support_email=os.environ.get("SUPPORT_EMAIL", "support@example.invalid"),
    upload_root=os.environ.get("UPLOAD_ROOT", "/tmp/portal-uploads"),
)

router = build_app(cfg)

app = Flask(__name__)


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def passthrough(path: str):
    full_path = "/" + path

    body: dict[str, Any] | None = None
    if request.method in ("POST", "PUT", "PATCH"):
        if request.is_json:
            body = request.get_json(silent=True) or {}
            if not isinstance(body, dict):
                body = {"_": body}
        elif request.form:
            body = dict(request.form)
        else:
            raw = (request.data or b"").decode("utf-8", "ignore").strip()
            body = {"raw": raw} if raw else {}
    else:
        body = dict(request.args) if request.args else {}

    incoming_headers = {k: v for k, v in request.headers.items()}
    lh = _lower_headers(incoming_headers)
    if "x-session" not in lh:
        cookie_sess = request.cookies.get("session")
        if cookie_sess:
            incoming_headers["x-session"] = cookie_sess

    portal_req = PortalRequest(
        path=full_path,
        method=request.method,
        body=body or {},
        headers=incoming_headers,
    )
    portal_resp = router.dispatch(portal_req)

    resp = make_response(portal_resp.to_json(), portal_resp.status)
    resp.headers["Content-Type"] = "application/json"

    # If the portal returns a session token, mirror it into a cookie for convenience.
    out_headers = portal_resp.headers or {}
    x_session = out_headers.get("x-session")
    if isinstance(x_session, str) and x_session:
        resp.headers["x-session"] = x_session
        resp.set_cookie("session", x_session, httponly=True)

    # Forward any other portal-provided headers.
    for k, v in out_headers.items():
        if k.lower() in ("content-type", "x-session"):
            continue
        if isinstance(v, str):
            resp.headers[k] = v

    return resp


@app.get("/healthz")
def healthz():
    return make_response(json.dumps({"ok": True}), 200, {"Content-Type": "application/json"})

