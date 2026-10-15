"""FastAPI application for the Thanos panel.

HTML routes:
  GET  /                 → cycle list + upload form (RF-18, RF-19)
  POST /upload           → upload one or more bundles (RF-18)
  GET  /cycle/{id}       → cycle view with aggregated artifacts (RF-20)

JSON routes (API):
  GET  /api/cycles       → aggregated cycles
  GET  /api/cycle/{id}   → one aggregated cycle
  GET  /health           → healthcheck

Security controls (docs/03_security.md):
  - Listens only on 127.0.0.1 by default and only accepts local Host headers or the
    configured one (THANOS_PANEL_HOST).
  - POST /upload: optional token (THANOS_PANEL_TOKEN), rejection of requests with a
    foreign Origin (CSRF), limits on size and number of files, schema and type
    validation before saving.
  - CSP, X-Frame-Options, nosniff and Referrer-Policy headers; errors without tracebacks.

Run:  python -m thanos.panel.app   (or: thanos-panel)
"""

from __future__ import annotations

import hmac
import json
from contextlib import asynccontextmanager
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..config import env, load_env, resolve_path
from ..log import get_logger, setup_logging
from .render import render_cycle, render_error, render_home
from .store import InvalidBundle, PanelStore

log = get_logger("panel")

MAX_FILES = 20
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]", "testserver"}
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
}

# The store is created at startup (or on first use), not when the module is imported.
store: PanelStore | None = None


def get_store() -> PanelStore:
    global store
    if store is None:
        store = PanelStore()
    return store


def _max_upload_bytes() -> int:
    try:
        return int(float(env("THANOS_PANEL_MAX_UPLOAD_MB", "5")) * 1024 * 1024)
    except ValueError:
        return 5 * 1024 * 1024


def _allowed_hosts() -> set[str]:
    configured = env("THANOS_PANEL_HOST", "127.0.0.1")
    # Wildcard addresses are EXCLUDED: they are not valid host names in the Host header.
    return _LOCAL_HOSTS | ({configured} if configured not in ("", "0.0.0.0", "::") else set())  # nosec B104


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """At startup: create the store and, if it is empty, seed it with the real P1 bundles."""
    s = get_store()
    if env("THANOS_PANEL_SEED", "1") != "0" and s.is_empty():
        try:
            n = s.seed_from(resolve_path("fixtures/bundles"))
            log.info("panel_seeded", extra={"fields": {"bundles": n}})
        except (OSError, ValueError) as exc:
            log.warning("panel_seed_failed", extra={"fields": {"error": str(exc)[:200]}})
    yield


app = FastAPI(title="Thanos Panel", version="1.0.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


def _hostname(host_header: str) -> str:
    """Host name without the port ('127.0.0.1:8000' → '127.0.0.1', '[::1]:8000' → '[::1]')."""
    if host_header.startswith("["):
        return host_header.split("]")[0] + "]"
    return host_header.rsplit(":", 1)[0] if host_header.count(":") == 1 else host_header


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    host = _hostname(request.headers.get("host") or "")
    if host not in _allowed_hosts():
        log.warning("host_rejected", extra={"fields": {"host": host[:100]}})
        return _error_response(request, 400, "Request rejected", "Host header not allowed.")
    if request.method == "POST":
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > MAX_FILES * _max_upload_bytes():
            return _error_response(request, 413, "Upload too large",
                                   "The request exceeds the maximum allowed size.")
        origin = request.headers.get("origin") or request.headers.get("referer")
        if origin and urlsplit(origin).hostname not in _allowed_hosts():
            log.warning("origin_rejected", extra={"fields": {"origin": origin[:100]}})
            return _error_response(request, 403, "Origin not allowed", "Uploads must be made from the panel itself.")
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


def _wants_json(request: Request) -> bool:
    return request.url.path.startswith("/api/") or request.url.path == "/health"


def _error_response(request: Request, status: int, title: str, detail: str):
    if _wants_json(request):
        response = JSONResponse({"error": title, "detail": detail}, status_code=status)
    else:
        response = HTMLResponse(render_error(status, title, detail), status_code=status)
    for name, value in _SECURITY_HEADERS.items():
        response.headers[name] = value
    return response


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    titles = {404: "Page not found", 405: "Method not allowed"}
    return _error_response(request, exc.status_code, titles.get(exc.status_code, "Error"), str(exc.detail))


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    log.error("unhandled_error", exc_info=exc, extra={"fields": {"path": request.url.path}})
    return _error_response(request, 500, "Internal error",
                           "An unexpected error occurred. Check the panel log.")


def _token_ok(provided: str | None) -> bool:
    expected = env("THANOS_PANEL_TOKEN", "")
    if not expected:
        return True
    return bool(provided) and hmac.compare_digest(provided.encode(), expected.encode())


@app.get("/", response_class=HTMLResponse)
def home(message: str | None = None, error: int = 0) -> HTMLResponse:
    return HTMLResponse(render_home(
        get_store().cycles(), message,
        token_required=bool(env("THANOS_PANEL_TOKEN", "")), is_error=bool(error),
    ))


@app.post("/upload")
async def upload(
    request: Request,
    files: list[UploadFile] = File(...),  # noqa: B008
    token: str | None = Form(None),  # noqa: B008
):
    if not _token_ok(token or request.headers.get("x-thanos-token")):
        log.warning("upload_unauthorized")
        return _error_response(request, 401, "Unauthorized", "The upload token is missing or incorrect.")
    if len(files) > MAX_FILES:
        return _error_response(request, 413, "Too many files", f"At most {MAX_FILES} files per upload.")

    limit = _max_upload_bytes()
    added, replaced, skipped = 0, 0, []
    for f in files:
        name = (f.filename or "file")[:120]
        raw = await f.read(limit + 1)
        if len(raw) > limit:
            skipped.append(f"{name}: exceeds {limit // (1024 * 1024)} MB")
            continue
        try:
            bundle = json.loads(raw)
        except (ValueError, RecursionError):
            skipped.append(f"{name}: not valid UTF-8 JSON")
            continue
        try:
            _cid, was_replaced = get_store().add_bundle(bundle)
        except InvalidBundle as exc:
            skipped.append(f"{name}: {exc}")
            continue
        added += 1
        replaced += was_replaced
    log.info("upload", extra={"fields": {"added": added, "replaced": replaced, "skipped": len(skipped)}})

    msg = f"Uploaded {added} bundle(s)"
    msg += f", {replaced} replaced (.bak copy saved)." if replaced else "."
    if skipped:
        msg += " Skipped: " + "; ".join(skipped)
    error = 1 if skipped and not added else 0
    return RedirectResponse(url=f"/?error={error}&message={quote(msg[:1500])}", status_code=303)


@app.get("/cycle/{cid}", response_class=HTMLResponse)
def cycle_view(request: Request, cid: str, prio: str | None = None):
    c = get_store().get_cycle(cid)
    if not c:
        return _error_response(request, 404, "Cycle not found", f"Cycle '{cid[:80]}' does not exist.")
    return HTMLResponse(render_cycle(c, prio if prio in ("P1", "P2", "P3", "P4") else None))


@app.get("/api/cycles")
def api_cycles() -> JSONResponse:
    return JSONResponse(get_store().cycles())


@app.get("/api/cycle/{cid}")
def api_cycle(cid: str) -> JSONResponse:
    c = get_store().get_cycle(cid)
    if not c:
        return JSONResponse({"error": "not found", "id": cid[:80]}, status_code=404)
    return JSONResponse(c)


@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "cycles": len(get_store().cycles())})


def main() -> None:
    import uvicorn

    load_env()
    setup_logging("INFO")
    host = env("THANOS_PANEL_HOST", "127.0.0.1")
    port = int(env("THANOS_PANEL_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
