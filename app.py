import os
import time
import hmac
import secrets
import logging
import functools
import threading
from collections import defaultdict, deque
from flask import Flask, request, session, abort, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging: DEBUG only in development, INFO in production
_DEBUG = bool(os.environ.get("FLASK_DEBUG"))
_log_level = logging.DEBUG if _DEBUG else logging.INFO
logging.basicConfig(level=_log_level)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)

# Secret key — never fall back to a known value in production.
_secret = os.environ.get("SESSION_SECRET")
if not _secret:
    if _DEBUG:
        _secret = "dev-secret-key-change-in-production"
    else:
        raise RuntimeError("SESSION_SECRET environment variable must be set in production")
app.secret_key = _secret

# Harden session cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=not _DEBUG,
)

# Trust one proxy hop (Vercel's edge) for scheme, host AND client IP, so
# request.remote_addr reflects the real visitor rather than the proxy.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Configure the database - Vercel compatible
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

if database_url:
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    # Serverless (Vercel) note: each concurrent request may run in its own
    # ephemeral Lambda. A per-instance QueuePool (pool_size/max_overflow) would
    # multiply open Postgres connections across instances and exhaust the
    # server's connection limit ("FATAL: too many connections") — made worse by
    # the micro-scan architecture firing several parallel workers per scan.
    # NullPool opens one connection per checkout and closes it on release
    # (Flask-SQLAlchemy tears the session down after every request), so no
    # idle/zombie connections linger between invocations. Front the database
    # with an external pooler (PgBouncer / Supabase transaction pooler / Neon
    # pooled endpoint) in the DATABASE_URL for best results.
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "poolclass": NullPool,
        "pool_pre_ping": True,
    }
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///security_buddy.db"
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "poolclass": NullPool,
        "pool_pre_ping": True,
    }

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the app with the extension
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to continue.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    init_db_once()
    from models import User
    return User.query.get(int(user_id))


# ─────────────────────────────────────────────────────────────────────────
# CSRF protection (self-contained, session-token based)
# ─────────────────────────────────────────────────────────────────────────
_CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def generate_csrf_token():
    """Return the per-session CSRF token, creating one if needed."""
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def _inject_csrf_token():
    return {"csrf_token": generate_csrf_token}


@app.context_processor
def _inject_feature_flags():
    """Expose feature flags to templates. The Gmail Newsletter Manager stays
    dormant (hidden + routes return 404) until Google OAuth is configured."""
    import gmail_manager
    return {"gmail_enabled": gmail_manager.gmail_oauth_configured()}


@app.before_request
def _csrf_protect():
    if request.method in _CSRF_SAFE_METHODS:
        return
    # REST API authenticates via X-API-Key — not cookie-based, no CSRF risk.
    if request.path.startswith("/api/"):
        return
    # Cron endpoint is authenticated by Authorization: Bearer header, not a
    # browser session, so it is not susceptible to CSRF.
    if request.path.startswith("/cron/"):
        return
    sent = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRF-Token")
        or request.headers.get("X-CSRFToken")
    )
    expected = session.get("_csrf_token")
    if not expected or not sent or not hmac.compare_digest(str(sent), str(expected)):
        abort(400, description="CSRF token missing or invalid")


# ─────────────────────────────────────────────────────────────────────────
# Lightweight in-memory IP rate limiting (per-process sliding window).
# Effective for single/multi-worker deployments; on serverless it degrades
# to per-instance limiting, which is still better than none.
# ─────────────────────────────────────────────────────────────────────────
_rate_buckets: dict = defaultdict(deque)
_rate_lock = threading.Lock()
_last_bucket_sweep = [0.0]
_BUCKET_MAX_WINDOW = 3600  # entries older than this are dead regardless of route window


def _client_ip():
    """Best-effort real client IP behind Vercel's edge proxy.

    Prefer X-Real-IP (set by the edge, not client-appendable the way
    X-Forwarded-For is), then the left-most X-Forwarded-For hop, then the
    ProxyFix-corrected remote_addr.
    """
    real = request.headers.get("X-Real-IP")
    if real:
        return real.strip()
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _maybe_sweep_buckets(now):
    """Drop rate-limit buckets that have gone fully stale, bounding memory.

    Without this, every unique (IP, route) pair leaves a permanent dict entry
    even after its requests age out — an unbounded leak on a long-lived worker.
    """
    if now - _last_bucket_sweep[0] < 300:
        return
    with _rate_lock:
        if now - _last_bucket_sweep[0] < 300:
            return
        _last_bucket_sweep[0] = now
        dead = [k for k, b in _rate_buckets.items()
                if not b or b[-1] < now - _BUCKET_MAX_WINDOW]
        for k in dead:
            _rate_buckets.pop(k, None)


def rate_limit(max_calls: int, window_seconds: int = 60):
    """Decorator: allow at most `max_calls` per `window_seconds` per client IP.

    Safe methods (GET/HEAD/OPTIONS) are never throttled, so read-only polling
    endpoints such as GET /api/scan/status are effectively exempt.
    """
    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            # Only throttle state-changing / action requests, not page loads or polling.
            if request.method in _CSRF_SAFE_METHODS:
                return view(*args, **kwargs)
            now = time.time()
            _maybe_sweep_buckets(now)
            key = f"{_client_ip()}:{view.__name__}"
            cutoff = now - window_seconds
            # Guard the read-modify-write on this bucket so concurrent workers
            # (many parallel micro-scan requests) can't corrupt the deque.
            with _rate_lock:
                bucket = _rate_buckets[key]
                while bucket and bucket[0] < cutoff:
                    bucket.popleft()
                allowed = len(bucket) < max_calls
                if allowed:
                    bucket.append(now)
                    retry = 0
                else:
                    retry = int(bucket[0] + window_seconds - now) + 1
            if allowed:
                return view(*args, **kwargs)
            if request.path.startswith("/api/"):
                resp = jsonify({
                    "error": "Rate limit exceeded",
                    "message": f"Too many requests. Retry in {retry}s.",
                })
                resp.status_code = 429
                resp.headers["Retry-After"] = str(retry)
                return resp
            abort(429, description=f"Rate limit exceeded. Retry in {retry}s.")
        return wrapper
    return decorator


# Content-Security-Policy.
#
# Backbone follows the strict self-first policy requested in DEVELOPMENT.md, but
# a handful of directives are widened to exactly the hosts the site genuinely
# loads — otherwise the CSP would break the app itself:
#   * script-src needs https://unpkg.com — Lucide (every page's icons) is served
#     from there; 'unsafe-inline' is required for the inline UI scripts, inline
#     event handlers (e.g. the font <link onload>) and enhancements.js hooks.
#   * the Google Ad* hosts keep AdSense working on content pages (it is gated
#     behind cookie consent and g.show_ads). Drop them if AdSense is removed.
#   * style-src / font-src allow Fontshare (the web fonts).
#   * img-src allows data: (inline favicons, PageSpeed screenshots) and https:.
# object-src/base-uri/frame-ancestors are locked down for extra hardening
# (frame-ancestors 'none' reinforces the existing X-Frame-Options: DENY).
_CSP = "; ".join([
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "img-src 'self' data: https:",
    "font-src 'self' https://api.fontshare.com https://cdn.fontshare.com",
    "style-src 'self' 'unsafe-inline' https://api.fontshare.com https://cdn.fontshare.com",
    "script-src 'self' 'unsafe-inline' https://unpkg.com "
    "https://pagead2.googlesyndication.com https://*.googlesyndication.com "
    "https://adservice.google.com https://*.google.com",
    "connect-src 'self' https://*.googlesyndication.com https://*.google.com "
    "https://*.doubleclick.net",
    "frame-src https://googleads.g.doubleclick.net https://tpc.googlesyndication.com "
    "https://*.google.com",
])


@app.after_request
def _set_security_headers(response):
    response.headers.setdefault("Content-Security-Policy", _CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
    )
    return response

def _run_column_migrations():
    """Safely add new columns to existing tables (idempotent, no data loss)."""
    from sqlalchemy import text
    candidates = [
        'ALTER TABLE "user" ADD COLUMN tos_accepted_at DATETIME NULL',
        'ALTER TABLE "user" ADD COLUMN email_notifications BOOLEAN NOT NULL DEFAULT TRUE',
        # Async micro-scan columns on scan_result (idempotent — ignored if present).
        'ALTER TABLE scan_result ADD COLUMN public_id VARCHAR(32)',
        "ALTER TABLE scan_result ADD COLUMN status VARCHAR(20) DEFAULT 'PROCESSING'",
        'ALTER TABLE scan_result ADD COLUMN ssl_result TEXT',
        'ALTER TABLE scan_result ADD COLUMN headers_result TEXT',
        'ALTER TABLE scan_result ADD COLUMN ports_result TEXT',
        'ALTER TABLE scan_result ADD COLUMN seo_result TEXT',
        'ALTER TABLE scan_result ADD COLUMN threat_result TEXT',
    ]
    with db.engine.connect() as conn:
        for stmt in candidates:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                conn.rollback()  # column already exists — safe to ignore


# ─────────────────────────────────────────────────────────────────────────
# Lazy, once-per-process schema initialization.
#
# Running db.create_all() + migrations at IMPORT time made every serverless
# cold start pay several DB round-trips before serving the first byte — and
# with a serverless Postgres that may itself be cold, that can add seconds to
# the very first page load. Instead we initialize on demand the first time a
# request actually needs the database, so DB-free pages (the landing page in
# particular) stay fast on a cold lambda.
#
# Set DB_AUTO_INIT=0 when the schema is managed externally to skip entirely.
# ─────────────────────────────────────────────────────────────────────────
_db_init_lock = threading.Lock()
_db_initialized = False

# Endpoints that never touch the database — kept off the lazy-init path so the
# landing page (the first thing visitors hit) responds instantly on a cold
# lambda without waiting on a database connection.
_DB_FREE_ENDPOINTS = {"index", "static"}


def init_db_once():
    """Create tables + run column migrations exactly once per process."""
    global _db_initialized
    if _db_initialized or os.environ.get("DB_AUTO_INIT", "1") == "0":
        return
    with _db_init_lock:
        if _db_initialized:
            return
        try:
            with app.app_context():
                import models  # noqa: F401
                db.create_all()
                _run_column_migrations()
            _db_initialized = True
            logging.info("Database tables created successfully")
        except Exception as e:
            # Leave the flag unset so a transient cold-DB failure can retry.
            logging.warning(f"Database initialization error: {e}")


@app.before_request
def _lazy_db_init():
    if request.endpoint in _DB_FREE_ENDPOINTS:
        return
    init_db_once()
