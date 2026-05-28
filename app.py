import os
import time
import hmac
import secrets
import logging
import functools
from collections import defaultdict, deque
from flask import Flask, request, session, abort, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
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

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database - Vercel compatible
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

if database_url:
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
        "pool_timeout": 20,
        "pool_size": 10,
        "max_overflow": 20
    }
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///security_buddy.db"
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
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


def _client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limit(max_calls: int, window_seconds: int = 60):
    """Decorator: allow at most `max_calls` per `window_seconds` per client IP."""
    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            # Only throttle state-changing / action requests, not page loads.
            if request.method in _CSRF_SAFE_METHODS:
                return view(*args, **kwargs)
            now = time.time()
            key = f"{_client_ip()}:{view.__name__}"
            bucket = _rate_buckets[key]
            cutoff = now - window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= max_calls:
                retry = int(bucket[0] + window_seconds - now) + 1
                if request.path.startswith("/api/"):
                    resp = jsonify({
                        "error": "Rate limit exceeded",
                        "message": f"Too many requests. Retry in {retry}s.",
                    })
                    resp.status_code = 429
                    resp.headers["Retry-After"] = str(retry)
                    return resp
                abort(429, description=f"Rate limit exceeded. Retry in {retry}s.")
            bucket.append(now)
            return view(*args, **kwargs)
        return wrapper
    return decorator


@app.after_request
def _set_security_headers(response):
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
    ]
    with db.engine.connect() as conn:
        for stmt in candidates:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                conn.rollback()  # column already exists — safe to ignore


with app.app_context():
    try:
        import models  # noqa: F401
        db.create_all()
        _run_column_migrations()
        logging.info("Database tables created successfully")
    except Exception as e:
        logging.warning(f"Database initialization error: {e}")
