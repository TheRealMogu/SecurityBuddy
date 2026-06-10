"""
Gmail Newsletter Manager — OAuth flow and newsletter discovery via the Gmail API.

Privacy by design: only message *headers* are ever requested (From, Date,
List-Unsubscribe, List-Unsubscribe-Post) — never the body or content of any
email. Messages that advertise a List-Unsubscribe header are grouped by sender
so the user can unsubscribe from each newsletter, using the RFC 8058 one-click
POST where the sender supports it.

Uses the official google-api-python-client / google-auth libraries. The heavy
Google imports are done lazily inside functions so the app boots even if the
optional dependencies are not installed in a given environment.
"""
import os
import re
import socket
import logging
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.utils import parseaddr, parsedate_to_datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Minimal scope: read-only access is enough to list newsletters by header.
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Gmail search query: only messages that advertise an unsubscribe mechanism.
NEWSLETTER_QUERY = "has:list-unsubscribe"

# Caps to stay comfortably within the serverless request budget.
_MAX_MESSAGES = 150
_MAX_WORKERS = 10

_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
_TOKEN_URI = "https://oauth2.googleapis.com/token"
_REVOKE_URI = "https://oauth2.googleapis.com/revoke"

# In development the OAuth redirect is plain http://localhost — allow it.
if os.environ.get("FLASK_DEBUG"):
    os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")
# Google may grant extra scopes (e.g. openid); don't fail on scope mismatch.
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")


def gmail_oauth_configured():
    """True when the server has Google OAuth credentials configured."""
    return bool(os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"))


# ── Token encryption at rest (GDPR Art. 32) ─────────────────────────────────
# OAuth tokens grant ongoing read access to the user's mailbox, so they are
# encrypted before being written to the database. The key comes from
# TOKEN_ENCRYPTION_KEY if set (a urlsafe-base64 32-byte Fernet key); otherwise
# it is derived deterministically from SESSION_SECRET.
def _fernet():
    import base64
    import hashlib
    from cryptography.fernet import Fernet
    key = os.environ.get("TOKEN_ENCRYPTION_KEY")
    if key:
        fkey = key.encode()
    else:
        secret = os.environ.get("SESSION_SECRET") or "dev-secret-key-change-in-production"
        fkey = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(fkey)


def encrypt_token(plaintext):
    """Encrypt a token for storage. Returns None/empty unchanged."""
    if not plaintext:
        return plaintext
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_token(ciphertext):
    """Decrypt a stored token. Returns None if missing or undecryptable."""
    if not ciphertext:
        return None
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except Exception:
        # Key rotated or value tampered — treat as disconnected; user reconnects.
        return None


def _client_config(redirect_uri):
    return {
        "web": {
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "auth_uri": _AUTH_URI,
            "token_uri": _TOKEN_URI,
            "redirect_uris": [redirect_uri],
        }
    }


# ── OAuth flow ──────────────────────────────────────────────────────────────
def build_auth_url(redirect_uri):
    """Return (authorization_url, state) to start the OAuth consent flow."""
    from google_auth_oauthlib.flow import Flow
    flow = Flow.from_client_config(
        _client_config(redirect_uri), scopes=GMAIL_SCOPES, redirect_uri=redirect_uri
    )
    # offline + consent so Google returns a refresh token we can persist.
    return flow.authorization_url(
        access_type="offline", include_granted_scopes="true", prompt="consent"
    )


def exchange_code(redirect_uri, state, code):
    """Exchange the OAuth callback code for credentials. Returns google Credentials."""
    from google_auth_oauthlib.flow import Flow
    flow = Flow.from_client_config(
        _client_config(redirect_uri), scopes=GMAIL_SCOPES,
        state=state, redirect_uri=redirect_uri,
    )
    flow.fetch_token(code=code)
    return flow.credentials


def credentials_from_record(record):
    """Build a google Credentials object from a stored GmailCredential row.

    Tokens are decrypted on the way out (they are stored encrypted at rest).
    """
    from google.oauth2.credentials import Credentials
    return Credentials(
        token=decrypt_token(record.token),
        refresh_token=decrypt_token(record.refresh_token),
        token_uri=record.token_uri or _TOKEN_URI,
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        scopes=(record.scopes or "").split() or GMAIL_SCOPES,
    )


def revoke(token):
    """Best-effort revocation of an access/refresh token at Google."""
    import requests
    if not token:
        return
    requests.post(
        _REVOKE_URI,
        params={"token": token},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=8,
    )


# ── Gmail API ───────────────────────────────────────────────────────────────
def _build_service(creds):
    from googleapiclient.discovery import build
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def get_email_address(creds):
    """Return the connected account's email via the Gmail profile endpoint."""
    service = _build_service(creds)
    profile = service.users().getProfile(userId="me").execute()
    return profile.get("emailAddress", "")


def _header(headers, name):
    name = name.lower()
    for h in headers:
        if h.get("name", "").lower() == name:
            return h.get("value", "")
    return ""


def _parse_unsubscribe(value):
    """Parse a List-Unsubscribe header into (https_url, mailto)."""
    https_url = mailto = None
    for part in re.findall(r"<([^>]+)>", value or ""):
        part = part.strip()
        low = part.lower()
        if low.startswith("mailto:") and not mailto:
            mailto = part
        elif low.startswith("http") and not https_url:
            https_url = part
    return https_url, mailto


def _fetch_message_meta(creds, msg_id):
    """Fetch headers-only metadata for one message and parse the unsubscribe info."""
    service = _build_service(creds)
    msg = service.users().messages().get(
        userId="me", id=msg_id, format="metadata",
        metadataHeaders=["From", "Date", "List-Unsubscribe", "List-Unsubscribe-Post"],
    ).execute()
    headers = msg.get("payload", {}).get("headers", [])

    list_unsub = _header(headers, "List-Unsubscribe")
    if not list_unsub:
        return None
    https_url, mailto = _parse_unsubscribe(list_unsub)
    one_click = "one-click" in _header(headers, "List-Unsubscribe-Post").lower()

    name, email = parseaddr(_header(headers, "From"))
    try:
        dt = parsedate_to_datetime(_header(headers, "Date"))
        if dt is not None and dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)  # naive UTC-ish for sorting
    except Exception:
        dt = None

    return {
        "name": name or (email.split("@")[0] if email else "Unknown sender"),
        "email": (email or "").lower(),
        "date": dt,
        "url": https_url,
        "mailto": mailto,
        "one_click": bool(one_click and https_url),
    }


def list_newsletters(creds):
    """Return a de-duplicated list of newsletter senders (latest email per sender).

    Each item: {name, email, last_date (ISO or None), url, mailto, one_click}.
    """
    service = _build_service(creds)

    ids = []
    resp = service.users().messages().list(
        userId="me", q=NEWSLETTER_QUERY, maxResults=min(_MAX_MESSAGES, 100)
    ).execute()
    ids.extend(m["id"] for m in resp.get("messages", []))
    while resp.get("nextPageToken") and len(ids) < _MAX_MESSAGES:
        resp = service.users().messages().list(
            userId="me", q=NEWSLETTER_QUERY, maxResults=100,
            pageToken=resp["nextPageToken"],
        ).execute()
        ids.extend(m["id"] for m in resp.get("messages", []))
    ids = ids[:_MAX_MESSAGES]

    senders = {}
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        futures = [ex.submit(_fetch_message_meta, creds, mid) for mid in ids]
        for fut in as_completed(futures):
            try:
                item = fut.result()
            except Exception as e:
                logger.debug("Gmail metadata fetch failed: %s", e)
                continue
            if not item or not item["email"]:
                continue
            key = item["email"]
            existing = senders.get(key)
            if existing is None:
                senders[key] = item
                continue
            # Keep the most recent email for display…
            if item["date"] and (existing["date"] is None or item["date"] > existing["date"]):
                existing["date"] = item["date"]
                existing["name"] = item["name"] or existing["name"]
            # …but make sure we retain a usable unsubscribe target.
            if not existing["url"] and item["url"]:
                existing["url"] = item["url"]
                existing["one_click"] = item["one_click"]
            if not existing["mailto"] and item["mailto"]:
                existing["mailto"] = item["mailto"]

    result = [
        {
            "name": it["name"],
            "email": it["email"],
            "last_date": it["date"].isoformat() if it["date"] else None,
            "url": it["url"],
            "mailto": it["mailto"],
            "one_click": it["one_click"],
        }
        for it in senders.values()
    ]
    result.sort(key=lambda r: (r["last_date"] or ""), reverse=True)
    return result


# ── One-click unsubscribe (RFC 8058) ────────────────────────────────────────
def _addr_is_public(addr):
    return not (
        addr.is_private or addr.is_loopback or addr.is_reserved
        or addr.is_link_local or addr.is_multicast or addr.is_unspecified
    )


def _is_public_https(url):
    """SSRF guard: require https and a publicly-routable host for every resolved IP."""
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            return False
        host = parsed.hostname
        if host in ("localhost",):
            return False
        try:
            return _addr_is_public(ipaddress.ip_address(host))
        except ValueError:
            pass  # hostname, resolve below
        try:
            infos = socket.getaddrinfo(host, None)
        except Exception:
            return False
        if not infos:
            return False
        for info in infos:
            ip = info[4][0].split("%")[0]
            try:
                if not _addr_is_public(ipaddress.ip_address(ip)):
                    return False
            except ValueError:
                return False
        return True
    except Exception:
        return False


def one_click_unsubscribe(url):
    """Perform an RFC 8058 one-click unsubscribe POST. Returns (ok, message)."""
    import requests
    if not _is_public_https(url):
        return False, "Unsubscribe URL is not a valid public HTTPS endpoint."
    try:
        resp = requests.post(
            url,
            data="List-Unsubscribe=One-Click",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
            allow_redirects=False,  # don't follow redirects — avoids SSRF bypass
        )
        if 200 <= resp.status_code < 400:
            return True, "Unsubscribe request sent."
        return False, f"The sender's server returned HTTP {resp.status_code}."
    except requests.RequestException as e:
        return False, f"Could not reach the unsubscribe endpoint: {e}"
