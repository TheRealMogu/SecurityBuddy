"""
SSRF-safe HTTP wrapper.

Every outgoing request made by the scanner, the SEO analyzer and the threat-intel
lookups goes through :func:`secure_request`. It closes two classes of SSRF that a
plain ``requests`` call is exposed to:

1. **Redirect SSRF** — ``requests`` follows redirects blindly. A public URL can
   answer ``302 Location: http://169.254.169.254/`` (cloud metadata) or
   ``http://127.0.0.1/`` (local services) and slip past a validation that only
   checked the *original* host. Here redirects are never auto-followed: we handle
   the chain manually and re-validate every hop.

2. **DNS rebinding (TOCTOU)** — even a validated hostname is resolved *again* by
   the socket layer at connect time, so an attacker controlling DNS can return a
   public IP during validation and a private IP milliseconds later. We defeat
   this by *pinning*: the host is resolved and validated once, and the socket is
   forced to connect to that exact IP. The URL is left untouched, so the TLS SNI,
   certificate hostname check and ``Host`` header all keep working normally.

The pin is applied by patching urllib3's ``create_connection`` and storing the
active pin in thread-local state, which keeps concurrent scans (the app uses
thread pools heavily) isolated from one another.
"""
import threading
from contextlib import contextmanager
from urllib.parse import urlparse, urljoin

import requests
import urllib3.util.connection as _urllib3_connection

from validators import resolve_and_validate_host


class SSRFSecurityError(requests.exceptions.RequestException):
    """Raised when a request (or one of its redirects) targets a blocked host.

    Subclasses ``requests.exceptions.RequestException`` so that existing call
    sites which already catch that type degrade gracefully (the individual
    check simply fails) instead of aborting the whole scan.
    """


# HTTP status codes that carry a Location header we may follow.
_REDIRECT_CODES = {301, 302, 303, 307, 308}

# ---------------------------------------------------------------------------
# IP pinning: force the socket to the validated IP without a second DNS lookup.
# ---------------------------------------------------------------------------
_pin_ctx = threading.local()
_orig_create_connection = _urllib3_connection.create_connection


def _pinning_create_connection(address, *args, **kwargs):
    """Drop-in for urllib3's create_connection that honours the active pin.

    When a pin for the address' host is set on the current thread, the socket
    connects straight to the pinned IP; otherwise resolution is unchanged.
    """
    host = address[0]
    pins = getattr(_pin_ctx, "pins", None)
    if pins:
        pinned_ip = pins.get(host)
        if pinned_ip:
            address = (pinned_ip,) + tuple(address[1:])
    return _orig_create_connection(address, *args, **kwargs)


# Install the patch exactly once, even if this module is imported repeatedly.
if not getattr(_urllib3_connection.create_connection, "_ssrf_pinned", False):
    _pinning_create_connection._ssrf_pinned = True
    _urllib3_connection.create_connection = _pinning_create_connection


@contextmanager
def _pinned(host, ip):
    """Pin ``host`` to ``ip`` for the duration of the block (thread-local)."""
    previous = getattr(_pin_ctx, "pins", None)
    merged = dict(previous) if previous else {}
    merged[host] = ip
    _pin_ctx.pins = merged
    try:
        yield
    finally:
        _pin_ctx.pins = previous


# A shared session for callers that don't pass one of their own.
_default_session = None
_default_session_lock = threading.Lock()


def _get_default_session():
    global _default_session
    if _default_session is None:
        with _default_session_lock:
            if _default_session is None:
                s = requests.Session()
                s.headers.setdefault("User-Agent", "SecurityBuddy/2.0 (Security Scanner)")
                _default_session = s
    return _default_session


def _validate_or_block(current_url):
    """Validate the URL's host and return ``(host, pinned_ip)`` or raise."""
    parsed = urlparse(current_url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise SSRFSecurityError("Blocked request to a non-HTTP(S) URL")
    host = parsed.hostname
    if not host:
        raise SSRFSecurityError("Blocked request to a URL with no host")
    ok, ip, err = resolve_and_validate_host(host)
    if not ok:
        raise SSRFSecurityError(err or "Blocked request to a disallowed host")
    return host, ip


def secure_request(url, method="GET", timeout=10, max_redirects=3, session=None, **kwargs):
    """Perform an SSRF-safe HTTP request.

    The target host (and every redirect hop) is resolved and validated to be a
    public IP, and the socket is pinned to that IP so no second DNS lookup can
    swap in an internal address. Redirects are followed manually, up to
    ``max_redirects``, re-validating each hop.

    Pass ``allow_redirects=False`` (as the open-redirect probe does) to get the
    raw redirect response back without following it — this is honoured by
    treating it as ``max_redirects=0``.

    Any other keyword argument (``headers``, ``params``, ``data``, ``json``,
    ``stream``, ``verify`` …) is forwarded to ``requests``.

    Raises :class:`SSRFSecurityError` if the target or a redirect resolves to a
    private, loopback or otherwise non-public address.
    """
    sess = session or _get_default_session()
    follow = kwargs.pop("allow_redirects", True)
    if follow is False:
        max_redirects = 0

    method = (method or "GET").upper()
    redirects_left = max_redirects
    current_url = url

    while True:
        host, ip = _validate_or_block(current_url)
        with _pinned(host, ip):
            resp = sess.request(
                method,
                current_url,
                timeout=timeout,
                allow_redirects=False,
                **kwargs,
            )

        is_redirect = resp.status_code in _REDIRECT_CODES and "Location" in resp.headers
        if not (follow and is_redirect and redirects_left > 0):
            return resp

        next_url = urljoin(current_url, resp.headers["Location"])
        # A 303 (and a 301/302 answering a non-idempotent method) turns the
        # follow-up into a bodyless GET, matching browser and requests behaviour.
        if resp.status_code == 303 or (
            resp.status_code in (301, 302) and method not in ("GET", "HEAD")
        ):
            method = "GET"
            for body_kw in ("data", "json", "files"):
                kwargs.pop(body_kw, None)

        resp.close()  # release the connection back to the pool before the next hop
        current_url = next_url
        redirects_left -= 1
