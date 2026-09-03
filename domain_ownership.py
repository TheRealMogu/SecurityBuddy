"""Domain-ownership verification for active penetration testing.

Active probes — SQL-injection payloads, XSS injection, admin-path brute — are
lawful against a target you control and an intrusion against one you do not. A
self-attestation checkbox ("I confirm I am authorized") is not proof of
anything: it lets any visitor point the probes at any third party. Real scanners
(Qualys, Detectify, Google's) require you to demonstrate control of the domain
before they will actively test it, and this does the same.

Two proofs are accepted, either one sufficient, both the industry norm:

  * a DNS TXT record on the domain containing the verification token, or
  * a file at http(s)://<domain>/.well-known/securitybuddy-verify.txt whose
    contents are the token.

Only someone who administers the domain's DNS, or can write to its web root, can
place either. The token is per user and per domain, so one user's proof cannot
authorise another's target.
"""

import secrets
import socket
from urllib.parse import urlparse

import requests

try:
    import dns.resolver
    _HAVE_DNS = True
except ImportError:  # pragma: no cover - dnspython is a hard dependency
    _HAVE_DNS = False

TOKEN_PREFIX = "securitybuddy-verify"
WELL_KNOWN_PATH = "/.well-known/securitybuddy-verify.txt"
_HTTP_TIMEOUT = 6


def new_token() -> str:
    """A fresh, unguessable verification token."""
    return f"{TOKEN_PREFIX}={secrets.token_hex(16)}"


def normalise_domain(raw: str) -> str | None:
    """Reduce user input to a bare registrable hostname, or None if it is not
    one. An IP address is rejected: ownership of an IP is not something DNS TXT
    or a well-known file can prove in the same way, and renting an address is
    not authority over what runs on it."""
    value = (raw or "").strip().lower()
    if not value:
        return None
    if "://" in value:
        value = urlparse(value).netloc or value
    value = value.split("/")[0].split("@")[-1].split(":")[0].strip(".")
    if not value or " " in value:
        return None
    # An IPv4 or IPv6 literal is not a domain for this purpose.
    try:
        socket.inet_aton(value)
        return None
    except OSError:
        pass
    if ":" in value:  # IPv6 literal
        return None
    if "." not in value or value.endswith("."):
        return None
    if not all(part and len(part) <= 63 and
               all(c.isalnum() or c == "-" for c in part)
               for part in value.split(".")):
        return None
    return value


def check_dns(domain: str, token: str) -> tuple[bool, str]:
    """True when a TXT record on the domain carries the token."""
    if not _HAVE_DNS:
        return False, "DNS lookups are not available on this server."
    seen = []
    for name in (domain, f"_{TOKEN_PREFIX}.{domain}"):
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=_HTTP_TIMEOUT)
        except Exception:
            continue
        for record in answers:
            text = b"".join(getattr(record, "strings", []) or []).decode("utf-8", "replace") \
                or str(record).strip('"')
            seen.append(text)
            if token in text:
                return True, f"Found the token in a TXT record on {name}."
    if seen:
        return False, "TXT records were found, but none contained the token yet."
    return False, "No TXT record carrying the token was found."


def check_well_known(domain: str, token: str) -> tuple[bool, str]:
    """True when the well-known file serves the token. Tries HTTPS, then HTTP."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}{WELL_KNOWN_PATH}"
        try:
            resp = requests.get(url, timeout=_HTTP_TIMEOUT, allow_redirects=False,
                                headers={"User-Agent": "SecurityBuddy-DomainVerify/1.0"})
        except requests.RequestException:
            continue
        if resp.status_code == 200 and token in resp.text:
            return True, f"Found the token at {url}."
        if resp.status_code == 200:
            return False, "The file was served, but did not contain the token yet."
    return False, "The verification file could not be fetched over HTTPS or HTTP."


def verify(domain: str, token: str) -> tuple[bool, str]:
    """Either proof is enough. DNS is tried first: it does not depend on a web
    server being up, and it is the harder of the two to place without control
    of the domain."""
    ok, detail = check_dns(domain, token)
    if ok:
        return True, detail
    ok, file_detail = check_well_known(domain, token)
    if ok:
        return True, file_detail
    return False, f"{detail} {file_detail}"


def instructions(domain: str, token: str) -> dict:
    """What to show the user so they can place either proof."""
    return {
        "dns": {
            "type": "TXT",
            "host": domain,
            "value": token,
            "note": f"Add a TXT record on {domain} (or on _{TOKEN_PREFIX}.{domain}) "
                    f"with this exact value, then check again. DNS can take a few "
                    f"minutes to propagate.",
        },
        "file": {
            "url": f"https://{domain}{WELL_KNOWN_PATH}",
            "contents": token,
            "note": f"Serve a file at {WELL_KNOWN_PATH} on {domain} whose contents "
                    f"are exactly this token, then check again.",
        },
    }
