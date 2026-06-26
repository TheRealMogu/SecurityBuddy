"""Editorial content for the Security Buddy guides section.

Each guide is original, long-form educational content that explains a web
security topic in depth. Guides are stored as structured data and rendered by
a single template (``templates/guide.html``); the hub (``templates/guides.html``)
is generated automatically from this list.

Keeping the content here — rather than in many near-identical HTML files — keeps
the section DRY and makes it trivial to add per-guide metadata (meta description,
reading time, JSON-LD) that benefits both SEO and readers.
"""

# Last meaningful content review. Surfaced to readers and in the sitemap.
GUIDES_UPDATED = "2026-06-23"

GUIDES = [
    {
        "slug": "https-ssl-tls-explained",
        "title": "HTTPS, SSL and TLS Explained: What a Padlock Really Means",
        "description": (
            "A plain-English guide to HTTPS, TLS certificates, the handshake, "
            "common SSL misconfigurations and how to fix them."
        ),
        "category": "Encryption",
        "icon": "lock",
        "read_time": "8 min read",
        "body": """
<p class="guide-lead">The padlock in your browser's address bar is one of the most
recognised security symbols on the internet — and one of the most misunderstood.
This guide explains what HTTPS actually guarantees, how the underlying TLS
protocol works, and the configuration mistakes that quietly weaken otherwise
"secure" sites.</p>

<h2>HTTP vs HTTPS: the one-line difference</h2>
<p>Plain <strong>HTTP</strong> sends every request and response as readable text.
Anyone positioned between your visitor and your server — a malicious Wi-Fi hotspot,
a compromised router, an internet provider — can read it, log it, or modify it in
transit. <strong>HTTPS</strong> is the same HTTP protocol wrapped inside an
encrypted <strong>TLS</strong> (Transport Layer Security) tunnel. TLS is the modern
successor to the older, now-deprecated SSL protocol; people still say "SSL
certificate" out of habit, but every secure site today uses TLS.</p>

<p>HTTPS provides three distinct guarantees, and it is worth keeping them separate
in your head:</p>
<ul>
  <li><strong>Confidentiality</strong> — the contents of each request and response
  are encrypted, so a network observer sees only ciphertext.</li>
  <li><strong>Integrity</strong> — if anyone tampers with the data in transit, the
  cryptographic checks fail and the connection is dropped.</li>
  <li><strong>Authentication</strong> — the certificate proves you are really
  talking to the server that owns the domain, not an impostor.</li>
</ul>

<h2>What actually happens during the TLS handshake</h2>
<p>Before any page data flows, the browser and server perform a short negotiation
called the handshake. Simplified, it looks like this:</p>
<ol>
  <li>The browser says hello and lists the TLS versions and cipher suites it
  supports.</li>
  <li>The server picks the strongest mutually-supported option and presents its
  <strong>certificate</strong> — a signed document binding a public key to a
  domain name.</li>
  <li>The browser verifies that certificate against its built-in list of trusted
  <strong>Certificate Authorities</strong> (CAs). It checks the signature, the
  expiry dates, and that the domain on the certificate matches the site being
  visited.</li>
  <li>Using public-key cryptography, both sides agree on a fresh symmetric session
  key. From here on, the much faster symmetric encryption protects the traffic.</li>
</ol>
<p>Modern TLS 1.3 streamlines this into a single round trip, which is part of why
HTTPS is no longer the performance penalty it once was.</p>

<h2>Where certificates come from</h2>
<p>You no longer need to pay for a basic certificate. <a href="https://letsencrypt.org"
target="_blank" rel="noopener">Let's Encrypt</a> issues free, automatically-renewing
certificates that every major browser trusts, and most hosting platforms — Vercel,
Netlify, Cloudflare, and others — provision and renew them for you with zero
configuration. The practical takeaway: there is no legitimate reason for a public
website to still be served over plain HTTP.</p>

<h2>Common SSL/TLS misconfigurations</h2>
<p>Having a certificate is not the same as being configured correctly. These are the
issues our scanner sees most often:</p>

<h3>1. No HTTP → HTTPS redirect</h3>
<p>If <code>http://example.com</code> still serves content instead of redirecting to
the <code>https://</code> version, a visitor's first request can be intercepted before
encryption ever kicks in. Every plain-HTTP request should return a
<code>301</code> redirect to the HTTPS equivalent.</p>

<h3>2. Expired or soon-to-expire certificates</h3>
<p>Certificates have a validity window — typically 90 days for Let's Encrypt. An
expired certificate triggers a full-page browser warning that scares visitors away
and breaks API clients. Automate renewal and monitor expiry dates; never rely on a
human remembering.</p>

<h3>3. Outdated protocol versions</h3>
<p>SSL 2.0, SSL 3.0, TLS 1.0 and TLS 1.1 all contain known weaknesses and are
deprecated. Your server should accept only <strong>TLS 1.2 and TLS 1.3</strong>.
Supporting older versions for the sake of ancient clients exposes everyone to
downgrade-style attacks.</p>

<h3>4. Missing HSTS</h3>
<p>The <code>Strict-Transport-Security</code> response header tells browsers to
refuse plain-HTTP connections to your domain for a set period, closing the gap on
that risky first request. We cover it in detail in the
<a href="/guides/http-security-headers">security headers guide</a>.</p>

<h3>5. Mixed content</h3>
<p>An HTTPS page that loads images, scripts or stylesheets over plain HTTP is said
to contain "mixed content". Browsers block or downgrade these resources, and a
single insecure script can undermine the whole page. Audit your templates so every
asset URL uses <code>https://</code> or a protocol-relative path.</p>

<h2>How to check your own site</h2>
<p>You can inspect a site's certificate yourself from the command line:</p>
<pre><code>openssl s_client -connect example.com:443 -servername example.com &lt; /dev/null 2&gt;/dev/null | openssl x509 -noout -dates -issuer</code></pre>
<p>That prints the issuer and the validity window. For a friendlier, all-in-one
report — protocol versions, redirect behaviour, expiry, and more — run your domain
through the <a href="/">Security Buddy scanner</a>; the HTTPS &amp; SSL section
grades exactly these items and tells you what to fix first.</p>

<h2>Key takeaways</h2>
<ul>
  <li>HTTPS gives you confidentiality, integrity and authentication — not just
  "encryption".</li>
  <li>Free, auto-renewing certificates remove every excuse for plain HTTP.</li>
  <li>Redirect all HTTP to HTTPS, disable old protocol versions, and add HSTS.</li>
  <li>Watch for expired certificates and mixed content — both break the guarantee
  the padlock implies.</li>
</ul>
""",
    },
    {
        "slug": "http-security-headers",
        "title": "HTTP Security Headers: A Practical Checklist",
        "description": (
            "What CSP, HSTS, X-Frame-Options, Referrer-Policy and other security "
            "headers do, why they matter, and recommended values you can copy."
        ),
        "category": "Hardening",
        "icon": "shield",
        "read_time": "10 min read",
        "body": """
<p class="guide-lead">Security headers are short instructions your server sends with
every response that tell the browser how to behave more defensively. They are some
of the highest-value, lowest-effort security improvements available: a few lines of
configuration can neutralise entire classes of attack. This guide walks through the
headers that matter, what each one defends against, and a recommended value you can
adapt.</p>

<h2>Why headers, not code?</h2>
<p>Many web attacks happen inside the visitor's browser — cross-site scripting,
clickjacking, content sniffing. The browser is the one place with enough context to
stop them, but it needs to be told what rules to enforce. Security headers are that
instruction channel. Because they are set centrally on the server, they protect
every page at once without touching application logic.</p>

<h2>Content-Security-Policy (CSP)</h2>
<p>CSP is the most powerful — and most involved — security header. It defines exactly
which sources the browser may load scripts, styles, images, fonts and frames from. A
well-built CSP makes cross-site scripting (XSS) dramatically harder: even if an
attacker injects a <code>&lt;script&gt;</code> tag, the browser refuses to run it
unless it comes from an allowed origin.</p>
<p>A reasonable starting policy for a site that serves its own assets:</p>
<pre><code>Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'</code></pre>
<p>Build your CSP incrementally. Start in report-only mode
(<code>Content-Security-Policy-Report-Only</code>), watch what it would have blocked,
then tighten. Avoid <code>'unsafe-inline'</code> and <code>'unsafe-eval'</code> in
<code>script-src</code> wherever possible — they reopen the very hole CSP is meant to
close.</p>

<h2>Strict-Transport-Security (HSTS)</h2>
<p>HSTS forces browsers to use HTTPS for your domain, even if a user types
<code>http://</code> or clicks an old link. After the first secure visit, the browser
remembers the rule for the duration you specify and silently upgrades every request.</p>
<pre><code>Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</code></pre>
<p>Only add <code>preload</code> once you are confident every subdomain is HTTPS-only —
it is hard to undo quickly. The <code>max-age</code> above is one year, the
recommended value for production.</p>

<h2>X-Frame-Options / frame-ancestors</h2>
<p>These defend against <strong>clickjacking</strong>, where an attacker loads your
site inside an invisible frame on their own page and tricks users into clicking
hidden buttons. To forbid framing entirely:</p>
<pre><code>X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'</code></pre>
<p>The CSP <code>frame-ancestors</code> directive is the modern replacement and is more
flexible (you can allow specific origins), but sending both covers older browsers.</p>

<h2>X-Content-Type-Options</h2>
<p>Browsers sometimes try to guess ("sniff") the type of a file, which can turn an
innocuous upload into an executable script. One value shuts this down:</p>
<pre><code>X-Content-Type-Options: nosniff</code></pre>

<h2>Referrer-Policy</h2>
<p>By default, browsers attach the full URL of the current page to outbound requests
via the <code>Referer</code> header — potentially leaking query strings, session
tokens, or internal paths to third parties. A sensible policy:</p>
<pre><code>Referrer-Policy: strict-origin-when-cross-origin</code></pre>
<p>This sends the full URL within your own site, only the origin to other HTTPS sites,
and nothing when downgrading to HTTP.</p>

<h2>Permissions-Policy</h2>
<p>Formerly Feature-Policy, this header lets you switch off browser features your site
does not use — camera, microphone, geolocation, USB — so a compromised script cannot
abuse them:</p>
<pre><code>Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=()</code></pre>

<h2>Quick-reference table</h2>
<div class="table-wrapper">
<table class="table">
  <thead><tr><th>Header</th><th>Defends against</th><th>Recommended value</th></tr></thead>
  <tbody>
    <tr><td>Content-Security-Policy</td><td>XSS, injection</td><td><code>default-src 'self'; object-src 'none'; frame-ancestors 'none'</code></td></tr>
    <tr><td>Strict-Transport-Security</td><td>Protocol downgrade</td><td><code>max-age=31536000; includeSubDomains</code></td></tr>
    <tr><td>X-Frame-Options</td><td>Clickjacking</td><td><code>DENY</code></td></tr>
    <tr><td>X-Content-Type-Options</td><td>MIME sniffing</td><td><code>nosniff</code></td></tr>
    <tr><td>Referrer-Policy</td><td>Referrer leakage</td><td><code>strict-origin-when-cross-origin</code></td></tr>
    <tr><td>Permissions-Policy</td><td>Feature abuse</td><td><code>camera=(), microphone=(), geolocation=()</code></td></tr>
  </tbody>
</table>
</div>

<h2>Headers you should remove</h2>
<p>Defence also means saying less. Headers like <code>Server</code>,
<code>X-Powered-By</code> and <code>X-AspNet-Version</code> advertise your exact
software stack and version, handing attackers a shortcut to known exploits. Strip
them where your platform allows.</p>

<h2>Verify your configuration</h2>
<p>You can see any site's headers with a single request:</p>
<pre><code>curl -sI https://example.com</code></pre>
<p>For a graded report — including a letter score for CSP quality and a list of
missing headers ranked by impact — run your domain through the
<a href="/">Security Buddy scanner</a>. The Security Headers section maps directly to
the checklist above.</p>

<h2>Key takeaways</h2>
<ul>
  <li>Security headers stop browser-side attacks that server code cannot.</li>
  <li>CSP is the highest-impact header — build it gradually in report-only mode.</li>
  <li>Add HSTS, deny framing, disable MIME sniffing, and tighten the referrer policy.</li>
  <li>Remove headers that leak your software versions.</li>
</ul>
""",
    },
    {
        "slug": "cookie-security-flags",
        "title": "Cookie Security: HttpOnly, Secure and SameSite Explained",
        "description": (
            "How the HttpOnly, Secure and SameSite cookie flags protect sessions "
            "from theft and CSRF — with the settings every site should use."
        ),
        "category": "Sessions",
        "icon": "cookie",
        "read_time": "7 min read",
        "body": """
<p class="guide-lead">Cookies are how most websites remember who you are between
requests — which makes them a prime target. Steal a session cookie and you often
become that user, no password required. Three small flags on each cookie close most
of the common avenues of attack. This guide explains what they do and how to set
them.</p>

<h2>Why session cookies are valuable</h2>
<p>After you log in, the server typically hands your browser a session cookie: a long,
random identifier that stands in for your credentials on every subsequent request. If
an attacker can read or guess that value, they can replay it and impersonate you. The
security flags below exist to make that read-or-replay as hard as possible.</p>

<h2>The HttpOnly flag</h2>
<p>By default, any JavaScript running on a page can read its cookies via
<code>document.cookie</code>. If an attacker manages to inject a script (an XSS
attack), they can scoop up the session cookie and send it to themselves.</p>
<p>Marking a cookie <strong>HttpOnly</strong> makes it invisible to JavaScript — the
browser still sends it on requests, but page scripts cannot read it. This single flag
turns many XSS bugs from "full account takeover" into something far less severe. Every
session and authentication cookie should be HttpOnly. (Cookies your front-end
genuinely needs to read in JavaScript are the rare exception — and those should never
hold session secrets.)</p>

<h2>The Secure flag</h2>
<p>A <strong>Secure</strong> cookie is only ever transmitted over HTTPS. Without this
flag, a cookie set on your secure site can still be sent on an accidental plain-HTTP
request — exposing it to any network observer. Combined with HTTPS everywhere and
HSTS, the Secure flag ensures session cookies never travel in the clear.</p>

<h2>The SameSite flag</h2>
<p><strong>SameSite</strong> controls whether a cookie is sent on requests that
originate from <em>other</em> websites. It is the front line against
<strong>Cross-Site Request Forgery (CSRF)</strong>, where a malicious page tricks your
browser into making an authenticated request to a site you are logged into.</p>
<div class="table-wrapper">
<table class="table">
  <thead><tr><th>Value</th><th>Behaviour</th><th>Use when</th></tr></thead>
  <tbody>
    <tr><td><code>Strict</code></td><td>Never sent on cross-site requests</td><td>Maximum safety; may log users out when arriving from external links</td></tr>
    <tr><td><code>Lax</code></td><td>Sent on top-level navigations (clicking a link) but not on cross-site sub-requests</td><td>The sensible default for most session cookies</td></tr>
    <tr><td><code>None</code></td><td>Sent on all cross-site requests</td><td>Only for cookies that genuinely need cross-site use — and then <code>Secure</code> is mandatory</td></tr>
  </tbody>
</table>
</div>
<p>Most browsers now default unmarked cookies to <code>Lax</code>, but you should set
the value explicitly rather than rely on browser defaults.</p>

<h2>Putting it together</h2>
<p>A hardened session cookie looks like this on the wire:</p>
<pre><code>Set-Cookie: session=ab12...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600</code></pre>
<p>In a typical web framework you set these flags in configuration rather than by hand.
For example, in Flask:</p>
<pre><code>app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)</code></pre>
<p>(Security Buddy itself ships with exactly these defaults.)</p>

<h2>A few extra hardening tips</h2>
<ul>
  <li><strong>Scope tightly.</strong> Set <code>Path</code> and <code>Domain</code> no
  wider than necessary so cookies are not shared with unrelated parts of your site.</li>
  <li><strong>Expire sensibly.</strong> Short <code>Max-Age</code> values limit the
  window in which a stolen cookie is useful.</li>
  <li><strong>Rotate on privilege change.</strong> Issue a fresh session identifier on
  login and on permission changes to defeat session-fixation attacks.</li>
  <li><strong>Consider name prefixes.</strong> Naming a cookie with the
  <code>__Host-</code> prefix forces the browser to require <code>Secure</code>, a
  host-only scope and a root path.</li>
</ul>

<h2>Check your cookies</h2>
<p>Open your browser's developer tools, go to the Application (or Storage) tab, and
inspect each cookie's flags. Or run your domain through the
<a href="/">Security Buddy scanner</a> — the Cookie Security section lists every
cookie your site sets and flags any that are missing HttpOnly, Secure or SameSite.</p>

<h2>Key takeaways</h2>
<ul>
  <li><strong>HttpOnly</strong> hides cookies from JavaScript, blunting XSS.</li>
  <li><strong>Secure</strong> keeps cookies off plain-HTTP connections.</li>
  <li><strong>SameSite=Lax</strong> is a strong default against CSRF.</li>
  <li>Set all three explicitly on every session cookie; scope and expire them
  tightly.</li>
</ul>
""",
    },
    {
        "slug": "cors-misconfigurations",
        "title": "CORS Misconfigurations: When Sharing Becomes a Security Hole",
        "description": (
            "Understand the same-origin policy, how CORS relaxes it, and the "
            "misconfigurations that expose your API to other websites."
        ),
        "category": "APIs",
        "icon": "share-2",
        "read_time": "8 min read",
        "body": """
<p class="guide-lead">Cross-Origin Resource Sharing (CORS) is one of the most
frequently misunderstood parts of web security. Developers reach for it when a browser
blocks an API call, copy a permissive snippet from a forum, and unknowingly open their
API to every website on the internet. This guide explains what CORS really controls
and how to configure it without creating a hole.</p>

<h2>Start with the same-origin policy</h2>
<p>Browsers enforce a rule called the <strong>same-origin policy</strong>: JavaScript
running on <code>https://a.com</code> cannot read responses from
<code>https://b.com</code>. An "origin" is the combination of scheme, host and port.
This policy is fundamental — it is what stops a malicious site you visit from quietly
reading your webmail or your bank's API using your logged-in session.</p>

<h2>What CORS actually does</h2>
<p>Sometimes you legitimately need cross-origin access — a single-page app on one
domain talking to an API on another. <strong>CORS is the controlled exception</strong>
to the same-origin policy. Through a set of response headers, your server tells the
browser: "it is safe to let <em>these specific</em> other origins read my responses."</p>
<p>The key point that trips people up: <strong>CORS is enforced by the browser, and it
loosens restrictions — it never adds them.</strong> It is not a firewall. It does not
protect your server. It decides whether a browser will hand a cross-origin response
back to the calling JavaScript.</p>

<h2>The headers involved</h2>
<ul>
  <li><code>Access-Control-Allow-Origin</code> — which origin(s) may read the
  response.</li>
  <li><code>Access-Control-Allow-Credentials</code> — whether cookies and auth headers
  may be included on cross-origin requests.</li>
  <li><code>Access-Control-Allow-Methods</code> / <code>-Headers</code> — which HTTP
  methods and request headers are permitted (sent in the preflight response).</li>
</ul>
<p>For requests that could change data, the browser first sends a "preflight"
<code>OPTIONS</code> request to ask permission before making the real call.</p>

<h2>The dangerous misconfigurations</h2>

<h3>1. Wildcard origin with credentials</h3>
<p>The single worst combination is reflecting an arbitrary origin <em>and</em> allowing
credentials:</p>
<pre><code>Access-Control-Allow-Origin: https://attacker.example
Access-Control-Allow-Credentials: true</code></pre>
<p>If your server echoes back whatever <code>Origin</code> the request carried and also
sets <code>Allow-Credentials: true</code>, then any website can make authenticated
requests to your API using a victim's cookies and read the response. That is a
full-blown data-leak. The browser actually forbids the literal wildcard
<code>*</code> together with credentials — which is exactly why attackers look for
servers that <em>reflect</em> the origin instead.</p>

<h3>2. Reflecting Origin without validation</h3>
<p>A common but unsafe pattern is to read the incoming <code>Origin</code> header and
copy it straight into <code>Access-Control-Allow-Origin</code>. This effectively trusts
everyone. Always validate the origin against an explicit allow-list of domains you
control.</p>

<h3>3. Over-broad wildcards on public APIs</h3>
<p><code>Access-Control-Allow-Origin: *</code> is acceptable for genuinely public,
unauthenticated data (a public price feed, say). It becomes a problem the moment the
endpoint returns anything user-specific. Never pair it with anything that relies on
cookies or tokens.</p>

<h3>4. Trusting "null"</h3>
<p>Some requests — from sandboxed iframes or local files — send
<code>Origin: null</code>. Allow-listing the string <code>null</code> is unsafe because
attackers can produce that origin deliberately.</p>

<h2>A safe configuration</h2>
<p>The pattern that works for an authenticated API serving a known front-end:</p>
<pre><code># pseudo-code
ALLOWED = {"https://app.example.com", "https://admin.example.com"}
origin = request.headers.get("Origin")
if origin in ALLOWED:
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Vary"] = "Origin"</code></pre>
<p>Note the <code>Vary: Origin</code> header — it tells caches not to serve one
origin's CORS response to another. Echo the origin only after confirming it is in your
allow-list, and never reflect arbitrary values.</p>

<h2>Remember what CORS is not</h2>
<p>Because CORS lives in the browser, it does nothing against tools like
<code>curl</code>, scripts, or server-to-server calls — they ignore it entirely. CORS
is <strong>not</strong> authentication or authorisation. You still need real access
controls, authentication tokens and rate-limiting on the server. CORS only governs
what other websites' JavaScript may read in a victim's browser.</p>

<h2>Check your API</h2>
<p>You can probe a CORS policy by sending a forged origin and inspecting the response:</p>
<pre><code>curl -sI -H "Origin: https://evil.example" https://api.example.com/data</code></pre>
<p>If the response reflects your forged origin — especially alongside
<code>Allow-Credentials: true</code> — you have a problem. The
<a href="/">Security Buddy scanner</a> flags wildcard origins and dangerous
credential combinations automatically in its CORS Policy check.</p>

<h2>Key takeaways</h2>
<ul>
  <li>CORS relaxes the same-origin policy; it is not a server-side defence.</li>
  <li>Never combine a reflected/wildcard origin with
  <code>Allow-Credentials: true</code>.</li>
  <li>Validate origins against an explicit allow-list and send <code>Vary: Origin</code>.</li>
  <li>CORS does not replace authentication, authorisation or rate-limiting.</li>
</ul>
""",
    },
    {
        "slug": "open-ports-and-network-exposure",
        "title": "Open Ports and Network Exposure: Reducing Your Attack Surface",
        "description": (
            "What open ports reveal about your servers, which ones should never face "
            "the internet, and how to shrink your network attack surface."
        ),
        "category": "Infrastructure",
        "icon": "radio",
        "read_time": "9 min read",
        "body": """
<p class="guide-lead">Every open port on an internet-facing server is a door. Some you
open on purpose — a web server needs ports 80 and 443. Others get left ajar by default
configurations, forgotten test setups, or convenience over caution. This guide explains
what ports are, which ones are dangerous to expose, and how to shrink your attack
surface.</p>

<h2>What a port actually is</h2>
<p>An IP address identifies a machine; a <strong>port</strong> identifies a specific
service on that machine. When software "listens" on a port, it accepts connections
there. A web server listens on 443; a PostgreSQL database listens on 5432; SSH listens
on 22. Scanning a host for open ports tells an attacker exactly which services are
running and reachable — the first step of almost every intrusion.</p>

<h2>The principle: least exposure</h2>
<p>The core idea is simple: <strong>a service that does not need to be reachable from
the internet should not be reachable from the internet.</strong> Your database, cache,
admin panel and internal APIs almost never need a public port. Yet they routinely end
up exposed because the default install binds to <code>0.0.0.0</code> (all interfaces)
instead of <code>127.0.0.1</code> (localhost only), and no firewall blocks the rest.</p>

<h2>Ports that should rarely face the internet</h2>
<div class="table-wrapper">
<table class="table">
  <thead><tr><th>Port</th><th>Service</th><th>Why it is risky exposed</th></tr></thead>
  <tbody>
    <tr><td>22</td><td>SSH</td><td>Constant brute-force target; restrict by IP and use keys, not passwords</td></tr>
    <tr><td>23</td><td>Telnet</td><td>Unencrypted remote shell — should not be running at all</td></tr>
    <tr><td>3306</td><td>MySQL / MariaDB</td><td>Direct database access; bind to localhost</td></tr>
    <tr><td>5432</td><td>PostgreSQL</td><td>Direct database access; bind to localhost</td></tr>
    <tr><td>6379</td><td>Redis</td><td>Often unauthenticated by default — a notorious breach vector</td></tr>
    <tr><td>27017</td><td>MongoDB</td><td>Historically shipped with no auth and a public bind</td></tr>
    <tr><td>9200</td><td>Elasticsearch</td><td>Frequently exposed with no authentication, leaking entire datasets</td></tr>
    <tr><td>3389</td><td>RDP</td><td>Remote Desktop; a top ransomware entry point</td></tr>
    <tr><td>11211</td><td>Memcached</td><td>No auth; abused for huge amplification DDoS attacks</td></tr>
  </tbody>
</table>
</div>
<p>The pattern is clear: databases, caches and remote-administration services are the
high-value targets. Many of these historically shipped with no authentication and a
public network bind — a combination responsible for some of the largest data leaks on
record.</p>

<h2>Why "no one knows the IP" is not protection</h2>
<p>It is tempting to think an obscure server is safe because nobody knows it exists.
The entire IPv4 internet can be port-scanned in under an hour with ordinary tools, and
services like Shodan continuously index exposed devices. Within minutes of a database
appearing on a public port, automated bots will find and probe it. Obscurity is not a
control.</p>

<h2>How to reduce your exposure</h2>
<h3>1. Bind services to localhost</h3>
<p>Configure databases and caches to listen on <code>127.0.0.1</code> only. Your
application, running on the same host or private network, can still reach them; the
public internet cannot.</p>

<h3>2. Put a firewall in front</h3>
<p>Default-deny inbound traffic and explicitly allow only the ports you need (usually
just 80 and 443). On a Linux host this might be a few <code>ufw</code> rules; in the
cloud it is a security group. The rule of thumb: allow-list the few, block the rest.</p>

<h3>3. Use a private network for internal services</h3>
<p>Cloud providers let you place databases and internal services on a private subnet
with no public IP at all. Application servers reach them over the private network,
removing the question of public exposure entirely.</p>

<h3>4. Lock down remote administration</h3>
<p>If you must expose SSH, restrict it to known source IP addresses, disable password
authentication in favour of keys, and consider a VPN or bastion host so the port is
never directly public.</p>

<h3>5. Decommission what you do not use</h3>
<p>Old test environments, abandoned services and forgotten containers accumulate open
ports. Periodically scan your own ranges and shut down anything you no longer need —
you cannot attack a service that is not running.</p>

<h2>Scan yourself before someone else does</h2>
<p>From another machine you can probe a host with <code>nmap</code>:</p>
<pre><code>nmap -Pn -p 22,80,443,3306,5432,6379,27017 example.com</code></pre>
<p>For a quick, no-install check, the <a href="/">Security Buddy scanner</a> probes a
curated set of risky ports — databases, admin panels and caches — and explains the risk
of each one it finds open, so you can prioritise what to close first.</p>

<h2>Key takeaways</h2>
<ul>
  <li>Every open port is attack surface; expose only what genuinely must be public.</li>
  <li>Bind databases and caches to localhost or a private network, never
  <code>0.0.0.0</code>.</li>
  <li>Default-deny with a firewall and allow-list only the ports you need.</li>
  <li>Obscurity is not protection — exposed services are found within minutes.</li>
</ul>
""",
    },
    {
        "slug": "strong-passwords-and-password-managers",
        "title": "Strong Passwords and Password Managers: A 2026 Guide",
        "description": (
            "Why length beats complexity, how attackers crack passwords, and how to "
            "use password managers and passkeys to stay safe."
        ),
        "category": "Authentication",
        "icon": "key",
        "read_time": "8 min read",
        "body": """
<p class="guide-lead">Passwords remain the front door to most of our digital lives, and
the advice around them has quietly changed. The old rules — forced complexity, frequent
rotation — have given way to a simpler, more effective model. This guide explains how
passwords are actually attacked and what genuinely protects you in 2026.</p>

<h2>How passwords get cracked</h2>
<p>Understanding the threat clarifies the defence. Attackers rarely sit there typing
guesses into a login form. Instead:</p>
<ul>
  <li><strong>Credential stuffing.</strong> When one site is breached, attackers take
  the leaked email/password pairs and try them everywhere else. Most people reuse
  passwords, so one breach unlocks many accounts.</li>
  <li><strong>Offline brute-force.</strong> If attackers steal a database of password
  hashes, they can guess billions of candidates per second on dedicated hardware —
  with no login form to slow them down.</li>
  <li><strong>Dictionary and rule-based attacks.</strong> Crackers start with common
  passwords and predictable patterns (<code>Password1!</code>,
  <code>Summer2025</code>), so "complex-looking" passwords often fall fast.</li>
</ul>

<h2>Length beats complexity</h2>
<p>The single most important property of a password is its <strong>length</strong>.
Every additional character multiplies the number of possibilities an attacker must try.
A short password packed with symbols (<code>P@ss1!</code>) is weaker than a long,
memorable string of words.</p>
<p>This is why current guidance from bodies like NIST recommends <strong>passphrases</strong>:
four or five random words such as <code>correct-harbor-violin-medal</code> are easy to
remember and astronomically hard to brute-force. Crucially, the words must be
<em>randomly chosen</em> — a phrase from a song or quote is already in the attackers'
wordlists.</p>

<h2>The rules that turned out to be counter-productive</h2>
<ul>
  <li><strong>Forced periodic rotation.</strong> Making people change passwords every
  90 days pushes them toward predictable patterns
  (<code>Spring2025</code> &rarr; <code>Summer2025</code>). Modern guidance: change a
  password only when there is evidence of compromise.</li>
  <li><strong>Mandatory character classes.</strong> Demanding an uppercase letter, a
  number and a symbol nudges everyone to the same tricks (<code>a&rarr;@</code>,
  <code>s&rarr;$</code>) that crackers already know. Length and randomness matter more.</li>
</ul>

<h2>The real fix: a password manager</h2>
<p>You cannot remember a unique 20-character random password for hundreds of sites — and
you should not try. A <strong>password manager</strong> generates, stores and fills
strong, unique passwords for every account behind a single master passphrase. This
solves the biggest real-world weakness — reuse — in one move.</p>
<p>Practical guidance:</p>
<ul>
  <li>Choose a reputable manager (built into your browser or OS, or a dedicated app).</li>
  <li>Protect it with a long, unique master passphrase you have never used elsewhere.</li>
  <li>Let it generate random passwords of at least 16 characters for every site.</li>
  <li>Turn on multi-factor authentication for the manager itself.</li>
</ul>
<p>Security Buddy includes a free, fully client-side
<a href="/tools/password">password generator</a> — passwords are created in your
browser and never sent anywhere — if you need strong values on the spot.</p>

<h2>Multi-factor authentication (MFA)</h2>
<p>Even a perfect password can be phished or leaked. <strong>MFA</strong> adds a second
factor so a stolen password alone is not enough. In rough order of strength:</p>
<ol>
  <li><strong>Hardware security keys / passkeys</strong> — phishing-resistant, the gold
  standard.</li>
  <li><strong>Authenticator apps</strong> (time-based codes) — solid and widely
  supported.</li>
  <li><strong>SMS codes</strong> — better than nothing, but vulnerable to SIM-swapping;
  avoid for high-value accounts.</li>
</ol>
<p>Enable MFA everywhere it is offered, prioritising email, banking and your password
manager.</p>

<h2>Passkeys: the beginning of the end for passwords</h2>
<p><strong>Passkeys</strong> are a newer, phishing-resistant replacement for passwords
built on public-key cryptography. Your device holds a private key; the site holds only
a public key. There is no shared secret to steal, reuse or phish, and signing in is
often just a fingerprint or face scan. Where a service offers passkeys, they are now
the most secure and convenient option available — adopt them as they roll out.</p>

<h2>Have you already been breached?</h2>
<p>Check your email addresses against <a href="https://haveibeenpwned.com"
target="_blank" rel="noopener">Have I Been Pwned</a>, a free service that tells you
which known breaches included your accounts. If a password shows up, change it
everywhere you used it — and let your password manager make sure that never happens
again.</p>

<h2>Key takeaways</h2>
<ul>
  <li>Length and randomness beat forced complexity — use passphrases.</li>
  <li>Reuse is the real danger; a password manager eliminates it.</li>
  <li>Turn on MFA everywhere, preferring authenticator apps or hardware keys.</li>
  <li>Adopt passkeys wherever they are offered.</li>
</ul>
""",
    },
    {
        "slug": "phishing-and-email-security",
        "title": "Phishing and Email Security: How to Spot and Stop It",
        "description": (
            "Recognise phishing techniques and learn how SPF, DKIM and DMARC stop "
            "attackers from spoofing your domain."
        ),
        "category": "Email",
        "icon": "mail",
        "read_time": "9 min read",
        "body": """
<p class="guide-lead">Phishing remains the most common way attackers get their first
foothold — not by breaking encryption, but by convincing a person to hand over a
password or click a malicious link. This guide covers how to recognise phishing as a
user, and how the email authentication standards SPF, DKIM and DMARC stop attackers
from impersonating your domain.</p>

<h2>What phishing is</h2>
<p>Phishing is social engineering delivered by message: an email, text or chat that
impersonates someone you trust to make you act against your interests — entering
credentials on a fake login page, approving a payment, or opening a malicious
attachment. The best phishing is not riddled with typos; it is a near-perfect copy of a
real message, timed and worded to create urgency.</p>

<h2>How to spot a phishing message</h2>
<ul>
  <li><strong>Mismatched sender address.</strong> The display name says "Your Bank" but
  the actual address is a look-alike domain (<code>your-bank-secure.com</code>). Always
  check the real address, not just the name.</li>
  <li><strong>Urgency and threats.</strong> "Your account will be closed in 24 hours."
  Pressure is designed to stop you thinking.</li>
  <li><strong>Links that do not match.</strong> Hover over a link before clicking; the
  visible text and the real destination often differ. On mobile, long-press to preview.</li>
  <li><strong>Unexpected attachments.</strong> Invoices, shipping notices and "scanned
  documents" you were not expecting are classic malware carriers.</li>
  <li><strong>Requests for credentials or codes.</strong> Legitimate organisations do
  not ask for your password or one-time codes by email.</li>
  <li><strong>Look-alike domains.</strong> Watch for swapped characters
  (<code>rn</code> for <code>m</code>), extra words, or unusual top-level domains.</li>
</ul>
<p>When in doubt, do not click. Navigate to the organisation's site directly by typing
the address you know, or call them using a number from their official site — never one
from the suspicious message.</p>

<h2>Defending your own domain: SPF, DKIM, DMARC</h2>
<p>If you own a domain, you have a responsibility too: stop attackers from sending
phishing emails that appear to come from <em>you</em>. Three DNS-based standards work
together to make spoofing your domain hard.</p>

<h3>SPF — Sender Policy Framework</h3>
<p>SPF is a DNS record listing which mail servers are allowed to send email for your
domain. Receiving servers check the sending server's IP against this list. A simple
record:</p>
<pre><code>v=spf1 include:_spf.google.com ~all</code></pre>
<p>The <code>~all</code> means "anything not listed should be treated as suspicious".
Using <code>-all</code> ("hard fail") is stronger once you are confident every
legitimate sender is included.</p>

<h3>DKIM — DomainKeys Identified Mail</h3>
<p>DKIM adds a cryptographic signature to each outgoing message. The receiving server
fetches your public key from DNS and verifies the signature, proving the message really
came from your domain and was not altered in transit. Your email provider generates the
key pair and gives you a DNS record to publish.</p>

<h3>DMARC — the policy that ties it together</h3>
<p>SPF and DKIM each check something, but on their own they do not tell receivers what
to <em>do</em> with a failure. <strong>DMARC</strong> sets that policy and adds
reporting:</p>
<pre><code>v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; adkim=s; aspf=s</code></pre>
<p>Here <code>p=reject</code> tells receivers to reject mail that fails authentication,
and <code>rua</code> gives an address to send aggregate reports to. Roll DMARC out
gradually: start at <code>p=none</code> (monitor only), read the reports to confirm all
your legitimate mail passes, then move to <code>p=quarantine</code> and finally
<code>p=reject</code>.</p>

<h2>Why all three matter together</h2>
<div class="table-wrapper">
<table class="table">
  <thead><tr><th>Standard</th><th>Answers the question</th></tr></thead>
  <tbody>
    <tr><td>SPF</td><td>Is this server allowed to send for the domain?</td></tr>
    <tr><td>DKIM</td><td>Was this message really signed by the domain and unaltered?</td></tr>
    <tr><td>DMARC</td><td>What should receivers do if SPF/DKIM fail — and tell me about it?</td></tr>
  </tbody>
</table>
</div>
<p>Without DMARC set to a real enforcement policy, attackers can often still spoof your
domain even if SPF and DKIM exist. The three are designed to be deployed together.</p>

<h2>Beyond authentication</h2>
<ul>
  <li><strong>Train your people.</strong> The strongest technical controls do not stop
  a user from typing their password into a convincing fake. Regular, blame-free
  awareness training measurably reduces click rates.</li>
  <li><strong>Use MFA.</strong> Even if a password is phished, a second factor —
  ideally a phishing-resistant passkey — can stop the takeover. See our
  <a href="/guides/strong-passwords-and-password-managers">passwords guide</a>.</li>
  <li><strong>Report and contain.</strong> Make it easy for staff to report suspected
  phishing, and have a plan to reset credentials quickly when someone does click.</li>
</ul>

<h2>Check your domain</h2>
<p>You can inspect your own DNS records:</p>
<pre><code>dig +short TXT example.com        # look for the v=spf1 record
dig +short TXT _dmarc.example.com # look for the v=DMARC1 record</code></pre>
<p>The <a href="/email">Security Buddy email analyzer</a> checks whether a domain
publishes SPF, DKIM and DMARC records and flags weak or missing policies, so you can see
at a glance how spoofable your domain is.</p>

<h2>Key takeaways</h2>
<ul>
  <li>Phishing targets people, not cryptography — verify senders and never act under
  manufactured urgency.</li>
  <li>SPF lists allowed senders; DKIM signs messages; DMARC sets the enforcement policy
  and reporting.</li>
  <li>Deploy all three, rolling DMARC from <code>none</code> to <code>reject</code>.</li>
  <li>Back it with MFA and ongoing awareness training.</li>
</ul>
""",
    },
    {
        "slug": "website-security-checklist",
        "title": "The Website Security Checklist for Small Teams",
        "description": (
            "A practical, prioritised checklist covering HTTPS, headers, cookies, "
            "authentication, dependencies and backups for small teams."
        ),
        "category": "Getting Started",
        "icon": "list-checks",
        "read_time": "7 min read",
        "body": """
<p class="guide-lead">Security can feel endless, but most real-world breaches exploit a
small set of well-known weaknesses. If you run a website without a dedicated security
team, working through this prioritised checklist closes the gaps that attackers
actually use. Each item links to a deeper guide where relevant.</p>

<h2>1. Encrypt everything in transit</h2>
<ul>
  <li>Serve the whole site over HTTPS with a valid, auto-renewing certificate.</li>
  <li>Redirect all HTTP traffic to HTTPS with a <code>301</code>.</li>
  <li>Add the <code>Strict-Transport-Security</code> header.</li>
  <li>Disable TLS 1.0/1.1; accept only TLS 1.2 and 1.3.</li>
</ul>
<p>Details in the <a href="/guides/https-ssl-tls-explained">HTTPS and TLS guide</a>.</p>

<h2>2. Set your security headers</h2>
<ul>
  <li>Add a Content-Security-Policy, starting in report-only mode.</li>
  <li>Send <code>X-Content-Type-Options: nosniff</code>.</li>
  <li>Deny framing with <code>X-Frame-Options</code> / <code>frame-ancestors</code>.</li>
  <li>Set a sensible <code>Referrer-Policy</code> and trim feature access with
  <code>Permissions-Policy</code>.</li>
  <li>Remove headers that leak software versions.</li>
</ul>
<p>See the <a href="/guides/http-security-headers">security headers checklist</a>.</p>

<h2>3. Harden sessions and cookies</h2>
<ul>
  <li>Mark session cookies <code>HttpOnly</code>, <code>Secure</code> and
  <code>SameSite=Lax</code>.</li>
  <li>Issue a fresh session on login and on privilege changes.</li>
  <li>Expire sessions after a reasonable period of inactivity.</li>
</ul>
<p>More in the <a href="/guides/cookie-security-flags">cookie security guide</a>.</p>

<h2>4. Get authentication right</h2>
<ul>
  <li>Store passwords using a strong, slow hash (bcrypt, scrypt or Argon2) — never
  plain text or fast hashes like MD5/SHA-1.</li>
  <li>Enforce length-based password rules and reject known-breached passwords.</li>
  <li>Offer (and ideally require) multi-factor authentication, and support passkeys.</li>
  <li>Rate-limit and add delays to login endpoints to slow brute-force attempts.</li>
</ul>
<p>See the <a href="/guides/strong-passwords-and-password-managers">passwords and MFA
guide</a>.</p>

<h2>5. Validate input and encode output</h2>
<ul>
  <li>Treat all user input as untrusted; validate it server-side.</li>
  <li>Use parameterised queries to prevent SQL injection — never build queries by
  string concatenation.</li>
  <li>Encode output correctly for its context to prevent XSS, and back it with a strong
  CSP.</li>
  <li>Protect state-changing requests with CSRF tokens and <code>SameSite</code>
  cookies.</li>
</ul>

<h2>6. Lock down your network</h2>
<ul>
  <li>Bind databases, caches and admin tools to localhost or a private network.</li>
  <li>Default-deny inbound traffic; expose only ports 80 and 443 publicly.</li>
  <li>Restrict SSH/RDP to known IPs, with keys not passwords.</li>
</ul>
<p>See <a href="/guides/open-ports-and-network-exposure">open ports and network
exposure</a>.</p>

<h2>7. Keep dependencies patched</h2>
<ul>
  <li>Track the libraries and frameworks you depend on, and update them promptly when
  security fixes land.</li>
  <li>Enable automated dependency alerts (for example, your code host's vulnerability
  scanning).</li>
  <li>Remove packages and features you no longer use — less code, less risk.</li>
</ul>

<h2>8. Protect your email domain</h2>
<ul>
  <li>Publish SPF, DKIM and DMARC records so attackers cannot spoof your domain.</li>
  <li>Move DMARC toward an enforcing policy once your reports look clean.</li>
</ul>
<p>See <a href="/guides/phishing-and-email-security">phishing and email security</a>.</p>

<h2>9. Back up — and test restores</h2>
<ul>
  <li>Automate regular backups of data and configuration.</li>
  <li>Keep at least one copy offline or in a separate account, safe from ransomware.</li>
  <li>Actually test a restore — an untested backup is a hope, not a plan.</li>
</ul>

<h2>10. Plan for the day something goes wrong</h2>
<ul>
  <li>Log meaningful security events and keep the logs somewhere tamper-resistant.</li>
  <li>Know in advance how you would rotate credentials, revoke sessions and notify
  users.</li>
  <li>Have a simple, written incident plan — under pressure, a checklist beats
  improvisation.</li>
</ul>

<h2>Put it on autopilot</h2>
<p>Several of these items — HTTPS, headers, cookies, CORS, open ports — can be verified
in seconds. Run your domain through the <a href="/">Security Buddy scanner</a> for a
graded report, fix what it flags, and re-scan to confirm. Then work down the remaining
items above at a steady pace; you do not have to do everything at once, but you should
know where you stand.</p>

<h2>Key takeaways</h2>
<ul>
  <li>Most breaches exploit a handful of well-known gaps — close those first.</li>
  <li>Encrypt transit, set headers, harden sessions, and get authentication right.</li>
  <li>Patch dependencies, lock down your network, and protect your email domain.</li>
  <li>Back up, test restores, and write a basic incident plan before you need it.</li>
</ul>
""",
    },
]

# Index by slug for O(1) lookup in the view.
GUIDES_BY_SLUG = {g["slug"]: g for g in GUIDES}
