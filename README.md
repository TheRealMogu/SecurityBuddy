# Security Buddy

A comprehensive web security and SEO scanning platform. Instant analysis for any domain or IP — no account required.

## Features

- **Security Scanner** — 18 checks: HTTPS, SSL/TLS, headers, cookies, CORS, DNS (SPF/DMARC), open ports, mixed content, HSTS quality, subdomain takeover, directory listing, open redirect, and more
- **Email Security** — MX records, SPF, DMARC, DKIM, 7 IP blacklists + 2 domain blacklists, PTR/rDNS, STARTTLS per mail server
- **SEO Analyser** — meta tags, content quality, PageSpeed Insights (mobile + desktop), Open Graph, structured data
- **Site Crawler** — crawl up to 100 pages and get a per-page SEO breakdown
- **REST API** — programmatic access with API keys, batch scanning and webhook callbacks
- **Dashboard** — scan history for registered users
- **No premium gates** — all features are free

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SESSION_SECRET` | ✅ | Flask session secret key |
| `DATABASE_URL` | ✅ (prod) | PostgreSQL connection string — SQLite used locally |
| `FLASK_DEBUG` | — | Set to `1` to enable debug mode |
| `SENDGRID_API_KEY` | — | Email notifications |
| `TWILIO_*` | — | SMS alerts |

### Database Setup

1. Create a PostgreSQL database ([Neon](https://neon.tech/) or [Supabase](https://supabase.com/) work well)
2. Set `DATABASE_URL`
3. Tables are created automatically on first run

## Local Development

```bash
git clone https://github.com/therealmogu/securitybuddy
cd securitybuddy

uv pip install -e .
SESSION_SECRET=dev python main.py
# → http://localhost:5000
```

## Security Checks

| Check | What it verifies |
|---|---|
| Connectivity | Reachability, HTTP status |
| HTTPS & Redirect | HTTPS availability, HTTP→HTTPS redirect |
| SSL Certificate | Validity, expiry, issuer, TLS version (1.2/1.3) |
| Security Headers | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-Content-Type-Options |
| HSTS Quality | max-age adequacy, includeSubDomains, preload flag |
| Cookie Security | Secure, HttpOnly, SameSite per cookie |
| CORS Policy | Wildcard origin, credentials-with-wildcard |
| HTTP Methods | TRACE/TRACK/DELETE/PUT exposure |
| Technology Fingerprint | Server version disclosure in headers |
| HTML Comment / Generator | `<meta generator>` and version-disclosing comments |
| Open Ports | FTP, Telnet, MySQL, Redis, MongoDB, Elasticsearch… |
| Sensitive File Exposure | `.env`, `.git/config`, `wp-config.php`, `database.yml`… |
| Admin Panel Discovery | `/admin`, `/phpmyadmin`, `/wp-admin`… |
| DNS Security | SPF record, DMARC policy |
| Subdomain Takeover | Dangling CNAME → unclaimed GitHub Pages, Heroku, Netlify, Azure… |
| Directory Listing | Apache/Nginx index pages on common paths |
| Mixed Content | HTTP resources on HTTPS pages |
| Open Redirect | Common redirect parameters (`?redirect=`, `?url=`, `?next=`…) |
| HTTP/2 Support | ALPN negotiation (informational) |

## Email Security Checks

| Check | What it verifies |
|---|---|
| MX Records | Mail server hostnames, priority, redundancy (1 vs 2+) |
| SPF | Policy (`-all` hardfail recommended), DNS lookup count (RFC limit: 10) |
| DMARC | Policy (`p=none/quarantine/reject`), `pct`, `rua`/`ruf` reporting addresses |
| DKIM | 18 common selectors probed in parallel, key-bit strength (warn if < 1024) |
| Blacklists — IP | Spamhaus ZEN, SpamCop, SORBS, Barracuda, UCEPROTECT L1, PSBL, S5H |
| Blacklists — Domain | Spamhaus DBL, URIBL Multi |
| PTR / rDNS | Reverse DNS for each MX server IP |
| STARTTLS | Port 25 connectivity + STARTTLS advertisement per mail server |

## API Usage

```bash
# Scan without authentication
curl -X POST https://your-app.vercel.app/api/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"target": "example.com"}'

# Batch scan with webhook callback
curl -X POST https://your-app.vercel.app/api/v1/webhook \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "targets": ["example.com", "example.org"],
    "fail_threshold": 70,
    "webhook_url": "https://your-ci.example/hook"
  }'

# API key status
curl https://your-app.vercel.app/api/v1/status \
  -H "X-API-Key: your-api-key"
```

Rate limit: **200 requests/hour** per API key.

## License

MIT License
