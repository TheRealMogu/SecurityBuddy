# SecurityBuddy — Guida per Claude Code

## Panoramica del progetto

SecurityBuddy è uno scanner di sicurezza web automatizzato con interfaccia web, API REST e CLI. Analizza domini e indirizzi IP e produce un punteggio di sicurezza da 0 a 100. Include anche un analizzatore SEO per singola pagina e un crawler SEO per siti interi (fino a 100 pagine).

**Stack:** Python 3.11+, Flask, SQLAlchemy, SQLite (dev) / PostgreSQL (prod), Vercel.

## Struttura dei file principali

```
main.py                 # Entry point — importa routes e api_routes
app.py                  # Factory Flask + init DB
routes.py               # Route web (/, /scan, /dashboard, /login, /seo, …)
api_routes.py           # Blueprint REST API (/api/v1/*)
scanner.py              # SecurityScanner — logica di scan
seo_analyzer.py         # SEOAnalyzer — analisi SEO singola pagina + PageSpeed
validators.py           # AdvancedValidator — validazione input
models.py               # ORM: User, ScanResult, APIKey, MonitoringConfig
notification_system.py  # Email alert (SendGrid/Twilio)
background_jobs.py      # Job asincroni per il crawler SEO (threading)
cache_manager.py        # Cache risultati
cli.py                  # CLI (entry point: securitybuddy)
```

> `premium_features.py` e `pdf_generator.py` sono presenti nel repo ma non usati —
> le funzionalità premium sono state rimosse (nessun gate `is_premium`).

## Come avviare in locale

```bash
# Installa dipendenze
uv pip install -e .

# Avvia il server
SESSION_SECRET=dev python main.py
# oppure
flask --app main run --debug
```

Il server parte su `http://localhost:5000`. Il DB SQLite viene creato automaticamente al primo avvio.

## Architettura dello scanner

`SecurityScanner.scan_target(target)` in `scanner.py` esegue questi check in sequenza:

| Check | Metodo | Punteggio max |
|---|---|---|
| Connettività | `_check_connectivity` | 10 |
| HTTPS & redirect | `_check_https` | 25 |
| Certificato SSL + TLS version | `_check_ssl_certificate` | 25 |
| Security headers (CSP quality) | `_check_security_headers` | 20 |
| Cookie security | `_check_cookie_security` | 5 |
| CORS policy | `_check_cors` | 5 |
| HTTP methods | `_check_http_methods` | 5 |
| Technology disclosure | `_check_technology_disclosure` | 5 |
| Open ports | `_check_open_ports` | 5 |
| Sensitive file exposure | `_check_sensitive_files` | 10 |
| Admin panel discovery | `_check_admin_panels` | 10 |
| DNS security (SPF + DMARC) | `_check_dns_security` | 10 |
| Mixed content | `_check_mixed_content` | 5 |
| HSTS quality | `_check_hsts_quality` | 5 |
| Subdomain takeover | `_check_subdomain_takeover` | 5 |
| Directory listing | `_check_directory_listing` | 5 |
| HTML comment / generator | `_check_html_comments` | 3 |
| Open redirect | `_check_open_redirect` | 5 |
| HTTP/2 support | `_check_http2_support` | +1 bonus |

> Il punteggio totale è sempre compresso nell'intervallo [0, 100].
> Alcuni check si applicano solo ai domini (non IP): `dns_security`, `subdomain_takeover`, `hsts_quality`, `http2`.
> `sensitive_files`, `admin_panels` e `directory_listing` vengono saltati sui siti SPA.

### Logica anti-false-positive

Prima di ogni scan, `_get_404_baseline()` colpisce un path UUID casuale per fingerprinting la risposta di errore del server. I check successivi usano:

- `_is_false_positive(response, baseline)` — confronta dimensione body (±50 byte)
- `_is_real_exposure(path, text)` — verifica pattern nel body (es. `DB_PASSWORD`, `[core]`)
- Se il sito è una **SPA** (`baseline.is_spa = True`), i check `sensitive_files`, `admin_panels` e `directory_listing` vengono saltati automaticamente

## Architettura SEO

`SEOAnalyzer.analyze(target)` in `seo_analyzer.py` esegue:

- URL & redirect chain
- HTTPS & HSTS
- Meta tags (title, description, canonical, noindex)
- Content quality (word count, headings, keyword stats via `top_keywords_with_stats`)
- Images (alt text, lazy loading)
- Links (interni/esterni, broken)
- PageSpeed Insights — mobile **e** desktop in parallelo (`ThreadPoolExecutor`)
  - Risultati in `checks.pagespeed` (mobile) e `checks.pagespeed_desktop`
  - Screenshot pagina in `checks.pagespeed.screenshot` (data URI base64)
- Structured data, robots meta, Open Graph, Twitter Card

Il crawler SEO (`background_jobs.py`) visita fino a 100 pagine del sito tramite sitemap + BFS, producendo per ogni URL un mini-risultato SEO con score, issues e warnings. Il report viene servito da `seo_site.html`.

## Template Jinja2

| Template | Descrizione |
|---|---|
| `base.html` | Layout base con navbar e footer |
| `index.html` | Homepage con form di scan |
| `scan_result.html` | Risultato scan sicurezza — sidebar score + accordion check |
| `seo.html` | Analisi SEO singola pagina — tabbed interface (Overview/Base/Content/Performance/Social) |
| `seo_site.html` | Report crawl SEO sito — tabbed interface (Overview/Issues/Pages/Site checks) |
| `dashboard.html` | Dashboard utente con storico scan |
| `login.html` | Login + registrazione (tab switcher) |
| `api_keys.html` | Gestione API key |
| `seo_crawl_waiting.html` | Pagina di attesa con polling del job SEO |
| `404.html`, `500.html` | Pagine di errore |

Tutti i template estendono `base.html` tranne le pagine standalone.

## API REST

Base URL: `/api/v1/`

Autenticazione via header `X-API-Key`. Endpoint principali:

```
POST /api/v1/scan          # Avvia scan
GET  /api/v1/scan/<id>     # Risultato scan
GET  /api/v1/scans         # Lista scan dell'utente (paginata)
POST /api/v1/webhook       # Scan batch + webhook callback
GET  /api/v1/status        # Info utente e API key
```

Rate limit: **200 req/h** per tutte le chiavi.

## Route web principali

```
GET  /                     # Homepage
POST /scan                 # Avvia scan sicurezza
GET  /scan/<id>            # Visualizza risultato scan
GET  /seo                  # Form analisi SEO
POST /seo                  # Avvia analisi SEO
POST /seo/crawl            # Avvia crawl SEO (background job)
GET  /seo/crawl/<id>/status   # Polling stato crawl (JSON)
GET  /seo/crawl/<id>/report   # Report crawl completato
GET  /dashboard            # Dashboard utente (login required)
GET  /api-keys             # Gestione API key (login required)
GET  /login                # Login / registrazione
GET  /badge/<domain>/<score>.svg  # Badge SVG dinamico
```

## Deploy (Vercel)

`vercel.json` usa due builder:
- `@vercel/python` su `main.py` — gestisce tutte le route Flask
- `@vercel/static` su `static/**` — serve CSS/JS/immagini

**Importante:** senza il builder `@vercel/static`, i file statici non vengono inclusi nel bundle e la pagina appare non stilizzata.

## Variabili d'ambiente

| Variabile | Descrizione |
|---|---|
| `SESSION_SECRET` | Chiave segreta Flask (obbligatoria in prod) |
| `DATABASE_URL` | PostgreSQL URL (se assente usa SQLite) |
| `FLASK_DEBUG` | Abilita debug mode |
| `SENDGRID_API_KEY` | Per notifiche email |
| `TWILIO_*` | Per SMS alert |

## Convenzioni di sviluppo

- Branch di lavoro: `claude/` prefix (es. `claude/add-response-validation-d1KnL`)
- I file statici stanno in `static/css/` e `static/js/`
- I template Jinja2 estendono tutti `base.html`
- Nessun Bootstrap — design system custom in `static/css/style.css` con CSS variables (`--color-*`, `--font-*`, `--radius-*`)
- Colore primario: `#01696f` (teal)
- Favicon generata con Pillow: scudo bianco su sfondo teal, file multipli in `static/`

## Livelli di rischio

| Score | Livello |
|---|---|
| ≥ 80 | `low` |
| 60–79 | `medium` |
| 40–59 | `high` |
| < 40 | `critical` |
