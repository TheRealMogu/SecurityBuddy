# SecurityBuddy — Guida allo sviluppo

## Panoramica del progetto

SecurityBuddy è uno scanner di sicurezza web automatizzato con interfaccia web, API REST e CLI. Analizza domini e indirizzi IP e produce un punteggio di sicurezza da 0 a 100. Include un analizzatore SEO per singola pagina, un crawler SEO per siti interi (fino a 100 pagine) e un analizzatore di email security (MX, SPF, DMARC, DKIM, blacklist, PTR, STARTTLS).

**Stack:** Python 3.11+, Flask, SQLAlchemy, SQLite (dev) / PostgreSQL (prod), Vercel.

## Struttura dei file principali

```
main.py                 # Entry point — importa routes e api_routes
app.py                  # Factory Flask + init DB
routes.py               # Route web (/, /scan, /dashboard, /login, /seo, …)
api_routes.py           # Blueprint REST API (/api/v1/*)
scanner.py              # SecurityScanner — logica di scan
seo_analyzer.py         # SEOAnalyzer — analisi SEO singola pagina + PageSpeed
email_analyzer.py       # EmailAnalyzer — MX, SPF, DMARC, DKIM, blacklist, PTR, STARTTLS
validators.py           # AdvancedValidator — validazione input
models.py               # ORM: User, ScanResult, APIKey, MonitoringConfig
notification_system.py  # Email alert (SendGrid/Twilio)
gmail_manager.py        # GmailManager — OAuth Google + discovery newsletter (solo header)
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

## Architettura Email Security

`EmailAnalyzer.analyze(domain)` in `email_analyzer.py` esegue:

| Check | Metodo | Punteggio max |
|---|---|---|
| MX records | `_check_mx` | 10 |
| SPF record | `_check_spf` | 15 |
| DMARC record | `_check_dmarc` | 20 |
| DKIM keys | `_check_dkim` | 15 |
| Blacklist (7 DNSBL IP + 2 domain) | `_check_blacklists` | 20 |
| PTR / reverse DNS | `_check_ptr` | 10 |
| STARTTLS per MX | `_check_smtp` | +10 bonus |

I check DKIM (18 selector comuni) e le blacklist vengono eseguiti in parallelo con `ThreadPoolExecutor`. La porta 25 può essere bloccata in ambienti cloud — il check SMTP è sempre wrapped in try/except.

**DKIM**: i selector comuni testati sono `default`, `google`, `mail`, `dkim`, `selector1`, `selector2`, `k1`, `smtp`, `mta`, `key1`, `email`, `mailjet`, `sendgrid`, `mx`, `s1`, `s2`, `sig1`, `pm`.

**Blacklist IP**: Spamhaus ZEN, SpamCop, SORBS, Barracuda, UCEPROTECT L1, PSBL, S5H.  
**Blacklist dominio**: Spamhaus DBL, URIBL Multi.

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
| `newsletter_manager.html` | Gmail Newsletter Manager — connect/disconnect, lista newsletter, unsubscribe |
| `email.html` | Analisi email security — tabbed interface (Overview/Records/Deliverability/Mail Servers) |
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
GET  /email                # Form analisi email security
POST /email                # Avvia analisi email security
GET  /dashboard            # Dashboard utente (login required)
GET  /api-keys             # Gestione API key (login required)
GET  /login                # Login / registrazione
GET  /badge/<domain>/<score>.svg  # Badge SVG dinamico
GET  /newsletter-manager   # Gmail Newsletter Manager (login required)
GET  /gmail/auth           # Avvia OAuth Google → redirect al consenso
GET  /gmail/callback       # Callback OAuth, salva i token
GET  /gmail/newsletters    # Lista newsletter (JSON) — solo header List-Unsubscribe
POST /gmail/unsubscribe     # Unsubscribe one-click (RFC 8058) o apri URL/mailto
DELETE /gmail/disconnect   # Revoca token e disconnette l'account Gmail
```

## Architettura Newsletter Manager

`gmail_manager.py` incapsula OAuth Google e la discovery delle newsletter via Gmail API
(`google-api-python-client` / `google-auth-oauthlib`). **Privacy by design**: si leggono
solo gli header dei messaggi (`From`, `Date`, `List-Unsubscribe`, `List-Unsubscribe-Post`),
mai il corpo. La query Gmail è `has:list-unsubscribe`; i metadata dei messaggi vengono
recuperati in parallelo (`ThreadPoolExecutor`) e raggruppati per mittente (ultima email per
sender). Scope minimo: `gmail.readonly`.

- I token OAuth sono salvati nel DB (`GmailCredential`, una riga per utente), non nella
  sessione cookie. La riga viene rimossa al disconnect o alla cancellazione account (cascade).
- Gli endpoint stanno sotto `/gmail/*` (non `/api/*`) perché autenticati via sessione: il
  namespace `/api/` è riservato alla REST API con `X-API-Key` ed è CSRF-exempt. Le richieste
  POST/DELETE inviano il token CSRF nell'header `X-CSRF-Token`.
- Unsubscribe: se il mittente supporta one-click (RFC 8058) il POST viene fatto lato server
  con guard anti-SSRF (solo HTTPS pubblico, no redirect); altrimenti l'URL/`mailto` viene
  aperto in una nuova scheda dal browser.
- Richiede `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`. In Google Cloud Console funziona in
  modalità "testing" aggiungendo il proprio account come test user (nessuna verifica completa).

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
| `GOOGLE_CLIENT_ID` | OAuth Google per il Newsletter Manager |
| `GOOGLE_CLIENT_SECRET` | OAuth Google per il Newsletter Manager |

## Convenzioni di sviluppo

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
