# SecurityBuddy — Guida per Claude Code

## Panoramica del progetto

SecurityBuddy è uno scanner di sicurezza web automatizzato (v2.0.0) con interfaccia web, API REST e CLI. Analizza domini e indirizzi IP e produce un punteggio di sicurezza da 0 a 100.

**Stack:** Python 3.11+, Flask, SQLAlchemy, SQLite (dev) / PostgreSQL (prod), Vercel.

## Struttura dei file principali

```
main.py              # Entry point — importa routes e api_routes
app.py               # Factory Flask + init DB
routes.py            # Route web (/, /scan, /dashboard, /login, …)
api_routes.py        # Blueprint REST API (/api/v1/*)
scanner.py           # SecurityScanner — logica di scan
validators.py        # AdvancedValidator — validazione input
models.py            # ORM: User, ScanResult, APIKey, MonitoringConfig
premium_features.py  # PremiumAnalytics, AdvancedScanner
pdf_generator.py     # Generazione report PDF (ReportLab)
notification_system.py  # Email alert (SendGrid/Twilio)
background_jobs.py   # Job asincroni (threading, no Celery in dev)
cache_manager.py     # Cache risultati
cli.py               # CLI (entry point: securitybuddy)
```

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
| HTTPS | `_check_https` | 25 |
| Certificato SSL | `_check_ssl_certificate` | 25 |
| Security headers | `_check_security_headers` | 20 |
| Cookie security | `_check_cookie_security` | 5 |
| CORS | `_check_cors` | 5 |
| HTTP methods | `_check_http_methods` | 5 |
| Technology disclosure | `_check_technology_disclosure` | 5 |
| Open ports | `_check_open_ports` | 5 |
| Sensitive file exposure | `_check_sensitive_files` | 10 |
| Admin panel discovery | `_check_admin_panels` | 10 |

### Logica anti-false-positive

Prima di ogni scan, `_get_404_baseline()` colpisce un path UUID casuale per fingerprint la risposta di errore del server. I check successivi usano:

- `_is_false_positive(response, baseline)` — confronta dimensione body (±50 byte)
- `_is_real_exposure(path, text)` — verifica pattern nel body (es. `DB_PASSWORD`, `[core]`)
- Se il sito è una **SPA** (`baseline.is_spa = True`), i check `sensitive_files` e `admin_panels` vengono saltati automaticamente e il punteggio non viene penalizzato

## API REST

Base URL: `/api/v1/`

Autenticazione via header `X-API-Key`. Endpoint principali:

```
POST /api/v1/scan          # Avvia scan
GET  /api/v1/scan/<id>     # Risultato scan
GET  /api/v1/scans         # Lista scan dell'utente
POST /api/v1/webhook/scan  # Scan batch + webhook callback
```

Rate limit: 100 req/h (free), 1000 req/h (premium).

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
- Merge su `main` sempre con `--no-ff`
- I file statici stanno in `static/css/` e `static/js/`
- I template Jinja2 estendono tutti `base.html`, tranne pagine standalone (es. pagine con design system separato)
- Nessun Bootstrap — design system custom in `static/css/style.css` con CSS variables (`--color-*`, `--font-*`, `--radius-*`)

## Livelli di rischio

| Score | Livello |
|---|---|
| ≥ 80 | `low` |
| 60–79 | `medium` |
| 40–59 | `high` |
| < 40 | `critical` |
