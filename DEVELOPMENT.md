# SecurityBuddy — Guida allo sviluppo

## Panoramica del progetto

SecurityBuddy è uno scanner di sicurezza web automatizzato con interfaccia web, API REST e CLI. Analizza domini e indirizzi IP e produce un punteggio di sicurezza da 0 a 100. Include un analizzatore SEO per singola pagina e un analizzatore di email security (MX, SPF, DMARC, DKIM, blacklist, PTR, STARTTLS).

**Stack:** Python 3.11+, Flask, SQLAlchemy, SQLite (dev) / PostgreSQL (prod), Vercel.

> **Architettura serverless-native**: lo scan di sicurezza gira come **micro-scan asincroni**
> orchestrati dal client (vedi [Architettura Micro-Scan Asincrona](#architettura-micro-scan-asincrona-serverless)
> qui sotto) per stare dentro il limite di 60s delle funzioni Vercel. Non esiste più un job
> manager in-memory: quel modello non sopravvive a istanze serverless effimere.

## Struttura dei file principali

```
main.py                 # Entry point — importa routes, api_routes e api_scan (blueprint)
app.py                  # Factory Flask + init DB + rate limiter + CSP/security headers
routes.py               # Route web (/, /scan, /dashboard, /login, /seo, /scan/live/<id>, …)
api_routes.py           # Blueprint REST API (/api/v1/*)
api_scan.py             # Blueprint micro-scan asincrono (/api/scan/*) — init/worker/status
scanner.py              # SecurityScanner — logica di scan (+ scan_group_* per i worker async)
seo_analyzer.py         # SEOAnalyzer — analisi SEO singola pagina + PageSpeed
email_analyzer.py       # EmailAnalyzer — MX, SPF, DMARC, DKIM (+ selector custom), blacklist, PTR, STARTTLS
threat_intel.py         # ThreatIntelAnalyzer — lookup URLhaus/ThreatFox (+ VirusTotal/AbuseIPDB opzionali)
guides_content.py       # Contenuto statico delle guide di sicurezza (/guides) — 10 guide
validators.py           # AdvancedValidator + resolve_and_validate_host — validazione input e SSRF
utils/secure_http.py    # secure_request() — wrapper HTTP con IP pinning anti SSRF/DNS-rebinding
models.py               # ORM: User, ScanResult (+ colonne micro-scan), APIKey, MonitoringConfig
notification_system.py  # Email alert (SendGrid/Twilio)
gmail_manager.py        # GmailManager — OAuth Google + discovery newsletter (solo header)
cache_manager.py        # Cache risultati
cli.py                  # CLI (entry point: securitybuddy)
static/js/pdf/          # PDF tools client-side: preserve/catalog/operations
static/vendor/          # pdf-lib + pdf.js vendorizzate e pinnate (VENDOR.json)
tools/pdf_compare.py    # Verificatore di fedelta PDF (pypdf, dev-only)
tools/verify_vendor.py  # Integrita delle librerie vendorizzate
```

> `premium_features.py` e `user_guide_system.py` sono presenti nel repo
> ma non usati — le funzionalità premium sono state rimosse (nessun gate `is_premium`).

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
| robots.txt (path sensibili) | `_check_robots_txt` | — (informativo) |
| HTTP/2 support | `_check_http2_support` | +1 bonus |

> Il punteggio totale è sempre compresso nell'intervallo [0, 100].
> Alcuni check si applicano solo ai domini (non IP): `dns_security`, `subdomain_takeover`, `hsts_quality`, `http2`.
> `sensitive_files`, `admin_panels` e `directory_listing` vengono saltati sui siti SPA.

### Metodi modulari per i micro-scan async

Oltre a `scan_target()` (usato dal fallback sincrono no-JS), `SecurityScanner` espone tre
metodi pubblici che eseguono un sottoinsieme coerente dei check sopra — usati dai worker
async (vedi sezione dedicata più sotto). L'unione dei tre gruppi copre esattamente gli
stessi check di `scan_target()`, quindi il punteggio finale è identico:

| Metodo | Check inclusi |
|---|---|
| `scan_group_ssl(target)` | `https`, `ssl`, `mixed_content`, `hsts_quality`, `http2` |
| `scan_group_headers(target)` | `connectivity`, `headers`, `cookies`, `cors`, `http_methods`, `tech`, `html_comments` |
| `scan_group_discovery(target)` | `ports`, `sensitive_files`, `admin_panels`, `directory_listing`, `robots_txt`, `open_redirect`, `dns_security`, `subdomain_takeover` |

`score(checks)` e `risk_level(score)` sono wrapper pubblici di `_calculate_score` /
`_determine_risk_level`, usati dalla route di aggregazione per calcolare il punteggio finale
una volta che tutti i moduli hanno scritto il proprio risultato.

### Protezione SSRF e DNS rebinding

Ogni richiesta HTTP in uscita (scanner, SEO analyzer, threat intel, webhook API, unsubscribe
Gmail) passa da `utils.secure_http.secure_request()` invece di chiamare `requests` /
`self.session` direttamente. Il wrapper:

- risolve e valida l'host con `validators.resolve_and_validate_host()` (rifiuta IP
  privati/loopback/link-local/reserved/multicast), e **pinna** il socket sull'IP validato
  (patch thread-local di `urllib3.util.connection.create_connection`) così una seconda
  risoluzione DNS non può cambiare l'IP tra validazione e connessione (DNS rebinding /
  TOCTOU) — l'URL/hostname originali restano intatti per SNI e verifica del certificato;
- non segue mai i redirect automaticamente: li gestisce in un loop manuale (max 3 hop di
  default), ri-validando l'host ad ogni hop, così un redirect verso un IP interno viene
  bloccato invece di essere seguito ciecamente;
- solleva `SSRFSecurityError` (sottoclasse di `requests.exceptions.RequestException`) se
  l'host — o un hop di redirect — risolve a un indirizzo non pubblico; i check esistenti che
  già gestiscono `RequestException`/`Exception` degradano quel singolo check senza
  interrompere lo scan, mentre le route utente (`/scan`, `/threat`) la intercettano
  esplicitamente e mostrano un messaggio sanificato.

I punti dove `allow_redirects=False` era già esplicito (probe open-redirect, discovery
sitemap) restano invariati passando `max_redirects=0`.

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

> **Il crawler SEO multi-pagina (fino a 100 pagine) è stato rimosso.** Si basava su
> `BackgroundJobManager` (thread in-memory), un modello incompatibile con le istanze
> serverless effimere di Vercel — il job non sopravvive tra una richiesta e l'altra su
> un'altra istanza. `analyze_site()` in `seo_analyzer.py` e `seo_site.html` restano nel
> repo ma non sono più raggiungibili da alcuna route; resta attiva solo l'analisi SEO
> per singola pagina (`/seo`). Un ripristino richiederebbe una coda/job store esterni
> (non in-memory) — vedi "Aree di miglioramento".

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

**Selector personalizzato**: il form `/email` accetta un campo opzionale "Custom DKIM
selector". `EmailAnalyzer.analyze(domain, custom_selector=...)` lo passa a `_check_dkim()`,
che lo sanifica (solo caratteri validi per un'etichetta DNS, max 63) e lo aggiunge in testa
alla lista dei 18 selector comuni — controllato in parallelo insieme agli altri. Il risultato
espone `custom_selector` e `custom_selector_found`; `email.html` mostra un badge trovato/non
trovato e lo evidenzia nella tabella dei selector trovati.

**Blacklist IP**: Spamhaus ZEN, SpamCop, SORBS, Barracuda, UCEPROTECT L1, PSBL, S5H.  
**Blacklist dominio**: Spamhaus DBL, URIBL Multi.

## Architettura Threat Intel

`ThreatIntelAnalyzer.search(query)` in `threat_intel.py` rileva il tipo di input (URL, IP,
hash MD5/SHA1/SHA256 o dominio) e interroga in parallelo (`ThreadPoolExecutor`) le sorgenti:

- **URLhaus** e **ThreatFox** (abuse.ch) — sempre attive, gratuite, nessuna chiave richiesta
- **VirusTotal** — solo se `VIRUSTOTAL_API_KEY` è impostata
- **AbuseIPDB** — solo se `ABUSEIPDB_API_KEY` è impostata (lookup IP)

Gli IP privati/loopback/link-local vengono rifiutati (`_is_private_ip`). La route `/threat`
ha un rate limit di 20 richieste/minuto per IP.

## Frontend enhancements

`static/js/enhancements.js` — loader unico per tutti gli effetti visivi, attivato su `window.load` + `requestIdleCallback`. Non tocca il critical rendering path.

| Effetto | Selettore target | Fallback |
|---|---|---|
| Shader gradient hero | `.hero-section`, `.premium-hero` (auto-inject di `.hero-bg`) | `::before` radial-gradient CSS |
| Glassmorphism scan card | `.scan-input-group` | background opaco |
| Glass trust badge | `.trust-badge` | background opaco |
| Cursor spotlight | `.features-grid .feature-card` | hover senza glow |
| Scroll reveal | `.features-grid .feature-card` (solo sotto la fold) | card visibili subito |

**Bail-out automatici**: `prefers-reduced-motion`, `Save-Data`, WebGL assente, shader compile failure, context loss WebGL, tab nascosto, sezione offscreen, **CPU low-end** (`navigator.hardwareConcurrency <= 2` — controllato in `initHeroGradient()` dopo l'iniezione di `.hero-bg`, così il fallback CSS statico resta comunque presente).

Il canvas shader viene iniettato a runtime come `firstChild` di qualsiasi `.hero-section` / `.premium-hero` — aggiungere un nuovo banner page non richiede modifiche al template. Il colore tema viene riletto dai CSS custom properties ad ogni toggle light/dark via `MutationObserver`.

## Password Generator

Tutto client-side in `templates/password_generator.html` (nessuna chiamata al server, le
password non transitano mai in rete):

- **Modalità Random Characters** (default) e **Passphrase** — toggle che genera 4–6 parole
  casuali separate da trattino da una wordlist inline compatta (equivalente semplificato
  della EFF Long List), con entropia calcolata onestamente su quel pool di parole.
- **Warning entropia bassa** — avviso visivo quando "Exclude look-alikes" è attivo alla
  lunghezza minima (8 caratteri), dove il pool ridotto abbassa sensibilmente l'entropia.
- **Cronologia di sessione** — ultime 5 password generate, salvate in `sessionStorage`
  (non `localStorage`: si azzera alla chiusura della tab, scelta deliberata per non
  persistere segreti su disco), con pulsante "Clear history".
- Preferenze (lunghezza, toggle charset, modalità, numero di parole) persistono in
  `localStorage` (`sb_pw_prefs`) — **mai** le password stesse.

## Content-Security-Policy

`app.py` imposta un `Content-Security-Policy` nell'`after_request` esistente (insieme a
`X-Content-Type-Options: nosniff` e `Referrer-Policy: strict-origin-when-cross-origin`).
La policy è self-first (`default-src 'self'`) ma allarga `script-src`/`connect-src`/
`frame-src` esattamente agli host che il sito carica davvero:

- `https://unpkg.com` — Lucide (icone, caricate su ogni pagina);
- gli host Google Ad* (`googlesyndication.com`, `googleadservices`, `doubleclick.net`…) —
  AdSense, attivo solo su pagine con `g.show_ads=True` e dietro consenso cookie;
- `https://api.fontshare.com` / `https://cdn.fontshare.com` — i web font.

`'unsafe-inline'` resta necessario su `script-src`/`style-src` per gli script inline
esistenti (consenso cookie, `enhancements.js` hook, `<link onload>`). `object-src 'none'`,
`base-uri 'self'` e `frame-ancestors 'none'` sono impostati per hardening aggiuntivo
(`frame-ancestors 'none'` rinforza l'`X-Frame-Options: DENY` già presente). Rimuovere gli
host Google Ad* se AdSense viene tolto dal sito; per una CSP `script-src 'self'` totale
servirebbe self-hostare Lucide.

## Architettura Micro-Scan Asincrona (serverless)

Lo scan di sicurezza **non gira più in modo sincrono monolitico**: su Vercel, una funzione
serverless ha un limite di 60s e istanze effimere, quindi un'esecuzione sincrona di tutti i
check rischia il timeout su target lenti. L'architettura attuale è **client-orchestrated**:
il browser avvia una scansione, poi lancia in parallelo 5 "worker" indipendenti e fa polling
di uno stato aggregato finché non sono tutti completi.

### Modello dati

`ScanResult` (in `models.py`) ha un campo `public_id` (UUID esadecimale, non l'id
autoincrementale — evita l'enumerazione), un campo `status` (`PROCESSING` → `COMPLETED`) e
cinque colonne nullable, una per modulo: `ssl_result`, `headers_result`, `ports_result`,
`seo_result`, `threat_result` (tutte `TEXT`, JSON serializzato). `modules_done()` verifica
che tutte e cinque siano popolate (dato o errore).

### Flusso

1. `POST /api/scan/init` — valida il target (via `AdvancedValidator`, con la stessa
   protezione SSRF del resto dell'app), crea la riga `ScanResult` con `status=PROCESSING`,
   ritorna `public_id` + `live_url` (pagina di progresso) + `status_url`.
2. Il browser (in `templates/scan_progress.html`) lancia in parallelo 5 `fetch()` verso
   `POST /api/scan/worker/{ssl,headers,ports,seo,threat}`, ognuno con solo `{public_id}` nel
   body — il **target viene letto dal DB**, mai passato di nuovo dal client (impedisce che
   un client aggiri la validazione SSRF di `/init` sostituendo il target a un worker).
3. Ogni worker esegue **un solo** gruppo di check (`scanner.py`: `scan_group_ssl` /
   `scan_group_headers` / `scan_group_discovery`; oppure `SEOAnalyzer.analyze` /
   `ThreatIntelAnalyzer.search`) e scrive il risultato **solo nella propria colonna** con un
   singolo `UPDATE` — nessuna corsa critica tra worker paralleli, ognuno tocca una colonna
   diversa. Un'eccezione in un worker viene catturata e salvata come `{"error": ...}` in
   quella colonna: non fa fallire lo scan né gli altri moduli.
4. Il browser fa polling di `GET /api/scan/status/<public_id>` ogni 2.5s. La route legge le
   5 colonne; quando tutte sono popolate, aggrega i check di `ssl`+`headers`+`ports` in un
   unico dizionario, calcola punteggio/risk level con `SecurityScanner.score()` /
   `.risk_level()`, salva il risultato aggregato in `results` + `security_score` e flippa
   `status` a `COMPLETED` con un `UPDATE` condizionale (`WHERE status='PROCESSING'`) — così
   anche più poll concorrenti eseguono l'aggregazione una sola volta.
5. Quando lo status è `COMPLETED`, la risposta include `report_url`: la pagina di report
   completa esistente (`scan_result.html`), invariata.

### Frontend

`templates/index.html`: il submit del form chiama `/api/scan/init` via `fetch` e reindirizza
a `live_url` invece di fare un normale POST sincrono — **progressive enhancement**: se
`fetch` non è disponibile il form ricade sul vecchio `POST /scan` sincrono (fallback no-JS,
stessa route di prima, utile anche se il flusso async fallisce).

`templates/scan_progress.html`: pagina di progresso — card per ognuno dei 5 moduli con
spinner → ✓/⚠, avvia i worker e il polling, mostra il punteggio finale con link al report.
Sia il fetch di init sia il polling dello status **tollerano risposte non-JSON** (una 500/504
di Vercel torna HTML): il codice controlla `content-type`/`response.ok` e fa `JSON.parse` in
try/catch prima di leggere i campi, così un errore server mostra un messaggio pulito invece
di far esplodere il parser JSON su `<!DOCTYPE`.

### Cosa è stato rimosso

`BackgroundJobManager` (`background_jobs.py`), `threading.Thread` e le route
`/seo/crawl*` sono state eliminate — quel modello (job in-memory, thread daemon) non
sopravvive a istanze serverless effimere: un worker thread avviato in una Lambda viene
congelato non appena la risposta HTTP parte, e il poll successivo può colpire un'altra
istanza con memoria vuota.

## Template Jinja2

| Template | Descrizione |
|---|---|
| `base.html` | Layout base con navbar e footer |
| `index.html` | Homepage con form di scan — avvia il flusso micro-scan async via `/api/scan/init` |
| `scan_progress.html` | Pagina di progresso micro-scan — card per modulo, polling status, punteggio finale |
| `scan_result.html` | Report completo scan sicurezza — sidebar score + accordion check |
| `seo.html` | Analisi SEO singola pagina — tabbed interface (Overview/Base/Content/Performance/Social) |
| `seo_site.html` | Report crawl SEO sito (feature rimossa — template non più raggiungibile) |
| `dashboard.html` | Dashboard utente con storico scan |
| `login.html` | Login + registrazione (tab switcher) |
| `api_keys.html` | Gestione API key |
| `newsletter_manager.html` | Gmail Newsletter Manager — connect/disconnect, lista newsletter, unsubscribe |
| `email.html` | Analisi email security — tabbed interface (Overview/Records/Deliverability/Mail Servers) + selector DKIM custom |
| `threat.html` | Threat Intel lookup — form + risultato per dominio/IP/URL/hash |
| `password_generator.html` | Generatore password client-side — random/passphrase, history, warning entropia |
| `guides.html`, `guide.html` | Indice e dettaglio delle guide di sicurezza (10 guide) |
| `account.html` | Impostazioni account (export dati, cancellazione) |
| `about.html`, `privacy.html` | Pagine statiche (about, privacy policy) |
| `404.html`, `500.html` | Pagine di errore — per i path `/api/*` gli errori 404/500 ritornano invece JSON (vedi errorhandler in `routes.py`) |

> `premium.html` esiste ancora nel repo ma non è più raggiungibile dalla navigazione
> (le funzionalità premium sono state rimosse).

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

## API Micro-Scan Asincrona

Base URL: `/api/scan/` (blueprint `api_scan.py`). **Pubblica e anonima**: nessuna route ha
`login_required` né richiede una API key — chiunque può avviare uno scan. `current_user` viene
letto solo per attaccare opzionalmente lo scan a un utente loggato (altrimenti resta uno scan
guest, tracciato in sessione); l'unico controllo abuso è il rate limit per IP. Come tutto il
namespace `/api/` è CSRF-exempt. Usata dal frontend per il flusso descritto in "Architettura
Micro-Scan Asincrona" qui sopra:

```
POST /api/scan/init                 # Valida target, crea ScanResult, ritorna public_id
POST /api/scan/worker/ssl           # Esegue scan_group_ssl, scrive ssl_result
POST /api/scan/worker/headers       # Esegue scan_group_headers, scrive headers_result
POST /api/scan/worker/ports         # Esegue scan_group_discovery, scrive ports_result
POST /api/scan/worker/seo           # Esegue SEOAnalyzer.analyze, scrive seo_result
POST /api/scan/worker/threat        # Esegue ThreatIntelAnalyzer.search, scrive threat_result
GET  /api/scan/status/<public_id>   # Stato aggregato + aggregazione/scoring quando completo
```

Ogni worker riceve solo `{"public_id": "..."}` nel body — il target è quello già validato e
salvato da `/init`. Rate limit: `init` 5 req/min per IP, i worker 30 req/min, `status` (GET)
esente dal rate limiter (solo i metodi non "safe" vengono throttled).

## Route web principali

```
GET  /                     # Homepage — il form avvia il flusso async via /api/scan/init
POST /scan                 # Avvia scan sicurezza sincrono (fallback no-JS)
GET  /scan/<id>            # Visualizza report completo scan
GET  /scan/live/<public_id>   # Pagina di progresso micro-scan (polling /api/scan/status)
GET  /seo                  # Form analisi SEO
POST /seo                  # Avvia analisi SEO
GET  /email                # Form analisi email security
POST /email                # Avvia analisi email security (accetta dkim_selector opzionale)
GET  /threat               # Form threat intel lookup
POST /threat               # Lookup threat intel (rate limit 20 req/min per IP)
GET  /tools/password       # Generatore password (client-side)
GET  /guides               # Indice guide di sicurezza
GET  /guides/<slug>        # Dettaglio guida
GET  /dashboard            # Dashboard utente (login required)
GET  /account              # Impostazioni account (login required)
GET  /account/export       # Export dati GDPR (login required)
POST /account/delete       # Cancellazione account (login required)
GET  /api-keys             # Gestione API key (login required)
GET  /login                # Login / registrazione (+ /register, /logout)
GET  /badge/<domain>/<score>.svg  # Badge SVG dinamico
GET  /newsletter-manager   # Gmail Newsletter Manager (login required)
GET  /gmail/auth           # Avvia OAuth Google → redirect al consenso
GET  /gmail/callback       # Callback OAuth, salva i token
GET  /gmail/newsletters    # Lista newsletter (JSON) — solo header List-Unsubscribe
POST /gmail/unsubscribe     # Unsubscribe one-click (RFC 8058) o apri URL/mailto
DELETE /gmail/disconnect   # Revoca token e disconnette l'account Gmail
```

## Architettura Newsletter Manager

> **Stato: dormiente.** La feature è completa nel codice ma disattivata finché non si
> impostano `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`. Senza quelle env il link in navbar
> è nascosto e tutte le route `/newsletter-manager` e `/gmail/*` rispondono 404 (gate
> `_require_gmail_enabled` + context flag `gmail_enabled`). Impostando le env si riattiva
> automaticamente, senza modifiche al codice.

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

## PDF Tools (client-side)

`/tools/pdf` è un set di operazioni **strutturali** sui PDF che gira interamente nel
browser. Non esiste una controparte server: nessun endpoint di upload, nessuno storage,
nessun log dei contenuti. Il file entra dalla File API ed esce come Blob.

> `pdf_generator.py` (reportlab, server-side) è stato **cancellato**: era codice morto e
> creava ambiguità sul naming. Il PDF in questo repo è solo lato client.

### Principio di fedeltà

Un'operazione che non può essere fatta preservando il documento non viene offerta. In
concreto: **mai rasterizzare**, **mai ridisegnare una pagina**, **mai appiattire**
annotazioni, campi form o layer. Le pagine si copiano con `copyPages` dal documento
originale; i content stream passano byte per byte (verificato, non assunto — vedi
`tools/pdf_compare.py`). L'unica cosa che la rotazione cambia è l'attributo `/Rotate`,
che è un numero, non un pixel.

Ciò che non è preservabile viene **elencato all'utente**, non lasciato cadere in silenzio.

### File

```
templates/pdf_tools.html      # Pagina + bootstrap delle librerie
static/js/pdf/pdflib.js       # Unico punto di contatto col global PDFLib + opzioni load/save
static/js/pdf/preserve.js     # Nucleo: rifiuti, ispezione, mappa di corrispondenza, copier, GC
static/js/pdf/catalog.js      # Preservazione delle strutture del catalogo
static/js/pdf/operations.js   # Unione, divisione/estrazione, riordino, rotazione
tools/pdf_compare.py          # Verificatore (pypdf, dev-only)
tests/pdf/                    # Test sintetici (node) + runner sui fixture
```

### Due opzioni di pdf-lib che sono requisiti, non preferenze

| Opzione | Perché |
|---|---|
| `save({ updateFieldAppearances: false })` | Di default pdf-lib **rigenera l'appearance stream di ogni campo form** usando i propri font: cambia silenziosamente il rendering di un modulo compilato. |
| `load({ updateMetadata: false })` | Di default pdf-lib riscrive `ModDate` e `Producer` al caricamento, sovrascrivendo l'identità del documento prima che possiamo copiarla. |

`ignoreEncryption` è **deliberatamente assente**. Non decifra: sopprime solo il controllo e
restituisce un documento con stringhe e stream ancora cifrati, che viene salvato come file
corrotto ma apribile. La rimozione di password e permessi **non è una funzionalità di questo
tool e non lo sarà**: togliere le protezioni a un documento non è una cosa che un sito di
sicurezza debba offrire.

### Cosa `copyPages` lascia indietro

`copyPages` copia *pagine*, non *documenti*. Tutto ciò che vive nel catalogo resta al suo
posto, e pdf-lib non avvisa. `catalog.js` riporta a mano: `/Info`, XMP, outline/bookmark,
`/AcroForm`, destinazioni nominate, allegati, page label, `/OCProperties`, attributi
documento.

**`/StructTreeRoot` (PDF taggato) non è preservabile** con pdf-lib: è incrociato con i
marked-content ID dentro i content stream e la libreria non li rimappa. L'output rende in
modo identico ma perde la marcatura di accessibilità. È un limite dichiarato, non una
scorciatoia — e viene riportato all'utente su ogni documento taggato.

### Tre trappole trovate testando, e come sono chiuse

**1. Doppia copia.** Gli oggetti raggiungibili da una pagina sono *già* stati copiati da
`copyPages` con nuovi numeri. Copiare a fondo `/AcroForm` sopra ci costruisce un secondo
insieme parallelo di campi: la pagina mostra il widget A, il form punta al widget B, i campi
si vedono e non si compilano. Stessa trappola per gli OCG. `buildCorrespondence()` cammina
in parallelo sul grafo sorgente e su quello destinazione e registra quale ref è diventato
quale; ogni copia successiva consulta prima quella mappa.

**2. Pagine non selezionate nell'output.** `copyPages` passa al proprio copier la pagina già
dereferenziata, quindi il ref della pagina non entra mai nella cache. Da lì il copier cammina
sul `/Parent` di un widget, attraversa l'albero dei campi, entra nel `/P` di un widget
fratello e copia le pagine su cui vivono *quelli*. Misurato: estraendo le pagine 1–2 di un
modulo di sei pagine, l'output conteneva una copia completa della pagina 3, content stream
incluso — invisibile in ogni viewer, recuperabile da qualsiasi parser.

**3. Nomi dei layer delle pagine escluse.** Stessa famiglia, percorso diverso:
`/OCProperties` continuava a elencare i layer di tutto il documento. Nessun contenuto di
pagina usciva, ma i *nomi* sì, e un layer chiamato "Bozza prezzi" racconta di materiale che
il destinatario non ha ricevuto.

La regola che chiude tutte e tre: **l'unica autorità su "questa pagina è stata tenuta?" è
l'insieme delle pagine selezionate.** La mappa di corrispondenza risponde a "pdf-lib ha
toccato questo oggetto", che è un'altra domanda. In più, prima del salvataggio gira un
mark-and-sweep dal trailer (`garbageCollect()`): pdf-lib scrive ogni oggetto del contesto,
raggiungibile o no, quindi qualunque cosa il copier abbia tirato dentro per sbaglio va
rimossa esplicitamente. **È un controllo di riservatezza, non un'ottimizzazione.**

### Segnalazioni pre-flight

Prima di produrre qualsiasi output, l'utente viene avvisato. `report.blocked` ferma
l'operazione, `report.confirm` richiede una conferma esplicita.

| Caso | Esito |
|---|---|
| Cifrato | Rifiutato al caricamento, con spiegazione |
| Form XFA dinamico | Bloccato — qualsiasi modifica strutturale lo invalida |
| Firma digitale | Bloccato — la firma copre i byte del file, ogni modifica la invalida |
| **JavaScript eseguibile** | **Conferma richiesta** — cercato in `/Names /JavaScript`, in un `/OpenAction` con `/S /JavaScript` e nelle additional actions `/AA` di documento e pagina |
| PDF taggato | Avviso: la marcatura di accessibilità andrà persa |

Il JavaScript non viene mai trasportato nell'output: è codice scritto contro la struttura
originale, e trapiantarlo in un documento riordinato è il default sbagliato. Ma su un sito
di sicurezza vale la pena **dirlo**, non solo gestirlo: un PDF che esegue codice all'apertura
è un veicolo comune di documenti malevoli, anche se molti moduli legittimi lo usano.

### Dipendenze vendorizzate

| Libreria | Versione | Ruolo |
|---|---|---|
| pdf-lib | 1.17.1 (MIT) | Manipolazione: legge e scrive ogni file prodotto |
| pdfjs-dist | 6.3.289 legacy ESM (Apache-2.0) | Solo rendering delle anteprime; non partecipa mai alla scrittura |

Stanno in `static/vendor/`, servite da `@vercel/static`: **non entrano nel bundle della
lambda Python**, quindi non pesano sul cold start. Il self-hosting tiene la CSP a
`script-src 'self'` senza allargamenti e impedisce a una terza parte di sapere che un utente
ha aperto un PDF.

Il worker di pdf.js è puntato a un URL **same-origin**. Serve: pdf.js ricade su un worker da
`blob:` solo quando `workerSrc` è cross-origin (`PDFWorker#initialize` controlla
`_isSameOrigin` prima), quindi same-origin significa che quel ramo non viene mai preso e
`default-src 'self'` basta.

**Verificare:**

```bash
python3 tools/verify_vendor.py                   # SHA-256 di ogni file vs VENDOR.json
python3 tools/verify_vendor.py --check-registry  # + segnala versioni upstream più recenti
```

**Aggiornare** (il vendoring toglie gli aggiornamenti automatici a librerie che parsano file
non fidati: la staleness qui è una questione di sicurezza, non di manutenzione):

1. Leggere il changelog upstream, in particolare le voci di sicurezza.
2. Scaricare il tarball dal registry npm e **verificare l'integrity sha512** dichiarato dal
   registry prima di estrarre.
3. Copiare i file elencati in `VENDOR.json` alla voce `source_in_tarball`.
4. Aggiornare in `VENDOR.json`: `version`, `pinned_on`, `tarball`, `tarball_integrity` e lo
   `sha256` di ogni file.
5. `python3 tools/verify_vendor.py` deve passare.
6. Rilanciare `tests/pdf/` e `tools/pdf_compare.py` sui fixture: un aggiornamento di pdf-lib
   può cambiare il comportamento del copier, che è esattamente dove stavano i tre difetti
   sopra.

### Classificazione dei documenti: TIPO A e TIPO B

**TIPO A** — la pagina disegna testo con un font che esiste nel documento: nome, categoria e
disponibilità dei glifi sono ispezionabili. **TIPO B** — la pagina è una scansione: non c'è un
font da leggere, solo un aspetto da stimare.

> **Il criterio non è "la pagina ha del testo".**
>
> Uno scansionato con OCR ne ha moltissimo. Misurato su un output Tesseract: **368 operazioni
> di testo per pagina**, un font incorporato vero, e un `/ToUnicode` che dichiara **55.506
> caratteri scrivibili**. Ciò che non ha è quel testo **visibile** — ogni operazione gira in
> render mode 3 — né un font con contorni: il programma è di 572 byte e non disegna nulla.
>
> Un controllo basato su "c'è testo?" o "il glifo è nel subset?" promuove quella pagina a
> TIPO A, scrive con il font glyphless e produce testo che l'utente non può vedere. Per
> questo la pagina viene classificata **prima**, da come è disegnata, e solo dopo si pone
> qualsiasi domanda sui font.

Segnali, in `static/js/pdf/pagetype.js`:

| Segnale | Soglia |
|---|---|
| Tutto il testo in modalità invisibile (`Tr` 3 o 7) | `visibleTextOps == 0 && textOps > 0` |
| Immagine singola che copre la pagina | copertura ≥ 0.85 via CTM |
| Programma di font troppo piccolo per contenere contorni | < 2048 byte |
| Nessun testo affatto sotto un'immagine a piena pagina | — |

TIPO B se (invisibile **e** coperta) oppure (nessun testo **e** coperta) oppure (font
glyphless **e** coperta). Il nome `GlyphLessFont` **non** viene usato come criterio: è la
convenzione di Tesseract, altri motori OCR ne usano altre.

### Classificazione dei font

> **`/FontDescriptor /Flags` non è utilizzabile come fonte primaria.** Misurato: ogni font
> incorporato prodotto da LibreOffice nel corpus riporta `Flags=4` (Symbolic) e nient'altro —
> incluso `LiberationSerif`, che è un serif, e `WenQuanYiZenHei`, che è CJK. Classificare per
> `/Flags` li chiama entrambi sans.

Cascata effettiva (`static/js/pdf/fonts.js`), **nome prima dei flag**:

1. **CJK** — `CIDSystemInfo /Ordering` in `{GB1, CNS1, Japan1, Korea1}`, oppure nome
   (`Ming, Song, Hei, Kai, Gothic, Mincho, Batang, WenQuanYi, SourceHan, Noto*CJK…`).
2. **Monospace** — bit `FixedPitch`, nome (`Mono, Courier, Consolas…`), oppure tutti i valori
   di `/Widths` uguali (segnale strutturale, indipendente dal nome).
3. **Serif** — nome (`Serif, Times, Georgia, Garamond, Palatino…`). Bit Serif solo come conferma.
4. **Sans** — default.

Sostituti: i **font standard PDF** (Times / Helvetica / Courier), che non richiedono
incorporamento e non aggiungono peso. **Il CJK non ha sostituto**: non esiste un font CJK
standard PDF e incorporarne uno costerebbe megabyte. Quando un glifo CJK manca l'operazione
**si blocca con un messaggio esplicito** invece di scrivere in uno script diverso.

### Disponibilità dei glifi

> **`/Widths` non dice quali *caratteri* può scrivere un subset.** I font sottoinsieme
> rimappano i codici su un intervallo denso `0..N` con encoding interno: `FirstChar=0
> LastChar=42` descrive 43 slot arbitrari, non un intervallo di caratteri.

Due meccanismi distinti, e confonderli è come si scrive un carattere che il font non contiene:

| Tipo di font | Oracolo |
|---|---|
| Subset incorporato | `/ToUnicode` **letto al contrario** (carattere → codice) |
| Standard 14 | tabella di encoding (WinAnsi + `/Differences`) |

Nessun parser di font, nessuna dipendenza aggiuntiva. Esempio reale: il subset DejaVuSans in
`01-word-export.pdf` può scrivere **41 caratteri** —
`,-.0123456789:;IPSabcdefghilmnopqrstuwxy`. Scrivere "Verifica" fallisce sulla `V`.

### Compilazione dei campi form

`static/js/pdf/fill.js`. Il valore va scritto **due volte**: in `/V`, che è ciò che legge un
programma, e in un appearance stream, che è ciò che vede una persona.

L'appearance viene costruito a mano perché le due scorciatoie sono entrambe sbagliate qui:
lasciar rigenerare pdf-lib significa lasciargli **scegliere il font** (ed è il comportamento
disattivato in `pdflib.js`); impostare `/NeedAppearances` passa la stessa scelta al viewer,
con una risposta diversa per ciascuno — e i browser spesso ignorano il flag mostrando un campo
vuoto sopra un valore che c'è davvero.

Il font viene dal `/DA` del campo, risolto contro il `/DR` del form: è questo il significato
di "il font già dichiarato per quella zona" per un campo di modulo. I campi non compilati non
vengono toccati: l'intero documento passa dal percorso di copia del blocco 1.

### Testo libero in overlay

`static/js/pdf/overlay.js` + `textruns.js`. Il testo nuovo va in un content stream
**aggiunto** all'array `/Contents`, mai dentro quello esistente: i byte che la pagina aveva
restano identici e l'aggiunta è un oggetto separato e ispezionabile. `pdf_compare.py` calcola
l'hash di **ogni stream separatamente** proprio per poterlo verificare.

**Trovare il font di una zona non è "il più vicino per distanza".** Le pagine reali impilano
ruoli tipografici a pochi punti l'uno dall'altro: il run più vicino a un click dentro un
blocco dati è spesso l'ultima parola del titolo sopra. Si preferisce un run sulla **stessa
riga di base** (stesso Ty entro 2.5 pt) a uno semplicemente più vicino; solo se non ce n'è si
ricade sul più vicino entro 72 pt, poi sul font dominante della pagina, poi sul default.

Due difetti emersi dal fixture `09` (titolo Times 10 pt sopra un blocco codici Courier):
i run erano registrati come **punti** invece che segmenti — un click oltre la fine di una
riga corta usciva dal raggio — e la dominanza di pagina contava per **nome di risorsa**,
che molti produttori rigenerano ad ogni chiamata di disegno.

**Stima della dimensione su TIPO B.** Si usa il `Tf` esplicito del layer OCR (per la scala
verticale di `Tm` e della CTM), non la spaziatura fra le righe di base. Misurato: i valori
`Tf` danno 11.0 pt contro gli 11.0 pt reali del documento da cui la scansione è stata fatta,
mentre i baseline gap danno 12.9 pt perché la spaziatura di paragrafo li gonfia. Il motore OCR
la conversione altezza→dimensione l'ha già fatta, e meglio.

> ⚠️ **Lo 0% di errore è un campione solo, ed è favorevole**: scansione a 150 DPI da un
> originale digitale pulito, senza inclinazione né artefatti. Da carta vera la stima sarà più
> larga. Resta marcata `ESTIMATED`, mai "rilevato".

Senza layer OCR: **default dichiarato di 11 pt sans**, con avviso che il documento non offre
alcun segnale. Nessuna stima dai pixel: un'ipotesi senza segnale dietro sarebbe una supposizione
travestita da misura.

> **Lo stato di testo va resettato esplicitamente, non ereditato.** `q`/`Q` salva e ripristina
> lo stato grafico, che **include** lo stato di testo. Misurato su un layer Tesseract: lo
> stream fa `BT 3 Tr … ET` fuori da ogni `q`/`Q`, lasciando la modalità di rendering
> invisibile in vigore. Il testo aggiunto sopra veniva scritto nel file e **non disegnava
> nulla** — esattamente il difetto contro cui questo tool mette in guardia. L'overlay ora
> azzera `Tr`, `Tz`, `Ts`, `Tc` e `Tw`: quello stesso stream lascia impostato anche `Tz`.

**UI di correzione.** Ogni posizionamento mostra da dove vengono dimensione e categoria
(`from the document` / `substitute font` / `ESTIMATED from the OCR layer` / `DEFAULT — no
signal` / `set by you`) e permette di cambiarle **prima** di scrivere. Un valore corretto
dall'utente viene registrato come `USER` con `reason=user-corrected`, non come una stima che
per caso era giusta — e non genera avviso, perché non è una supposizione del sistema. Le
coordinate del click passano da `viewport.convertToPdfPoint()` di pdf.js, che gestisce anche
la rotazione di pagina.

### Ritaglio della pagina

`static/js/pdf/crop.js`. Ritagliare un PDF si fa normalmente scrivendo un `/CropBox`, e qui
sarebbe la cosa sbagliata: sposta il bordo che il viewer disegna e lascia nel file ogni parola
e ogni immagine tolte, recuperabili da chiunque lo apra con qualcosa che non sia un viewer. Uno
strumento che su un sito di sicurezza scrive "ritagliato" mentre il contenuto è ancora lì è
peggio di nessuno strumento.

Quindi il ritaglio **cancella le operazioni di disegno**, e quando non può si rifiuta invece di
fingere. Le regole:

* Ciò di cui non si riesce a calcolare l'estensione **non è rimovibile**. Mai cancellare su una
  supposizione.
* Ciò che **attraversa** il bordo non è rimovibile qui: tagliare una Bézier o ricodificare metà
  immagine è un lavoro diverso e molto più grosso. La risposta onesta è nominare cosa
  resterebbe e fermarsi.
* Un percorso usato come **clip** non si cancella mai: toglierlo cambierebbe cosa si vede nella
  parte di pagina che l'utente ha chiesto di tenere.
* Il **testo invisibile si rimuove come quello visibile**. Un layer OCR è esattamente ciò che
  un ritaglio deve togliere, e nessun viewer mostrerà mai all'utente che è ancora lì.
* Una riga tagliata di lato si accorcia su un confine di carattere e viene riemessa con uno
  spostamento `TJ`, non con un `Td`: un `Td` sposterebbe tutto ciò che è posizionato
  relativamente a quella riga più avanti.

Senza accettazione esplicita l'operazione **si rifiuta**. Con l'accettazione, il report porta
una voce in evidenza che dice che l'output non è redatto.

> **Come si verifica.** `pdftotext` non serve: rispetta il `/CropBox`, quindi riporta come
> assente ciò che è soltanto nascosto — misura la visibilità, non la rimozione, che è proprio
> la distinzione per cui questo strumento esiste. `tests/pdf/crop.mjs` legge l'output con
> pypdf, che decodifica il content stream e ignora il riquadro di pagina. Su
> `03-scanned-ocr.pdf` le parole ricavabili passano da 368 a 190.

### Modifica del testo esistente

`static/js/pdf/replace.js`. **È l'unica operazione che riscrive un content stream.** Tutte le
altre lasciano stare i byte della pagina: le strutturali li copiano, l'overlay ne affianca uno
nuovo. Una sostituzione non può: l'operazione di disegno che mette quelle parole sulla pagina è
proprio ciò che cambia. `pdf_compare.py` lo riporta come stream modificato, ed è voluto.

> **Perché non coprire il testo vecchio.** La versione facile disegna un rettangolo del colore
> di sfondo sopra le parole vecchie e scrive le nuove sopra. Sembra giusto ed è una bugia: il
> testo originale resta nel content stream, recuperabile con copia-incolla o con qualsiasi
> parser. Su un sito di sicurezza spedire una redazione che non redige non è un'opzione. La
> stringa vecchia viene **rimossa dal file** — verificato con `pdftotext`, che sull'output non
> trova più il testo sostituito.

**Cosa non fa: il reflow.** La sostituzione è disegnata dalla stessa origine con lo stesso
font, quindi una stringa più lunga prosegue oltre dove finiva l'originale e una più corta
lascia un vuoto. Niente di ciò che segue si sposta. Quando la larghezza cambia oltre il 15% il
piano lo dice **prima** di scrivere. Era l'esclusione posta all'inizio del progetto, e la
ragione è quella: farlo davvero significa rimandare a capo i paragrafi, il che richiede le
metriche e le regole di impaginazione del produttore originale.

**Un sostituto non è ammesso qui.** Per il testo *nuovo* un font sostitutivo è un compromesso
visibile e onesto. Per una *sostituzione* è un difetto: mezza riga di corpo in una faccia
diversa non combacerebbe con le parole a destra e a sinistra sulla stessa riga. Se il font del
documento non ha i glifi, l'operazione si **blocca** e dice quali caratteri mancano.

**Il kerning si perde.** Misurato: `01-word-export.pdf` usa `TJ` con aggiustamenti di
spaziatura su **23 array su 23** — è il caso normale in un export da word processor, non
un'eccezione. Quegli aggiustamenti sono calcolati per quelle coppie di lettere e non si
trasferiscono su parole diverse: il testo sostituito viene impostato con la spaziatura normale
del font, cosa visibile da vicino su una riga giustificata. Riportato nel piano.

Per **leggere** il testo esistente serve la `/ToUnicode` letta in avanti: i codici di un font
sottoinsieme sono numeri di slot arbitrari, e senza quella mappa il testo già sulla pagina si
legge come caratteri di controllo.

### Verifica: `tools/pdf_compare.py`

Dipende da **pypdf**, dipendenza **solo di sviluppo** (`pyproject.toml`, mai
`requirements.txt`): nulla lato server tocca i PDF. pypdf è deliberatamente
un'implementazione *indipendente* — verificare l'output di pdf-lib con pdf-lib
condividerebbe i suoi punti ciechi e farebbe passare un file rotto.

Riporta: numero pagine, dimensioni di ogni pagina in punti, font incorporati con nome,
sottotipo e flag di subset, numero annotazioni, numero e nomi dei campi form, metadati. Più
i due hash che colgono ciò che i nomi non colgono:

- **SHA-256 del content stream di ogni pagina** — byte grezzi, ancora codificati. Decodificare
  maschererebbe una ricompressione.
- **SHA-256 di ogni programma di font incorporato** (`/FontFile`, `/FontFile2`, `/FontFile3`).
  Nome e flag di subset possono restare identici mentre i byte cambiano.

**Criterio d'uscita del blocco 1: questi hash devono coincidere tra input e output.** Se
differiscono, l'operazione è sbagliata anche se il PDF si apre e sembra a posto.

```bash
python3 tools/pdf_compare.py FILE                        # descrivi
python3 tools/pdf_compare.py IN OUT --pages 3,1,0        # confronta con mappatura pagine
node tests/pdf/run_fixtures.mjs                          # gira le 4 operazioni sui fixture
python3 tools/pdf_compare.py --manifest tests/fixtures/pdf/out/manifest.json
```

Il confronto dei font usa gli **insiemi** di hash distinti, non le liste: un documento può
legittimamente incorporare lo stesso programma più volte (una copia per pagina è comune nei
file assemblati pagina per pagina), e unire due documenti che portano lo stesso font dà due
copie. Cambia il conteggio, non i byte. Un programma i cui **byte** cambiano, o che sparisce,
fallisce comunque.

I metadati sono confrontati in **entrambe le direzioni**: un metadato *aggiunto*
dall'operazione conta quanto uno perso. Un tool che si scrive il proprio Title o Producer
sopra quello del documento ne sta riscrivendo l'identità.

### Fixture PDF per i test

Cinque documenti in `tests/fixtures/pdf/` (in `.gitignore` — **non committarli**, e non usare
documenti di lavoro reali). Ricette per ricrearli da zero:

| # | File | Cosa mette alla prova |
|---|---|---|
| 1 | `01-word-export.pdf` | Font sottoinsieme reali, gerarchia di titoli, PDF taggato — **vedi avvertenza sotto** |
| 2 | `02-fillable-form.pdf` | AcroForm con widget su pagine non contigue, outline |
| 3 | `03-scanned-ocr.pdf` | Immagine a piena pagina + strato di testo OCR invisibile |
| 4 | `04-accented-cjk.pdf` | Accentate europee e CJK, subset multi-byte |
| 5 | `05-password-protected.pdf` | Deve essere **rifiutato**, non elaborato |

**1 — Export da word processor.** In Word: un documento di 3+ pagine con titoli, grassetto,
corsivo e una tabella → *Salva come* / *Esporta* in PDF. Senza Word, con LibreOffice:

```bash
soffice --headless --convert-to pdf --outdir tests/fixtures/pdf documento.docx
```

Serve `libreoffice-writer` installato (`libreoffice-core` da solo non ha i filtri documento).

> ### ⚠️ Copertura mancante: l'export di Word non è mai stato provato
>
> Il fixture `01-word-export.pdf` con cui il blocco 1 è stato verificato è stato prodotto
> con **LibreOffice**, non con Microsoft Word: nell'ambiente di sviluppo Word non era
> disponibile. Le due cose non sono intercambiabili, e le differenze cadono esattamente
> dove il blocco 1 fa le sue affermazioni:
>
> - **Mapping dei font.** Word incorpora sottoinsiemi TrueType/CFF con convenzioni di
>   naming, encoding e prefissi di subset proprie, e usa i font CID diversamente da
>   LibreOffice. È il terreno del blocco 2 (riuso del font incorporato), ma tocca anche
>   il blocco 1: `pdf_compare.py` confronta nomi dei font e flag di subset.
> - **Metadati.** Word scrive un pacchetto XMP e un `/Info` con campi propri (incluse
>   proprietà personalizzate del documento) che LibreOffice non produce.
> - **Marcatura.** Le due suite generano `/StructTreeRoot` in modi diversi, e la perdita
>   dell'albero di struttura è già un limite dichiarato.
>
> **Nulla di specifico di Word è quindi coperto dai test attuali.** Chi riprende il
> progetto e ha accesso a Word dovrebbe rigenerare il fixture 1 con un export vero e
> rilanciare `node tests/pdf/run_fixtures.mjs` più `tools/pdf_compare.py --manifest`.
> Non è un problema noto: è una zona non esplorata.

**2 — Modulo compilabile.** Un modulo pubblico scaricabile (per esempio dal sito
dell'Agenzia delle Entrate) va benissimo ed è più realistico. Per generarne uno equivalente
in locale, con `reportlab`, i campi vanno messi su pagine **non contigue** — è la
disposizione che ha fatto emergere il difetto (2):

```python
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
c = canvas.Canvas("02-fillable-form.pdf", pagesize=A4); W, H = A4
c.bookmarkPage("p0"); c.addOutlineEntry("Applicant details", "p0", level=0)
c.acroForm.textfield(name="applicant.name", x=160, y=H-125, width=260, height=18,
                     borderColor=(0,0,0), forceBorder=True)
c.showPage()
c.bookmarkPage("p1"); c.addOutlineEntry("Guidance notes", "p1", level=0)
c.showPage()                      # pagina senza campi, di proposito
c.bookmarkPage("p2"); c.addOutlineEntry("Declaration", "p2", level=0)
c.acroForm.textfield(name="declaration.date", x=160, y=H-125, width=160, height=18,
                     borderColor=(0,0,0), forceBorder=True)
c.showPage(); c.save()
```

**3 — Scansione con OCR.** L'ideale è una pagina stampata e riacquisita con uno scanner con
OCR attivo. Equivalente riproducibile, che produce la stessa struttura (immagine + testo
invisibile):

```bash
pdftoppm -r 150 -gray -png 01-word-export.pdf scan     # poppler-utils
for f in scan-*.png; do tesseract "$f" "ocr-${f%.png}" -l eng pdf; done
# poi concatenare gli ocr-scan-*.pdf in un unico file (pypdf PdfWriter)
```

**4 — Accentate e CJK.** Un documento con italiano/francese/tedesco/spagnolo accentati e
paragrafi in cinese semplificato, tradizionale, giapponese e coreano, esportato come al
punto 1. Ai paragrafi CJK va assegnato un font che li copra (per esempio *WenQuanYi Zen Hei*
o un Noto CJK), altrimenti l'export li scrive come caselle vuote e il fixture non prova
nulla.

**5 — Protetto da password.** Creato apposta, mai un documento reale protetto:

```python
from pypdf import PdfReader, PdfWriter
w = PdfWriter()
for p in PdfReader("01-word-export.pdf").pages: w.add_page(p)
w.encrypt(user_password="fixture-user", owner_password="fixture-owner",
          algorithm="AES-256")
with open("05-password-protected.pdf", "wb") as f: w.write(f)
```

Questo fixture ha già colto un difetto: `instanceof EncryptedPDFError` **non funziona** con il
bundle UMD minificato di pdf-lib (la catena di prototipi si perde, arriva un `Error` con
`.name === 'Error'`), quindi ogni PDF protetto veniva riportato all'utente come *file
corrotto*. Il rilevamento ora incrocia più segnali — vedi `isEncryptedError()`.

## Deploy (Vercel)

`vercel.json` usa due builder:
- `@vercel/python` su `main.py` — gestisce tutte le route Flask
- `@vercel/static` su `static/**` — serve CSS/JS/immagini

**Importante:** senza il builder `@vercel/static`, i file statici non vengono inclusi nel bundle e la pagina appare non stilizzata.

### Cold start

Il primo accesso dopo un periodo di inattività paga l'avvio della serverless function. I fattori, in ordine di impatto:

1. **Dimensione del bundle** — `@vercel/python` installa da `requirements.txt` (priorità su `pyproject.toml`). Il file è volutamente minimale: solo le librerie importate a runtime. Le dipendenze pesanti di `pyproject.toml` (matplotlib, seaborn→pandas+numpy, reportlab, celery, twilio, trafilatura…) servono solo a moduli non usati (`premium_features.py`, `pdf_generator.py`) e **non vanno aggiunte** a `requirements.txt`. Il refactor micro-scan e l'hardening SSRF **non hanno aggiunto nessuna dipendenza** — `NullPool` viene da `sqlalchemy`, già presente.
2. **Init DB a import time** — `app.py` esegue `db.create_all()` ad ogni cold start **a meno che** `DB_AUTO_INIT=0`. Le migrazioni di colonna (`_run_column_migrations()`, ALTER idempotenti) invece **girano sempre**, indipendentemente da `DB_AUTO_INIT` — solo `create_all()` viene skippato. Questo per evitare che uno schema nuovo (es. le colonne micro-scan aggiunte in questo refactor) dia `500` per sempre su un DB esistente finché non si migra a mano: al primo deploy dopo un cambio di schema, la prima richiesta che tocca il DB si "auto-ripara".
3. **Resume del database** — Neon/Supabase free tier sospendono il DB inattivo; la prima query paga la ripresa (~0.5–3 s). Indipendente dall'app.
4. Le librerie Google in `gmail_manager.py` sono già lazy-importate (dentro le funzioni), quindi non pesano sull'import dell'app.

### Connection pooling (NullPool)

`SQLALCHEMY_ENGINE_OPTIONS` usa `poolclass=NullPool` (sia per Postgres che SQLite): ogni
richiesta apre e chiude la propria connessione invece di mantenere un pool per-processo.
Motivo: con l'architettura micro-scan, un utente genera più richieste concorrenti (`init` +
5 worker paralleli + polling), e su Vercel ogni richiesta concorrente **può** finire su
un'istanza Lambda diversa — un `QueuePool` classico (con `pool_size`/`max_overflow`) apre un
pool per istanza e può saturare rapidamente il limite di connessioni di Postgres
("`FATAL: too many connections`"). `NullPool` evita che le connessioni si accumulino tra
istanze effimere. **Per reggere il carico in produzione, `DATABASE_URL` dovrebbe puntare a
un connection pooler esterno** (Neon pooled endpoint con `-pooler` nell'host, o Supabase
transaction pooler sulla porta 6543) — senza pooler esterno, `NullPool` apre/chiude una
connessione reale a ogni richiesta, il che è corretto per evitare l'esaurimento ma paga un
piccolo costo di round-trip aggiuntivo per connessione.

### Rate limiting

Il limiter in-memory (`app.py`, decoratore `rate_limit`) è **thread-safe** (lock su un
singolo dizionario di bucket condiviso) e fa periodicamente pulizia dei bucket scaduti per
non accumulare memoria indefinitamente. `_client_ip()` preferisce l'header `X-Real-IP`
(impostato dall'edge, non falsificabile dal client come `X-Forwarded-For`), poi il primo hop
di `X-Forwarded-For`, poi `request.remote_addr` corretto da `ProxyFix(x_for=1, ...)` — così i
limiti vengono applicati all'IP reale del visitatore e non all'IP del proxy/edge Vercel.
Resta comunque un limite **per-istanza** (non condiviso tra Lambda diverse): un limite
realmente globale richiederebbe uno store condiviso (Redis).

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
| `TOKEN_ENCRYPTION_KEY` | Chiave Fernet per cifrare i token Gmail at-rest (fallback: derivata da `SESSION_SECRET`) |
| `VIRUSTOTAL_API_KEY` | Abilita VirusTotal come sorgente Threat Intel (opzionale) |
| `ABUSEIPDB_API_KEY` | Abilita AbuseIPDB come sorgente Threat Intel per gli IP (opzionale) |
| `DB_AUTO_INIT` | `0` per saltare `create_all` + migrazioni al cold start (default: attivo) |

## Aree di miglioramento

### PDF Tools
- **L'export di Word non è coperto dai test.** Il fixture 1 è un export LibreOffice
  (Word non era disponibile in ambiente di sviluppo). Font mapping, XMP/`/Info` e
  marcatura di Word differiscono e non sono mai stati esercitati — vedi l'avvertenza in
  "Fixture PDF per i test". Da rifare con un export Word autentico.
- **Overlay di testo libero (blocco 2, passo 3) non iniziato.** La compilazione dei campi
  form esistenti è fatta; resta il testo libero in un punto qualsiasi della pagina, sia su
  TIPO A che su TIPO B. Per il TIPO B servirà la stima visiva (dimensione approssimativa,
  serif o sans) con l'avviso obbligatorio che è una **stima**, non un font recuperato.
- **Nessun font CJK vendorizzato.** Decisione presa: quando un glifo CJK manca dal subset
  l'operazione si blocca. Rivedibile se emerge un caso d'uso reale.


### SEO Crawler
- **Feature rimossa**: il crawler multi-pagina (`/seo/crawl*`, `BackgroundJobManager`) è stato
  eliminato perché incompatibile con le istanze serverless effimere di Vercel (vedi
  "Architettura Micro-Scan Asincrona"). Un ripristino richiederebbe un job store esterno
  (coda + DB, non thread in-memory) — es. lo stesso pattern `public_id` + colonne di stato
  usato per lo scan di sicurezza, esteso con progress incrementale per pagina.
- **Siti JS-rendered (SPA/Wix/Squarespace)**: senza headless browser i link generati lato client non sono scopribili — resta valido anche per l'analisi SEO a singola pagina.
- **Bot protection**: alcuni siti (Cloudflare, WAF custom) bloccano IP datacenter anche con User-Agent da browser. Non correggibile lato codice.

### Micro-Scan asincrono
- **Worker `ports` su Vercel**: il check delle porte apre socket TCP grezzi verso porte
  non-HTTP (3306, 6379, …); l'egress non-HTTP può essere bloccato in ambienti serverless.
  Il worker non crasha (try/except per porta), ma potrebbe risultare sempre "nessuna porta
  aperta" in produzione — da verificare con un test live e, se confermato, documentarlo
  nella UI del risultato invece di lasciarlo silenzioso.
- **Rate limiting condiviso tra istanze**: il limiter resta per-processo/istanza (vedi sopra);
  uno store condiviso (Redis) darebbe un limite realmente globale, utile ora che un singolo
  scan genera ~10-15 richieste in un minuto.
- **Timeout worker → scan bloccato**: se un worker non risponde mai (crash silenzioso, rete),
  la colonna resta `NULL` per sempre e lo stato non passa mai a `COMPLETED`. Un timeout lato
  poll (es. dopo N minuti considerare il modulo "failed" anche senza risposta) chiuderebbe
  questo caso limite.

### Caching
- **`cache_manager.py` (`ScanCache`) è codice morto** — non è importato da nessuna route.
  `/api/scan/init` crea sempre una riga `ScanResult` nuova e rilancia tutti e 5 i worker
  anche se lo stesso target è stato scansionato pochi minuti prima. Wiring proposto: prima
  di creare la riga, cercare uno scan `COMPLETED` recente (stessa logica già presente in
  `ScanCache.get_cached_result`, finestra configurabile via `cache_duration_hours`) per lo
  stesso `target` + `user_id`/guest, e riusare quello invece di rieseguire gli scan di rete
  (handshake TLS, probe porte, PageSpeed, threat intel — tutte chiamate costose). Da
  decidere: se esporre comunque un modo per forzare un rescan (bypass cache) dalla UI.
  In alternativa, se il riuso dei risultati non è desiderato, rimuovere il modulo morto.
- **`/guides` e `/guides/<slug>` non hanno `Cache-Control`** — sono contenuto Python statico
  (`guides_content.py`, cambia solo al deploy), esattamente come `/sitemap.xml`, `/robots.txt`
  e `/ads.txt` che invece impostano già `public, max-age=86400`. Aggiungere lo stesso header
  alle route guide è un fix a basso rischio, stesso pattern già in uso nel codebase.

### Password Generator
- **Wordlist passphrase**: il pool di parole per la modalità Passphrase è una lista compatta
  hardcoded (non la EFF Long List completa a 7776 parole). Sostituirla con la lista completa
  aumenterebbe l'entropia per parola e la resistenza a dizionari di attacco specifici.
- **Modalità "Verifica password" (check di una password esistente, non generazione)**:
  riuserebbe l'entropia in bit / crack time già calcolati per il generatore, con una
  visualizzazione a 4 stadi (graffetta → lucchetto → chiavistello → caveau) invece della
  barra piatta attuale. Vincoli del progetto da rispettare: niente GSAP o altre dipendenze
  nuove (`CONTRIBUTING.md` — no build step, no bundler); l'equivalente nativo è
  `Element.animate()` (Web Animations API) o uno scrubber su `stroke-dashoffset` di un SVG,
  entrambi in grado di andare avanti *e indietro* nella timeline (utile per il caso "utente
  cancella un carattere → l'animazione si smonta", non solo si resetta). La password non
  deve mai lasciare il browser — stesso principio già seguito dal generatore esistente.
  Punto aperto: se integrarla come tab nella pagina esistente (`/tools/password`) o come
  pagina separata.

### UI — pattern "valore + range atteso"
Diversi check hanno già il dato ma sepolto nel testo dell'accordion: `ssl.days_until_expiry`,
`hsts_quality.max_age`, `dkim.selectors_found[].key_bits`, `spf.lookup_count`,
`dmarc.pct`. Ridisegnare quei check specifici in `scan_result.html`/`email.html` con un
valore grande, il range atteso in piccolo sopra, e un bordo/icona di warning quando il
valore è fuori range renderebbe leggibile a colpo d'occhio ciò che oggi richiede di aprire
l'accordion e leggere la frase. Da scoping su 3-4 check inizialmente, non su tutti — un
redesign totale delle ~20 card è un progetto a parte, non un miglioramento incrementale.

### Idee valutate e scartate
- **Filtri a chip + contatore risultati stile directory** (pattern "SHOWING N OF M"): unico
  candidato nel progetto sarebbero le 10 guide in `/guides`, categorizzate. Scartato: quel
  pattern (ricerca client-side, chip per categoria, contatore) rende con 50-200 elementi,
  non con 10 — costruirlo oggi sarebbe over-engineering rispetto al beneficio.
- **Receipt/scontrino animato** per un riepilogo scan condivisibile/stampabile: fattibile
  tecnicamente (clip-path che scende dall'alto, bordo a zigzag via SVG mask, rispetto di
  `prefers-reduced-motion`), ma è uno stile skeuomorfico-giocoso in contrasto con il design
  minimale teal esistente (nessun altro elemento del sito ha quel linguaggio visivo). Non è
  un problema tecnico ma una decisione di tono prodotto — da validare prima di implementare.

### Visual Enhancements
- **Pagine app interne** (dashboard, account, API keys): `.page-header` è troppo compatto per lo shader; una sottile barra gradiente CSS (`border-bottom` o pseudo-elemento `::after` con `conic-gradient`) darebbe coerenza visiva senza usare WebGL.
- **Spotlight + reveal sulle premium feature card** (`.premium-feature-card`): la classe è diversa da `.feature-card`, quindi gli effetti 21st.dev non si applicano lì. Estensione banale in `enhancements.js`.
- **Verifica browser**: lo shader e il glassmorphism non sono stati testati visivamente nel container di sviluppo (network policy blocca il download di Chromium headless). Consigliato un test manuale su Safari (supporto backdrop-filter variabile) e Firefox (WebGL path diverso).

### Sicurezza
- **CSP `'unsafe-inline'`**: `script-src`/`style-src` includono ancora `'unsafe-inline'` per
  gli script inline esistenti (consenso cookie, hook di `enhancements.js`). Eliminarlo
  richiederebbe spostare quegli script in file esterni e/o adottare nonce/hash per-richiesta.
- **CSP e Lucide da CDN**: `script-src` include `https://unpkg.com` per caricare Lucide.
  Self-hostare la libreria in `static/js/` permetterebbe una CSP `script-src 'self'` totale.

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
