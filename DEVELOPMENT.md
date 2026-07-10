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
```

> `premium_features.py`, `pdf_generator.py` e `user_guide_system.py` sono presenti nel repo
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

Base URL: `/api/scan/` (blueprint `api_scan.py`, non richiede API key — autenticato via
sessione/cookie CSRF-exempt come tutto il namespace `/api/`). Usata dal frontend per il
flusso descritto in "Architettura Micro-Scan Asincrona" qui sopra:

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

### Password Generator
- **Wordlist passphrase**: il pool di parole per la modalità Passphrase è una lista compatta
  hardcoded (non la EFF Long List completa a 7776 parole). Sostituirla con la lista completa
  aumenterebbe l'entropia per parola e la resistenza a dizionari di attacco specifici.

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
