# Changelog

Tutte le modifiche rilevanti al progetto sono documentate qui.
Il formato segue [Keep a Changelog](https://keepachangelog.com/it/1.0.0/).

---

## [Non rilasciato]

### Aggiunto
- **Architettura micro-scan asincrona (serverless-native)** — lo scan di sicurezza non gira
  più in un'unica richiesta sincrona monolitica: nuovo blueprint `/api/scan/*`
  (`api_scan.py`) con `POST /init` (valida il target, crea la riga `ScanResult`, ritorna un
  `public_id` non enumerabile), cinque route worker indipendenti (`ssl`, `headers`, `ports`,
  `seo`, `threat`) che leggono il target dal DB e scrivono ciascuna solo la propria colonna, e
  `GET /status/<public_id>` che aggrega i risultati e calcola il punteggio finale quando tutti
  i moduli sono completi. Il frontend (`templates/scan_progress.html`) lancia i 5 worker in
  parallelo e fa polling ogni 2.5s. Elimina il rischio di timeout a 60s di Vercel sui target
  lenti; `ScanResult` guadagna i campi `public_id`, `status` e le 5 colonne per-modulo
  (`models.py`). `SecurityScanner` espone `scan_group_ssl/headers/discovery` per eseguire un
  sottoinsieme coerente dei check esistenti (stesso punteggio finale di `scan_target()`).
- **Protezione SSRF e DNS rebinding su tutte le richieste HTTP in uscita** — nuovo
  `utils/secure_http.secure_request()`, usato da scanner, SEO analyzer, threat intel, webhook
  API e unsubscribe Gmail al posto di `requests`/`self.session` diretti. Risolve e valida
  l'host, **pinna** il socket sull'IP validato (chiude la finestra di DNS rebinding/TOCTOU tra
  validazione e connessione) mantenendo intatti hostname/SNI per la verifica del certificato,
  e gestisce i redirect manualmente (max 3 hop di default) ri-validando l'host ad ogni hop
  invece di seguirli ciecamente. Nuovo `validators.resolve_and_validate_host()`.
- **Content-Security-Policy** — nuovo header `Content-Security-Policy` nell'`after_request`
  esistente: self-first (`default-src 'self'`), allargato solo agli host effettivamente
  caricati dal sito (unpkg per Lucide, host Google Ad* per AdSense, Fontshare per i font),
  con `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'` come hardening
  aggiuntivo.
- **DKIM — selector personalizzato** — campo opzionale nel form `/email` per testare un
  selector custom insieme ai 18 comuni; il risultato mostra se il selector custom è stato
  trovato ed è evidenziato nella tabella.
- **Password generator — modalità Passphrase** — genera 4-6 parole casuali separate da
  trattino (equivalente semplificato della EFF Long List), alternativa al charset casuale.
- **Password generator — cronologia di sessione** — ultime 5 password generate mostrate in
  UI, salvate in `sessionStorage` (si azzera alla chiusura della tab, mai su disco), con
  pulsante "Clear history".
- **Password generator — warning entropia bassa** — avviso visivo quando "Exclude
  look-alikes" è attivo alla lunghezza minima (8 caratteri).
- **3 nuove guide di sicurezza** (`/guides`) — *SSRF and DNS Rebinding: The Definitive
  Guide*, *Email Security and Deliverability: SPF, DKIM and DMARC Explained*, e una
  riscrittura più ampia della guida *HTTP Security Headers* (CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy).
- **Bail-out shader su CPU low-end** — lo shader WebGL della hero section viene ora saltato
  quando `navigator.hardwareConcurrency <= 2`, mantenendo il fallback CSS statico.
- **Visual enhancements — lazy-loaded, zero impatto sul critical path** (`static/js/enhancements.js`)
  - **Gradiente shader animato** nella hero section e in ogni banner di pagina (`.hero-section`, `.premium-hero`) — WebGL self-hosted con simplex noise (equivalente a ShaderGradient, zero dipendenze, ~5 KB); colors letti dalle CSS variables e aggiornati al toggle light/dark; pausa automatica quando la sezione esce dal viewport o il tab è nascosto; DPR capped a 1.5; fallback CSS statico sempre presente
  - **Glassmorphism** su scan card e trust badge — `backdrop-filter: blur + saturate`, semitrasparenza che legge il gradiente sottostante; entrambi i temi light/dark
  - **Cursor spotlight** sulle feature card — glow radiale che segue il puntatore, solo su dispositivi pointer:fine
  - **Scroll reveal** scaglionato sulle feature card — IntersectionObserver, staggered delay, mai applicato a card già visibili al caricamento
  - Tutto attivato su `window.load` + `requestIdleCallback`; bail-out automatico per `prefers-reduced-motion`, Save-Data, WebGL assente, shader compile failure, context loss
- **Password generator — "Exclude look-alikes"** — nuovo toggle che rimuove dal pool i caratteri visivamente ambigui (`0 O o`, `1 l I i`, `|`); entropia, charset size e crack time si ricalcolano sul pool ridotto
- **Password generator — preferenze persistenti** — lunghezza e toggle salvati in `localStorage` (`sb_pw_prefs`) e ripristinati alla visita successiva; vengono salvate **solo le impostazioni**, mai le password generate

### Modificato
- **Connection pooling database** — `SQLALCHEMY_ENGINE_OPTIONS` usa ora `poolclass=NullPool`
  (era `QueuePool` con `pool_size`/`max_overflow`): con l'architettura micro-scan un utente
  genera più richieste concorrenti che possono finire su istanze Lambda diverse, e un pool
  per-istanza rischiava di saturare il limite di connessioni Postgres. Richiede un
  `DATABASE_URL` puntato a un pooler esterno (Neon pooled endpoint / Supabase transaction
  pooler) per reggere il carico in produzione.
- **Rate limiter reso thread-safe** — accesso ai bucket protetto da lock, con pulizia
  periodica dei bucket scaduti per evitare un leak di memoria non limitato nel tempo.
  `_client_ip()` preferisce ora `X-Real-IP` (impostato dall'edge Vercel) rispetto al primo
  hop di `X-Forwarded-For`, per non applicare i limiti all'IP del proxy invece di quello del
  visitatore reale. Limiti per-route sulle nuove API `/api/scan/*`: `init` 5 req/min,
  worker 30 req/min, `status` (GET) esente.
- **Password generator — nuovi default**: 12 caratteri (era 16), simboli disattivi, look-alikes esclusi — pensato per password da digitare/trascrivere senza errori
- **Password generator — layout compatto**: hero ridotta e griglia a due colonne su desktop (password + statistiche a sinistra, opzioni a destra), tutto raggiungibile senza scroll; su mobile resta a colonna singola

### Rimosso
- **Crawler SEO multi-pagina** (`/seo/crawl*`, `BackgroundJobManager`, `background_jobs.py`)
  — il modello a thread in-memory non sopravvive alle istanze serverless effimere di
  Vercel: un job avviato in una Lambda viene congelato non appena la risposta HTTP parte, e
  il polling successivo può colpire un'altra istanza con stato vuoto. Resta attiva l'analisi
  SEO per singola pagina (`/seo`).

### Corretto
- **500 su `/api/scan/init` in produzione (colonne mancanti)** — la tabella `scan_result`
  esistente non aveva le nuove colonne micro-scan perché `db.create_all()` non altera
  tabelle esistenti e le migrazioni di colonna erano gated dietro `DB_AUTO_INIT`, disattivato
  in produzione: il primo INSERT falliva con "column does not exist", Flask rispondeva con
  `500.html` (HTML) e il frontend andava in errore su `response.json()` ("Unexpected token
  '<'"). Le migrazioni di colonna ora girano sempre, indipendentemente da `DB_AUTO_INIT` —
  uno schema nuovo si auto-ripara alla prima richiesta dopo il deploy. Aggiunto anche: gli
  errorhandler 404/500 ritornano JSON per i path `/api/*` invece di una pagina HTML, e i
  `fetch()` lato frontend (`index.html`, `scan_progress.html`) verificano `content-type` e
  fanno `JSON.parse` in try/catch prima di leggere i campi.
- **Cold start Vercel molto lento al primo accesso** — due cause rimosse:
  - il bundle della serverless function installava ~29 pacchetti di cui solo ~13 usati a
    runtime (matplotlib, seaborn→pandas+numpy, reportlab, celery, redis, twilio, trafilatura,
    sendgrid… servivano solo a moduli morti). Nuovo `requirements.txt` minimale che
    `@vercel/python` usa con priorità; rimosso `requirements_vercel.txt` (nome non
    riconosciuto da Vercel, era ignorato)
  - `db.create_all()` giravano ad ogni cold start: ora skippabile con
    `DB_AUTO_INIT=0` (da impostare dopo il primo deploy); le migrazioni di colonna restano
    sempre attive (vedi sopra)
- **Password generator — slider lunghezza invisibile** — il range input aveva `-webkit-appearance:none` ma nessuno stile per track e thumb; aggiunto stile esplicito con fill primario dinamico (`--range-pct`) per WebKit e Firefox
- **Password generator — lunghezza non editabile** — sostituito lo `<span>` statico con un `<input type="number">` bidirezionalmente sincronizzato con lo slider; normalizzazione (clamp 8–64) su blur/enter
- **SEO crawler — sito bloccato sulla homepage** — `SiteCrawler._normalise` confrontava l'host con uguaglianza stretta; aggiunto `_canon_host()` che tratta `www.example.com` e `example.com` come lo stesso sito, così i siti con link interni che usano la forma opposta vengono crawlati correttamente (sottodomini reali restano esterni)

---

## [2.1.0] — 2026-06-10

### Aggiunto
- **Gmail Newsletter Manager** (`/newsletter-manager`) — connessione Gmail via OAuth Google
  per elencare le newsletter attive e disiscriversi
  - **Dormiente di default**: senza `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` il link è
    nascosto e le route rispondono 404; si riattiva impostando le env (nessuna modifica al codice)
  - `gmail_manager.py`: flusso OAuth (`google-auth-oauthlib`) + Gmail API
    (`google-api-python-client`), scope minimo `gmail.readonly`
  - Privacy by design: legge **solo** gli header dei messaggi
    (`From`, `Date`, `List-Unsubscribe`, `List-Unsubscribe-Post`), mai il corpo
  - Unsubscribe one-click RFC 8058 lato server (con guard anti-SSRF) o apertura URL/`mailto`
  - Endpoint `/gmail/auth`, `/gmail/callback`, `/gmail/newsletters`, `/gmail/unsubscribe`,
    `/gmail/disconnect` (autenticati via sessione, protetti da CSRF)
  - Modello `GmailCredential` (token OAuth nel DB, una riga per utente, cascade su delete)
  - Token OAuth **cifrati at-rest** con Fernet (chiave da `TOKEN_ENCRYPTION_KEY` o derivata
    da `SESSION_SECRET`) — GDPR Art. 32
  - Variabili d'ambiente `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `TOKEN_ENCRYPTION_KEY`
  - Dipendenze: `google-api-python-client`, `google-auth`, `google-auth-oauthlib`,
    `google-auth-httplib2`, `cryptography`
  - Template `newsletter_manager.html` con skeleton di caricamento, empty state,
    ordinamento per data/mittente e feedback inline
- **Verifica Google AdSense** — meta tag `google-adsense-account` in `base.html` e route
  `/ads.txt` (nessuno script né cookie di terze parti, GDPR-neutro)
- **File `LICENSE`** (MIT)

### Modificato
- **Privacy policy** (`privacy.html`) aggiornata per il Newsletter Manager: trattamento Gmail,
  token e indirizzo salvati, Google come terza parte / trasferimento UE–USA, base giuridica
  (consenso, Art. 6(1)(a)), conservazione, revoca via disconnect e sezione dedicata con
  aderenza alla Google API Limited Use
- **Export dati** (`account_export`) include lo stato della connessione Gmail (indirizzo +
  data), mai i token — GDPR Art. 15

---

## [2.0.0] — 2026-05-18

### Aggiunto
- **Validazione risposta scanner** — logica anti-false-positive per i check di file sensibili e admin panel
  - `_get_404_baseline()`: fingerprint della risposta di errore del server prima dello scan
  - `_is_false_positive()`: confronto dimensione body (±50 byte) con la baseline
  - `_is_real_exposure()`: verifica che il body contenga pattern reali (es. `DB_PASSWORD`, `[core]`)
  - `SENSITIVE_PATHS`: dizionario con 10 path sensibili e relativi pattern attesi
  - `ADMIN_PATHS`: lista di 9 path admin comuni
- **Rilevamento SPA**: se il server risponde `200` a un path UUID casuale, il sito viene classificato come SPA e i check `sensitive_files` e `admin_panels` vengono saltati automaticamente con nota nel report
- **Check `_check_sensitive_files`**: scansione di `.env`, `wp-config.php`, `.git/config` e altri file sensibili con validazione a tre livelli
- **Check `_check_admin_panels`**: discovery di path admin comuni (`/admin`, `/wp-admin`, `/phpmyadmin`, ecc.)
- **Flag `spa_detected`** nel risultato top-level dello scan
- **CLI** (`cli.py`) con entry point `securitybuddy`
- **GitHub Action** (`.github/actions/security-buddy/`) per integrazione CI/CD
- **Pagina Premium** (`templates/premium.html`)
- **`.gitignore`**

### Modificato
- `_calculate_score()`: i check `sensitive_files` e `admin_panels` non penalizzano il punteggio quando saltati per SPA
- Design system completamente riscritto — nessuna dipendenza da Bootstrap, CSS variables custom (`--color-*`, `--font-*`, `--radius-*`), dark mode nativa
- Tutti i template aggiornati al nuovo design (Cabinet Grotesk + Satoshi)
- Rimossi Bootstrap e Feather Icons dai template (sostituiti con Lucide SVG inline)
- `vercel.json`: aggiunto builder `@vercel/static` per `static/**` — fix per CSS/JS non serviti in produzione
- `pdf_generator.py`: refactor layout report
- `routes.py`: aggiunta SVG badge, gestione flash messages

### Corretto
- File statici (CSS/JS) non venivano inclusi nel bundle Vercel — pagina appariva non stilizzata in produzione
- Pagina bianca al caricamento causata da risorse render-blocking
- Dipendenze mal ordinate in `pyproject.toml`
- 13 vulnerabilità di sicurezza (SSRF, rate limiting, validazione input)

---

## [1.0.0] — 2026-05-05

### Aggiunto
- Scanner di sicurezza base con 9 check: connettività, HTTPS, SSL, security headers, cookie, CORS, HTTP methods, technology disclosure, open ports
- Interfaccia web Flask con login, dashboard, risultati scan
- API REST `/api/v1/` con autenticazione via API key
- Sistema di notifiche email (SendGrid)
- Report PDF (ReportLab)
- Premium features: advanced scanner, analytics, monitoraggio schedulato
- Background jobs asincroni
- Deploy su Vercel (`vercel.json`)
