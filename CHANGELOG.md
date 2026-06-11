# Changelog

Tutte le modifiche rilevanti al progetto sono documentate qui.
Il formato segue [Keep a Changelog](https://keepachangelog.com/it/1.0.0/).

---

## [Non rilasciato]

### Aggiunto
- **Visual enhancements — lazy-loaded, zero impatto sul critical path** (`static/js/enhancements.js`)
  - **Gradiente shader animato** nella hero section e in ogni banner di pagina (`.hero-section`, `.premium-hero`) — WebGL self-hosted con simplex noise (equivalente a ShaderGradient, zero dipendenze, ~5 KB); colors letti dalle CSS variables e aggiornati al toggle light/dark; pausa automatica quando la sezione esce dal viewport o il tab è nascosto; DPR capped a 1.5; fallback CSS statico sempre presente
  - **Glassmorphism** su scan card e trust badge — `backdrop-filter: blur + saturate`, semitrasparenza che legge il gradiente sottostante; entrambi i temi light/dark
  - **Cursor spotlight** sulle feature card — glow radiale che segue il puntatore, solo su dispositivi pointer:fine
  - **Scroll reveal** scaglionato sulle feature card — IntersectionObserver, staggered delay, mai applicato a card già visibili al caricamento
  - Tutto attivato su `window.load` + `requestIdleCallback`; bail-out automatico per `prefers-reduced-motion`, Save-Data, WebGL assente, shader compile failure, context loss
- **Password generator — "Exclude look-alikes"** — nuovo toggle che rimuove dal pool i caratteri visivamente ambigui (`0 O o`, `1 l I i`, `|`); entropia, charset size e crack time si ricalcolano sul pool ridotto
- **Password generator — preferenze persistenti** — lunghezza e toggle salvati in `localStorage` (`sb_pw_prefs`) e ripristinati alla visita successiva; vengono salvate **solo le impostazioni**, mai le password generate

### Modificato
- **Password generator — nuovi default**: 12 caratteri (era 16), simboli disattivi, look-alikes esclusi — pensato per password da digitare/trascrivere senza errori
- **Password generator — layout compatto**: hero ridotta e griglia a due colonne su desktop (password + statistiche a sinistra, opzioni a destra), tutto raggiungibile senza scroll; su mobile resta a colonna singola

### Corretto
- **Cold start Vercel molto lento al primo accesso** — due cause rimosse:
  - il bundle della serverless function installava ~29 pacchetti di cui solo ~13 usati a
    runtime (matplotlib, seaborn→pandas+numpy, reportlab, celery, redis, twilio, trafilatura,
    sendgrid… servivano solo a moduli morti). Nuovo `requirements.txt` minimale che
    `@vercel/python` usa con priorità; rimosso `requirements_vercel.txt` (nome non
    riconosciuto da Vercel, era ignorato)
  - `db.create_all()` + migrazioni giravano ad ogni cold start: ora skippabili con
    `DB_AUTO_INIT=0` (da impostare dopo il primo deploy)
- **Password generator — slider lunghezza invisibile** — il range input aveva `-webkit-appearance:none` ma nessuno stile per track e thumb; aggiunto stile esplicito con fill primario dinamico (`--range-pct`) per WebKit e Firefox
- **Password generator — lunghezza non editabile** — sostituito lo `<span>` statico con un `<input type="number">` bidirezionalmente sincronizzato con lo slider; normalizzazione (clamp 8–64) su blur/enter
- **SEO crawler — sito bloccato sulla homepage** — `SiteCrawler._normalise` confrontava l'host con uguaglianza stretta; aggiunto `_canon_host()` che tratta `www.example.com` e `example.com` come lo stesso sito, così i siti con link interni che usano la forma opposta vengono crawlati correttamente (sottodomini reali restano esterni)

---

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
