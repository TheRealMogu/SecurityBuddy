# Changelog

Tutte le modifiche rilevanti al progetto sono documentate qui.
Il formato segue [Keep a Changelog](https://keepachangelog.com/it/1.0.0/).

---

## [Non rilasciato]

### Aggiunto
- **Gmail Newsletter Manager** (`/newsletter-manager`) — connessione Gmail via OAuth Google
  per elencare le newsletter attive e disiscriversi
  - `gmail_manager.py`: flusso OAuth (`google-auth-oauthlib`) + Gmail API
    (`google-api-python-client`), scope minimo `gmail.readonly`
  - Privacy by design: legge **solo** gli header dei messaggi
    (`From`, `Date`, `List-Unsubscribe`, `List-Unsubscribe-Post`), mai il corpo
  - Unsubscribe one-click RFC 8058 lato server (con guard anti-SSRF) o apertura URL/`mailto`
  - Endpoint `/gmail/auth`, `/gmail/callback`, `/gmail/newsletters`, `/gmail/unsubscribe`,
    `/gmail/disconnect` (autenticati via sessione, protetti da CSRF)
  - Modello `GmailCredential` (token OAuth nel DB, una riga per utente, cascade su delete)
  - Variabili d'ambiente `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`
  - Template `newsletter_manager.html` con skeleton di caricamento, empty state,
    ordinamento per data/mittente e feedback inline

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
