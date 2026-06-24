import json
import html
import os
import functools
import ipaddress
from datetime import datetime, timedelta
from hmac import compare_digest as _hmac_compare
from urllib.parse import urlparse
from flask import render_template, request, redirect, url_for, flash, session, make_response, jsonify, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db, rate_limit
from models import User, ScanResult, APIKey, MonitoringConfig, GmailCredential
from scanner import SecurityScanner
from seo_analyzer import SEOAnalyzer
from validators import AdvancedValidator, clean_target
from notification_system import NotificationSystem, make_unsubscribe_token
from email_analyzer import EmailAnalyzer
from threat_intel import ThreatIntelAnalyzer
from api_routes import api_bp
from background_jobs import job_manager
from guides_content import GUIDES, GUIDES_BY_SLUG, GUIDES_UPDATED
import gmail_manager

# Register API blueprint
app.register_blueprint(api_bp)

# Pre-computed dummy hash so login timing is constant whether or not the user exists
_DUMMY_PASSWORD_HASH = generate_password_hash('dummy-password-for-timing-equalization')


def _is_safe_next(target):
    """Allow only relative, same-site redirect targets (no //, no scheme/netloc)."""
    if not target:
        return False
    if target.startswith('//') or target.startswith('/\\') or '\\' in target:
        return False
    parsed = urlparse(target)
    return not parsed.scheme and not parsed.netloc and target.startswith('/')


def _remember_guest_scan(scan_id):
    """Track guest scan IDs in the session so only the creator can view them."""
    ids = session.get('guest_scans', [])
    ids.append(scan_id)
    session['guest_scans'] = ids[-50:]


@app.route('/')
def index():
    """Homepage with scan form"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
@rate_limit(max_calls=10, window_seconds=60)
def scan():
    """Process scan request"""
    target = request.form.get('target', '').strip()
    
    if not target:
        flash('Please enter a domain or IP address to scan.', 'warning')
        return redirect(url_for('index'))
    
    # Advanced validation
    validator = AdvancedValidator()
    target = clean_target(target)
    is_valid, error_msg = validator.validate_target(target)
    
    if not is_valid:
        flash(f'Invalid target: {error_msg}', 'error')
        return redirect(url_for('index'))
    
    try:
        # Perform security scan
        scanner = SecurityScanner()
        results = scanner.scan_target(target)
        
        # SEO analysis (domain targets only)
        if results.get('scan_type') == 'domain':
            try:
                seo = SEOAnalyzer()
                results['seo'] = seo.analyze(target)
            except Exception as seo_err:
                results['seo'] = {'error': str(seo_err)}

        # Save scan result to database
        scan_result = ScanResult(
            target=target,
            scan_type=results.get('scan_type', 'domain'),
            results=json.dumps(results),
            security_score=results.get('overall_score', 0),
            user_id=current_user.id if current_user.is_authenticated else None
        )
        db.session.add(scan_result)
        db.session.commit()

        if not current_user.is_authenticated:
            _remember_guest_scan(scan_result.id)

        return render_template('scan_result.html', results=results, scan_id=scan_result.id)

    except Exception as e:
        flash(f'Scan failed: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password.', 'warning')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()

        # Always run a password hash comparison to equalize timing and avoid
        # leaking whether a username exists.
        if user:
            password_ok = user.check_password(password)
        else:
            check_password_hash(_DUMMY_PASSWORD_HASH, password)
            password_ok = False

        if user and password_ok:
            login_user(user)
            next_page = request.args.get('next')
            if not _is_safe_next(next_page):
                next_page = None
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        agree_terms = request.form.get('agree_terms')
        age_confirm = request.form.get('age_confirm')

        if not all([username, email, password]):
            flash('Please fill in all fields.', 'warning')
            return render_template('login.html')

        if not agree_terms:
            flash('You must accept the Terms of Service and Privacy Policy to register.', 'error')
            return render_template('login.html')

        if not age_confirm:
            flash('You must confirm you are 16 or older to register.', 'error')
            return render_template('login.html')

        if len(password) < 12:
            flash('Password must be at least 12 characters long.', 'error')
            return render_template('login.html')

        existing = (
            User.query.filter_by(username=username).first()
            or User.query.filter_by(email=email).first()
        )
        if existing:
            flash('Registration failed — please check your details and try again.', 'error')
            return render_template('login.html')

        user = User(username=username, email=email, tos_accepted_at=datetime.utcnow())
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash('Registration successful! Welcome to Security Buddy.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with scan history"""
    # Get user's recent scans
    recent_scans = ScanResult.query.filter_by(user_id=current_user.id)\
                                  .order_by(ScanResult.created_at.desc())\
                                  .limit(10).all()
    
    return render_template('dashboard.html', recent_scans=recent_scans)

@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    """View specific scan result"""
    scan_result = ScanResult.query.get_or_404(scan_id)

    if scan_result.user_id:
        # Owned scan — only the owner may view it.
        if not current_user.is_authenticated or scan_result.user_id != current_user.id:
            flash('You do not have access to this scan result.', 'error')
            return redirect(url_for('index'))
    else:
        # Guest scan — only viewable by the session that created it.
        if scan_id not in session.get('guest_scans', []):
            flash('You do not have access to this scan result.', 'error')
            return redirect(url_for('index'))

    results = json.loads(scan_result.results)
    return render_template('scan_result.html', results=results, scan_id=scan_id)

@app.route('/api-keys')
@login_required
def api_keys():
    """Manage API keys"""
    user_api_keys = APIKey.query.filter_by(user_id=current_user.id, active=True).all()
    # Pop the newly-created key from the session for one-time display in the template
    new_key = session.pop('new_api_key', None)
    return render_template('api_keys.html', api_keys=user_api_keys, new_api_key=new_key)

@app.route('/create-api-key', methods=['POST'])
@login_required
def create_api_key():
    """Create new API key"""
    name = request.form.get('name', 'Default API Key')

    try:
        api_key = current_user.generate_api_key(name)
        # Store the plaintext key in the server-side session (one-time display).
        # It is NOT put in a flash message to avoid it appearing in server logs.
        session['new_api_key'] = api_key
        flash('API key created. Copy it now — it will not be shown again.', 'warning')

    except Exception as e:
        flash(f'Failed to create API key: {str(e)}', 'error')

    return redirect(url_for('api_keys'))

@app.route('/badge/<path:domain>/<int:score>.svg')
def badge_svg(domain, score):
    """Dynamic SVG security score badge for sharing."""
    score = max(0, min(100, score))

    # Sanitize the domain: keep only safe label characters, cap length, then
    # XML-escape before interpolating into the SVG markup.
    import re as _re
    domain = _re.sub(r'[^a-zA-Z0-9.\-]', '', domain)[:253]
    domain = html.escape(domain, quote=True)

    if score >= 80:
        color = '#1a7f4b'
        grade = 'A' if score >= 90 else 'B'
    elif score >= 60:
        color = '#92590e'
        grade = 'C'
    elif score >= 40:
        color = '#b91c1c'
        grade = 'D'
    else:
        color = '#991b1b'
        grade = 'F'

    label = 'security'
    value = f'{score}/100 · {grade}'
    label_w = 64
    value_w = 88
    total_w = label_w + value_w
    height = 20

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{height}" role="img" aria-label="{domain} security score: {score}">
  <title>{domain} security score: {score}/100 ({grade})</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0"  stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1"  stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_w}" height="{height}" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_w}" height="{height}" fill="#555"/>
    <rect x="{label_w}" width="{value_w}" height="{height}" fill="{color}"/>
    <rect width="{total_w}" height="{height}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">
    <text x="{label_w // 2 * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{(label_w - 10) * 10}" lengthAdjust="spacing">{label}</text>
    <text x="{label_w // 2 * 10}" y="140" transform="scale(.1)" textLength="{(label_w - 10) * 10}" lengthAdjust="spacing">{label}</text>
    <text x="{(label_w + value_w // 2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{(value_w - 10) * 10}" lengthAdjust="spacing">{value}</text>
    <text x="{(label_w + value_w // 2) * 10}" y="140" transform="scale(.1)" textLength="{(value_w - 10) * 10}" lengthAdjust="spacing">{value}</text>
  </g>
</svg>'''

    response = make_response(svg)
    response.headers['Content-Type'] = 'image/svg+xml'
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response


@app.route('/seo', methods=['GET', 'POST'])
@rate_limit(max_calls=10, window_seconds=60)
def seo_scan():
    """Dedicated SEO analysis page"""
    if request.method == 'GET':
        return render_template('seo.html')

    target = request.form.get('target', '').strip()
    if not target:
        flash('Please enter a domain to analyse.', 'warning')
        return redirect(url_for('seo_scan'))

    validator = AdvancedValidator()
    target = clean_target(target)
    is_valid, error_msg = validator.validate_target(target)

    if not is_valid:
        flash(f'Invalid target: {error_msg}', 'error')
        return redirect(url_for('seo_scan'))

    try:
        seo = SEOAnalyzer()
        results = seo.analyze(target)
        return render_template('seo.html', results=results, target=target)
    except Exception as e:
        flash(f'SEO analysis failed: {str(e)}', 'error')
        return redirect(url_for('seo_scan'))


@app.route('/seo/crawl', methods=['POST'])
@rate_limit(max_calls=5, window_seconds=60)
def seo_crawl_start():
    """Start a site-wide SEO crawl as a background job."""
    target = request.form.get('target', '').strip()
    if not target:
        return jsonify({'error': 'No target provided'}), 400

    target = clean_target(target)
    validator = AdvancedValidator()
    is_valid, error_msg = validator.validate_target(target)
    if not is_valid:
        return jsonify({'error': error_msg}), 400

    job_id = job_manager.submit_seo_crawl_job(target, max_pages=100)
    return jsonify({'job_id': job_id})


@app.route('/seo/crawl/<job_id>/status')
def seo_crawl_status(job_id):
    """Poll the status of a site-wide SEO crawl job."""
    status = job_manager.get_seo_crawl_status(job_id)
    if status is None:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify(status)


@app.route('/seo/crawl/<job_id>/report')
def seo_crawl_report(job_id):
    """Show the site SEO report (or a waiting page if still running)."""
    status = job_manager.get_seo_crawl_status(job_id)
    if not status:
        flash('Crawl not found or expired.', 'error')
        return redirect(url_for('seo_scan'))
    if status['status'] != 'completed':
        return render_template('seo_crawl_waiting.html',
                               job_id=job_id,
                               target=status['target'],
                               status=status)
    return render_template('seo_site.html',
                           crawl=status['result'],
                           job_id=job_id)


@app.route('/email', methods=['GET', 'POST'])
@rate_limit(max_calls=10, window_seconds=60)
def email_scan():
    """Email security analysis page."""
    if request.method == 'GET':
        return render_template('email.html')

    target = request.form.get('target', '').strip()
    if not target:
        flash('Please enter a domain to analyse.', 'warning')
        return redirect(url_for('email_scan'))

    target = clean_target(target)
    validator = AdvancedValidator()
    is_valid, error_msg = validator.validate_target(target)
    if not is_valid:
        flash(f'Invalid target: {error_msg}', 'error')
        return redirect(url_for('email_scan'))

    try:
        analyzer = EmailAnalyzer()
        results = analyzer.analyze(target)
        return render_template('email.html', results=results, target=target)
    except Exception as e:
        flash(f'Email analysis failed: {str(e)}', 'error')
        return redirect(url_for('email_scan'))


@app.route('/threat', methods=['GET', 'POST'])
@rate_limit(max_calls=20, window_seconds=60)
def threat_scan():
    """Threat intelligence lookup — hash, domain, IP, URL."""
    if request.method == 'GET':
        return render_template('threat.html')

    query = request.form.get('query', '').strip()
    if not query:
        flash('Please enter a search term.', 'warning')
        return redirect(url_for('threat_scan'))

    if len(query) > 2048:
        flash('Search term is too long.', 'error')
        return redirect(url_for('threat_scan'))

    try:
        analyzer = ThreatIntelAnalyzer()
        results = analyzer.search(query)
        return render_template('threat.html', results=results, query=query)
    except Exception as e:
        flash(f'Search failed: {str(e)}', 'error')
        return redirect(url_for('threat_scan'))


@app.route('/tools/password')
def password_generator():
    """Client-side cryptographically secure password generator."""
    return render_template('password_generator.html')


@app.route('/privacy')
def privacy():
    """GDPR Art. 13 privacy notice."""
    return render_template('privacy.html')


@app.route('/about')
def about():
    """About page — what Security Buddy is and the principles behind it."""
    return render_template('about.html')


@app.route('/guides')
def guides():
    """Editorial hub listing every security guide."""
    return render_template('guides.html', guides=GUIDES)


@app.route('/guides/<slug>')
def guide(slug):
    """A single long-form security guide, rendered from structured content."""
    item = GUIDES_BY_SLUG.get(slug)
    if item is None:
        abort(404)
    # Surface a few other guides as "related" — the next ones in order, wrapping around.
    idx = GUIDES.index(item)
    related = [GUIDES[(idx + i) % len(GUIDES)] for i in range(1, 4)]
    return render_template('guide.html', guide=item, related=related,
                           updated=GUIDES_UPDATED)


@app.route('/sitemap.xml')
def sitemap():
    """XML sitemap covering public, content-rich pages for search engines."""
    pages = [
        (url_for('index', _external=True), '1.0'),
        (url_for('about', _external=True), '0.7'),
        (url_for('guides', _external=True), '0.8'),
        (url_for('seo_scan', _external=True), '0.6'),
        (url_for('email_scan', _external=True), '0.6'),
        (url_for('threat_scan', _external=True), '0.6'),
        (url_for('password_generator', _external=True), '0.6'),
        (url_for('privacy', _external=True), '0.3'),
    ]
    pages += [(url_for('guide', slug=g['slug'], _external=True), '0.7') for g in GUIDES]

    urls = ''.join(
        f'<url><loc>{loc}</loc><lastmod>{GUIDES_UPDATED}</lastmod>'
        f'<priority>{prio}</priority></url>'
        for loc, prio in pages
    )
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           f'{urls}</urlset>')
    resp = make_response(xml)
    resp.headers['Content-Type'] = 'application/xml; charset=utf-8'
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


@app.route('/robots.txt')
def robots_txt():
    """Allow crawling and point search engines at the sitemap."""
    content = (
        'User-agent: *\n'
        'Allow: /\n'
        f'Sitemap: {url_for("sitemap", _external=True)}\n'
    )
    resp = make_response(content)
    resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


@app.route('/ads.txt')
def ads_txt():
    """Authorized Digital Sellers (ads.txt) for Google AdSense verification."""
    content = 'google.com, pub-9729522875920807, DIRECT, f08c47fec0942fa0\n'
    resp = make_response(content)
    resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """Account settings — notification prefs."""
    if request.method == 'POST':
        if request.form.get('action') == 'notifications':
            current_user.email_notifications = bool(request.form.get('email_notifications'))
            db.session.commit()
            flash('Notification preferences saved.', 'success')
        return redirect(url_for('account'))
    return render_template('account.html')


@app.route('/account/delete', methods=['POST'])
@login_required
def account_delete():
    """Permanently delete account and all associated data (Art. 17 GDPR)."""
    password = request.form.get('password', '')
    if not current_user.check_password(password):
        flash('Incorrect password. Account not deleted.', 'error')
        return redirect(url_for('account'))
    user = User.query.get(current_user.id)
    logout_user()
    db.session.delete(user)
    db.session.commit()
    flash('Your account and all associated data have been permanently deleted.', 'info')
    return redirect(url_for('index'))


@app.route('/account/export')
@login_required
def account_export():
    """Data portability export — JSON (Art. 15 & 20 GDPR)."""
    scans = ScanResult.query.filter_by(user_id=current_user.id).all()
    gmail_cred = current_user.gmail_credential
    data = {
        'exported_at': datetime.utcnow().isoformat(),
        'user': {
            'username': current_user.username,
            'email': current_user.email,
            'created_at': current_user.created_at.isoformat(),
            'tos_accepted_at': current_user.tos_accepted_at.isoformat()
                               if current_user.tos_accepted_at else None,
        },
        # Gmail connection status only — OAuth tokens are never exported.
        'gmail_connection': ({
            'connected': True,
            'email': gmail_cred.email,
            'connected_at': gmail_cred.created_at.isoformat() if gmail_cred.created_at else None,
        } if gmail_cred else {'connected': False}),
        'scans': [
            {
                'target': s.target,
                'scan_type': s.scan_type,
                'security_score': s.security_score,
                'created_at': s.created_at.isoformat(),
            }
            for s in scans
        ],
    }
    resp = make_response(json.dumps(data, indent=2))
    resp.headers['Content-Type'] = 'application/json'
    resp.headers['Content-Disposition'] = 'attachment; filename="securitybuddy-export.json"'
    return resp


@app.route('/notifications/unsubscribe')
def notifications_unsubscribe():
    """One-click email unsubscribe with HMAC token."""
    uid = request.args.get('uid', type=int)
    token = request.args.get('token', '')
    if not uid or not token:
        flash('Invalid unsubscribe link.', 'error')
        return redirect(url_for('index'))
    expected = make_unsubscribe_token(uid, app.secret_key)
    if not _hmac_compare(expected, token):
        flash('Invalid unsubscribe link.', 'error')
        return redirect(url_for('index'))
    user = User.query.get(uid)
    if user:
        user.email_notifications = False
        db.session.commit()
    flash('You have been unsubscribed from email notifications.', 'info')
    return redirect(url_for('index'))


# ─────────────────────────────────────────────────────────────────────────
# Gmail Newsletter Manager
#
# OAuth + Gmail endpoints live under /gmail/* (not /api/*) on purpose: the
# /api/ namespace is reserved for the X-API-Key REST API and is CSRF-exempt.
# These endpoints are session/cookie authenticated, so they must stay inside
# the CSRF-protected world. State-changing requests (POST/DELETE) therefore
# send the per-session token via the X-CSRF-Token header.
#
# The whole feature stays dormant until Google OAuth is configured: without
# GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET every route below returns 404 and the
# nav link is hidden. Setting those env vars re-enables it with no code change.
# ─────────────────────────────────────────────────────────────────────────
def _require_gmail_enabled(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not gmail_manager.gmail_oauth_configured():
            abort(404)
        return view(*args, **kwargs)
    return wrapper


@app.route('/newsletter-manager')
@login_required
@_require_gmail_enabled
def newsletter_manager():
    """Newsletter Manager page — connect Gmail and unsubscribe from newsletters."""
    cred = GmailCredential.query.filter_by(user_id=current_user.id).first()
    return render_template(
        'newsletter_manager.html',
        connected=cred is not None,
        gmail_email=cred.email if cred else None,
        oauth_configured=gmail_manager.gmail_oauth_configured(),
    )


@app.route('/gmail/auth')
@login_required
@_require_gmail_enabled
def gmail_auth():
    """Start the Google OAuth flow and redirect to the consent screen."""
    if not gmail_manager.gmail_oauth_configured():
        flash('Gmail integration is not configured on this server.', 'error')
        return redirect(url_for('newsletter_manager'))
    redirect_uri = url_for('gmail_callback', _external=True)
    auth_url, state = gmail_manager.build_auth_url(redirect_uri)
    session['gmail_oauth_state'] = state
    return redirect(auth_url)


@app.route('/gmail/callback')
@login_required
@_require_gmail_enabled
def gmail_callback():
    """Handle the OAuth callback and persist the tokens for the current user."""
    state = session.pop('gmail_oauth_state', None)
    if not state or request.args.get('state') != state:
        flash('Gmail authorization failed: invalid state.', 'error')
        return redirect(url_for('newsletter_manager'))
    if request.args.get('error'):
        flash('Gmail authorization was cancelled.', 'warning')
        return redirect(url_for('newsletter_manager'))

    code = request.args.get('code')
    if not code:
        flash('Gmail authorization failed: missing code.', 'error')
        return redirect(url_for('newsletter_manager'))

    try:
        redirect_uri = url_for('gmail_callback', _external=True)
        creds = gmail_manager.exchange_code(redirect_uri, state, code)
        email = gmail_manager.get_email_address(creds)

        cred = GmailCredential.query.filter_by(user_id=current_user.id).first()
        if cred is None:
            cred = GmailCredential(user_id=current_user.id)
            db.session.add(cred)
        cred.email = email
        cred.token = gmail_manager.encrypt_token(creds.token)
        if creds.refresh_token:  # only returned on first consent — keep the old one otherwise
            cred.refresh_token = gmail_manager.encrypt_token(creds.refresh_token)
        cred.token_uri = creds.token_uri
        cred.scopes = ' '.join(creds.scopes or gmail_manager.GMAIL_SCOPES)
        cred.expiry = creds.expiry
        cred.updated_at = datetime.utcnow()
        db.session.commit()
        flash(f'Connected Gmail account {email}.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Could not connect Gmail: {e}', 'error')

    return redirect(url_for('newsletter_manager'))


@app.route('/gmail/newsletters')
@login_required
@_require_gmail_enabled
def gmail_newsletters():
    """Return the list of newsletter senders found in the connected mailbox (JSON)."""
    cred = GmailCredential.query.filter_by(user_id=current_user.id).first()
    if cred is None:
        return jsonify({'error': 'not_connected'}), 400
    try:
        creds = gmail_manager.credentials_from_record(cred)
        newsletters = gmail_manager.list_newsletters(creds)
        # Persist a refreshed access token if google-auth renewed it mid-request.
        if creds.token and creds.token != gmail_manager.decrypt_token(cred.token):
            cred.token = gmail_manager.encrypt_token(creds.token)
            cred.expiry = creds.expiry
            cred.updated_at = datetime.utcnow()
            db.session.commit()
        return jsonify({'newsletters': newsletters})
    except Exception as e:
        app.logger.warning(f'Gmail newsletter fetch failed: {e}')
        return jsonify({'error': 'fetch_failed', 'message': str(e)}), 502


@app.route('/gmail/unsubscribe', methods=['POST'])
@login_required
@_require_gmail_enabled
@rate_limit(max_calls=30, window_seconds=60)
def gmail_unsubscribe():
    """Unsubscribe from a newsletter.

    one_click + https URL → perform the RFC 8058 POST server-side.
    Otherwise return the url/mailto for the browser to open in a new tab.
    """
    cred = GmailCredential.query.filter_by(user_id=current_user.id).first()
    if cred is None:
        return jsonify({'status': 'error', 'message': 'Gmail is not connected.'}), 400

    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    mailto = (data.get('mailto') or '').strip()
    one_click = bool(data.get('one_click'))

    if one_click and url:
        ok, message = gmail_manager.one_click_unsubscribe(url)
        return jsonify({'status': 'ok' if ok else 'error', 'message': message}), \
            (200 if ok else 502)
    if url:
        return jsonify({'status': 'open', 'url': url,
                        'message': 'Opening the unsubscribe page in a new tab.'})
    if mailto:
        return jsonify({'status': 'mailto', 'url': mailto,
                        'message': 'Opening your email client to unsubscribe.'})
    return jsonify({'status': 'error',
                    'message': 'No unsubscribe method available for this sender.'}), 400


@app.route('/gmail/disconnect', methods=['DELETE', 'POST'])
@login_required
@_require_gmail_enabled
def gmail_disconnect():
    """Disconnect the Gmail account: revoke tokens at Google and delete the row."""
    cred = GmailCredential.query.filter_by(user_id=current_user.id).first()
    if cred:
        try:
            gmail_manager.revoke(
                gmail_manager.decrypt_token(cred.refresh_token)
                or gmail_manager.decrypt_token(cred.token)
            )
        except Exception:
            pass  # best-effort — still drop our copy below
        db.session.delete(cred)
        db.session.commit()
    return jsonify({'status': 'ok'})


@app.route('/cron/cleanup', methods=['POST'])
def cron_cleanup():
    """Retention cleanup: delete guest scans older than 90 days."""
    secret = os.environ.get('CRON_SECRET', '')
    if not secret:
        return jsonify({'error': 'Not configured'}), 503
    auth = request.headers.get('Authorization', '')
    if not _hmac_compare(f'Bearer {secret}', auth):
        return jsonify({'error': 'Unauthorized'}), 401
    cutoff = datetime.utcnow() - timedelta(days=90)
    deleted = ScanResult.query.filter(
        ScanResult.user_id.is_(None),
        ScanResult.created_at < cutoff
    ).delete()
    db.session.commit()
    return jsonify({'deleted': deleted})


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
