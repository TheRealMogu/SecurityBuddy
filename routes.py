import json
from urllib.parse import urlparse
from flask import render_template, request, redirect, url_for, flash, session, make_response, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from app import app, db
from models import User, ScanResult, APIKey, MonitoringConfig
from scanner import SecurityScanner
from seo_analyzer import SEOAnalyzer
from validators import AdvancedValidator, clean_target
from pdf_generator import SecurityReportPDF
from premium_features import PremiumAnalytics, AdvancedScanner
from notification_system import NotificationSystem
from api_routes import api_bp

# Register API blueprint
app.register_blueprint(api_bp)

@app.route('/')
def index():
    """Homepage with scan form"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
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

        # Advanced scanning for premium users
        if current_user.is_authenticated and current_user.is_premium:
            advanced_scanner = AdvancedScanner()
            advanced_results = advanced_scanner.advanced_vulnerability_scan(f"https://{target}")
            results['advanced_scan'] = advanced_results
        
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
        
        # Send notification for premium users if critical issues found
        if current_user.is_authenticated and current_user.is_premium:
            critical_issues = []
            if results.get('overall_score', 100) < 40:
                checks = results.get('checks', {})
                for check_name, check_data in checks.items():
                    if isinstance(check_data, dict) and check_data.get('issues'):
                        critical_issues.extend(check_data['issues'])
                
                if critical_issues:
                    notification_system = NotificationSystem()
                    notification_system.send_vulnerability_alert(
                        current_user.email, scan_result, critical_issues
                    )
        
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
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            # Validate next_page to prevent open redirect
            if next_page and urlparse(next_page).netloc != '':
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
        
        if not all([username, email, password]):
            flash('Please fill in all fields.', 'warning')
            return render_template('login.html')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('login.html')
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('login.html')
        
        # Create new user
        user = User(username=username, email=email)
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
    
    # Check if user has access to this scan
    if scan_result.user_id and (not current_user.is_authenticated or scan_result.user_id != current_user.id):
        flash('You do not have access to this scan result.', 'error')
        return redirect(url_for('index'))
    
    results = json.loads(scan_result.results)
    return render_template('scan_result.html', results=results, scan_id=scan_id)

@app.route('/premium')
def premium():
    """Premium features preview"""
    return render_template('premium.html')

@app.route('/download-pdf/<int:scan_id>')
@login_required
def download_pdf(scan_id):
    """Download PDF report (Premium feature)"""
    if not current_user.is_premium:
        flash('PDF downloads are available for premium users only.', 'warning')
        return redirect(url_for('premium'))
    
    try:
        scan_result = ScanResult.query.get_or_404(scan_id)
        
        # Check ownership
        if scan_result.user_id != current_user.id:
            flash('You do not have access to this scan result.', 'error')
            return redirect(url_for('dashboard'))
        
        # Generate PDF
        pdf_generator = SecurityReportPDF()
        pdf_buffer = pdf_generator.generate_report(scan_result, {
            'organization': current_user.organization
        })
        
        filename = f"security_report_{scan_result.target}_{scan_result.created_at.strftime('%Y%m%d')}.pdf"
        
        response = make_response(pdf_buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
        
    except Exception as e:
        flash(f'Failed to generate PDF: {str(e)}', 'error')
        return redirect(url_for('view_scan', scan_id=scan_id))

@app.route('/analytics')
@login_required
def analytics():
    """Premium analytics dashboard"""
    if not current_user.is_premium:
        flash('Analytics are available for premium users only.', 'warning')
        return redirect(url_for('premium'))
    
    try:
        analytics = PremiumAnalytics()
        
        # Generate charts
        trend_chart = analytics.generate_security_trend_chart(current_user.id)
        comparison_chart = analytics.generate_domain_comparison_chart(current_user.id)
        vulnerability_chart = analytics.generate_vulnerability_distribution(current_user.id)
        
        return render_template('analytics.html', 
                             trend_chart=trend_chart,
                             comparison_chart=comparison_chart,
                             vulnerability_chart=vulnerability_chart)
        
    except Exception as e:
        flash(f'Failed to load analytics: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

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


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
