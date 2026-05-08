import json
from urllib.parse import urlparse
from flask import render_template, request, redirect, url_for, flash, session, make_response, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from app import app, db
from models import User, ScanResult, APIKey, MonitoringConfig
from scanner import SecurityScanner
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


POSTI_DATA = [{"name": "Bicchierino bar", "category": "Bar", "city": "Milan", "location": "1.2 km from Armani/Silos", "rating": None, "favorites": 12}, {"name": "Cascate di Novalesa", "category": "Waterfall", "city": "Turin", "location": "1.8 km from Novalesa Abbey", "rating": 4.9, "favorites": 30}, {"name": "Laghi Verdi", "category": "Natural Landmark", "city": "Turin · Balme", "location": None, "rating": None, "favorites": None}, {"name": "Ponte dei Salti", "category": "Outdoors", "city": "Locarno · Lavertezzo", "location": None, "rating": 5.0, "favorites": 600}, {"name": "Fiume Elsa", "category": "Attraction", "city": "Siena", "location": "146 m from Parco fluviale dell'Elsa", "rating": None, "favorites": None}, {"name": "Lago di Dres", "category": "Natural Landmark", "city": "Turin", "location": "2.4 km from Ufficio Turistico Ceres", "rating": None, "favorites": None}, {"name": "N'Ombra de Vin", "category": "Gastropub", "city": "Milan", "location": "1.1 km from Milan Cathedral", "rating": 5.0, "favorites": 3}, {"name": "MIsushi Restaurant", "category": "Sushi Restaurant", "city": "Milan", "location": "1.5 km from Milan Cathedral", "rating": None, "favorites": 1}, {"name": "Muu Sushi - Porta Romana", "category": "Sushi Restaurant", "city": "Milan", "location": "1.6 km from Milan Cathedral", "rating": None, "favorites": 1}, {"name": "Shin Fusion Restaurant", "category": "Sushi Restaurant", "city": "Milan", "location": "1.5 km from Milan Cathedral", "rating": None, "favorites": 13}, {"name": "Famoso Fusion dal 1988", "category": "Thai Restaurant", "city": "Milan", "location": "2.9 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Sato Sushi Experience - Porta Venezia", "category": "Sushi Restaurant", "city": "Milan", "location": "1.8 km from Milan Cathedral", "rating": None, "favorites": 14}, {"name": "Kappou NINOMIYA", "category": "Japanese Restaurant", "city": "Milan", "location": "2.5 km from Armani/Silos", "rating": None, "favorites": 3}, {"name": "Oasi Giapponese", "category": "Japanese Restaurant", "city": "Milan", "location": "2.7 km from Armani/Silos", "rating": None, "favorites": None}, {"name": "Il Massimo del Gelato", "category": "Ice Cream Shop", "city": "Milan", "location": "2.0 km from Sforzesco Castle", "rating": None, "favorites": 1}, {"name": "Gusto 17 - Navigli | Tortona District", "category": "Ice Cream Shop", "city": "Milan", "location": "1.9 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Artico Gelateria - Isola", "category": "Ice Cream Shop", "city": "Milan", "location": "2.2 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Frezza - Cucina de Coccio", "category": "Italian Restaurant", "city": "Milan", "location": "1.7 km from Milan Cathedral", "rating": None, "favorites": 6}, {"name": "Toyama Sushi Milano", "category": "Sushi Restaurant", "city": "Milan", "location": "2.7 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Wu Taiyo Fusion Ranzoni 6 Milano", "category": "Other Cuisine", "city": "Milan", "location": "2.6 km from Sforzesco Castle", "rating": None, "favorites": 100}, {"name": "Ginza Sushi", "category": "Sushi Restaurant", "city": "Milan", "location": "2.5 km from Sforzesco Castle", "rating": None, "favorites": 2}, {"name": "Minami Milano", "category": "Japanese Restaurant", "city": "Milan", "location": "2.1 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Casanori", "category": "Japanese Restaurant", "city": "Milan", "location": "2.1 km from Sforzesco Castle", "rating": None, "favorites": 2}, {"name": "Miyabi Milano", "category": "Sushi Restaurant", "city": "Milan", "location": "794 m from Milan Cathedral", "rating": None, "favorites": 12}, {"name": "Città del Drago 2", "category": "Chinese Restaurant", "city": "Milan", "location": "1.7 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Poporoya", "category": "Japanese Restaurant", "city": "Milan", "location": "2.2 km from Milan Cathedral", "rating": None, "favorites": 20}, {"name": "Oriental Thai Restaurant", "category": "Thai Restaurant", "city": "Milan", "location": "2.1 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Duorice sushi", "category": "Sushi Restaurant", "city": "Milan", "location": "2.8 km from Sforzesco Castle", "rating": None, "favorites": 1}, {"name": "Yi Pin Sushi", "category": "Sushi Restaurant", "city": "Milan", "location": "2.9 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Toyama 2", "category": "Sushi Restaurant", "city": "Milan", "location": "573 m from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "RAITO FANTASTIC FUSION", "category": "Sushi Restaurant", "city": "Milan", "location": "1.5 km from Milan Cathedral", "rating": None, "favorites": 2}, {"name": "Domò Sushi Milano", "category": "Sushi Restaurant", "city": "Milan", "location": "1.6 km from Milan Cathedral", "rating": 4.8, "favorites": 98}, {"name": "Soft Sushi", "category": "Japanese Restaurant", "city": "Milan", "location": "697 m from Chiesa Madre di San G.", "rating": None, "favorites": None}, {"name": "Ishi Sushi", "category": "Restaurant", "city": "Bari · Santeramo in Colle", "location": None, "rating": None, "favorites": None}, {"name": "Sushi Kòbbo", "category": "Japanese Restaurant", "city": "Milan", "location": "1.6 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Kanji Centrale", "category": "Japanese Restaurant", "city": "Milan", "location": "2.2 km from Milan Cathedral", "rating": None, "favorites": 22}, {"name": "AYU Sushi Concept", "category": "Sushi Restaurant", "city": "Milan", "location": "2.0 km from Milan Cathedral", "rating": None, "favorites": 70}, {"name": "The Seed Milano", "category": "Coffee Shop", "city": "Milan", "location": "1.3 km from Milan Cathedral", "rating": None, "favorites": 1}, {"name": "Castelnuovo Bocca d'Adda", "category": "District", "city": "Lodi, Lombardy", "location": None, "rating": None, "favorites": 1}, {"name": "Penelope a casa", "category": "Restaurant", "city": "Milan", "location": "1.5 km from Milan Cathedral", "rating": 4.7, "favorites": 7}, {"name": "Atelier Prato", "category": "Restaurant", "city": "Milan", "location": "488 m from Sforzesco Castle", "rating": 4.8, "favorites": 5}, {"name": "La Pescheria da Claudio e Giulia", "category": "Seafood Restaurant", "city": "Milan", "location": "2.4 km from Church of Saints Pete.", "rating": 4.5, "favorites": 100}, {"name": "Ravioleria Sarpi", "category": "Fast Food Store", "city": "Milan", "location": "1.2 km from Sforzesco Castle", "rating": None, "favorites": 1}, {"name": "Orizzonti", "category": "Restaurant", "city": "Milan", "location": "715 m from Milan Cathedral", "rating": 4.6, "favorites": 2}, {"name": "Armani/Bamboo Bar", "category": "Bar", "city": "Milan", "location": "718 m from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Tommasi Milano", "category": "Italian Restaurant", "city": "Milan", "location": "1.8 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Il Trullo Osteria Pizzeria Cucina", "category": "Italian Restaurant", "city": "Milan", "location": "2.1 km from Milan Cathedral", "rating": None, "favorites": 6}, {"name": "Il Salumaio di Montenapoleone", "category": "Restaurant", "city": "Milan", "location": "672 m from Milan Cathedral", "rating": 4.9, "favorites": 8}, {"name": "Giardini di Villa Reale", "category": "Nature-Based Attraction", "city": "Milan", "location": "1.1 km from Milan Cathedral", "rating": None, "favorites": 1}, {"name": "Sushiteca O.ma.ca.sé", "category": "Japanese Restaurant", "city": "Milan", "location": "1.8 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Nobuya", "category": "Restaurant", "city": "Milan", "location": "471 m from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Azabu10", "category": "Japanese Restaurant", "city": "Milan", "location": "558 m from Arcimboldi Theater", "rating": 4.8, "favorites": 20}, {"name": "Sushi Matsu Omakase", "category": "Japanese Restaurant", "city": "Milan", "location": "2.0 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "IYO Omakase", "category": "Sushi Restaurant", "city": "Milan", "location": "2.0 km from Milan Cathedral", "rating": None, "favorites": 2}, {"name": "L'ile Douce Milano", "category": "Tea Shop", "city": "Milan", "location": "2.2 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Wakaba", "category": "Japanese Izakaya", "city": "Milan", "location": "1.4 km from Milan Cathedral", "rating": None, "favorites": 6}, {"name": "EssenzaSushi", "category": "Vegetarian/Vegan", "city": "Milan", "location": "1.5 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Nobu Milano", "category": "Japanese Restaurant", "city": "Milan", "location": "753 m from Milan Cathedral", "rating": 4.9, "favorites": 14}, {"name": "Emoraya", "category": "Japanese Restaurant", "city": "Milan", "location": "2.2 km from Milan Cathedral", "rating": None, "favorites": 3}, {"name": "SACHI Milano | Duomo Terrace", "category": "Japanese Restaurant", "city": "Milan", "location": "412 m from Milan Cathedral", "rating": None, "favorites": 34}, {"name": "Lazzaro 1915", "category": "Fine Dining", "city": "Padua · Pontelongo", "location": None, "rating": None, "favorites": None}, {"name": "Iyo", "category": "Restaurant", "city": "Milan", "location": "3.0 km from Fontana delle Quattro", "rating": None, "favorites": None}, {"name": "Ralph's Bar", "category": "Gastropub", "city": "Milan", "location": "721 m from Milan Cathedral", "rating": 4.9, "favorites": 56}, {"name": "Beefbar Milano", "category": "Italian Restaurant", "city": "Milan", "location": "677 m from Milan Cathedral", "rating": 4.9, "favorites": 40}, {"name": "Isola Rooftop Terrace Milano", "category": "Gastropub", "city": "Milan", "location": "425 m from Milan Cathedral", "rating": None, "favorites": 20}, {"name": "Giacomo Caffè Letterario", "category": "Cafe", "city": "Milan", "location": "129 m from Milan Cathedral", "rating": None, "favorites": 1}, {"name": "Piazza Quadrilatero - Ex Semina.", "category": "Landmark", "city": "Milan", "location": "634 m from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Botanical Garden Città Studi", "category": "Nature-Based Attraction", "city": "Milan", "location": "2.1 km from Forlanini Park", "rating": None, "favorites": None}, {"name": "Grow Restaurant", "category": "Fine Dining", "city": "Monza and Brianza", "location": "1.6 km from Nuovo Ci.", "rating": None, "favorites": None}, {"name": "Trattoria contemporanea", "category": "Fine Dining", "city": "Como · Lomazzo", "location": None, "rating": None, "favorites": 12}, {"name": "Osteria degli Assonica", "category": "Fine Dining", "city": "Bergamo · Sorisole", "location": None, "rating": None, "favorites": 15}, {"name": "Emporio Armani Caffè & Ristora.", "category": "Cafe", "city": "Milan", "location": "714 m from Milan Cathedral", "rating": 4.9, "favorites": 5}, {"name": "Lu bar", "category": "Fresh Sale Store", "city": "Milan", "location": "2.9 km from Forlanini Park", "rating": None, "favorites": None}, {"name": "Giardino Cordusio", "category": "Gastropub", "city": "Milan", "location": "411 m from Milan Cathedral", "rating": 4.9, "favorites": 100}, {"name": "El Porteño Prohibido", "category": "Specialty Restaurant", "city": "Milan", "location": "1.4 km from Milan Cathedral", "rating": 4.9, "favorites": 15}, {"name": "Crocca - Milano Via California", "category": "Pizza Fast Food", "city": "Milan", "location": "2.0 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Officina del Riso Navigli", "category": "Italian Restaurant", "city": "Milan", "location": "2.3 km from Milan Cathedral", "rating": None, "favorites": 2}, {"name": "Ce Piace - Osteria Romana", "category": "Italian Restaurant", "city": "Milan", "location": "3.0 km from BAM", "rating": 4.6, "favorites": 100}, {"name": "LùBar", "category": "Other Cuisine", "city": "Milan", "location": "1.1 km from Milan Cathedral", "rating": 4.7, "favorites": 24}, {"name": "Spontini", "category": "Pizza Fast Food", "city": "Milan", "location": "2.2 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Panozzi e Panelli Bottega Mene.", "category": "Deli Restaurant", "city": "Milan", "location": "361 m from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Vesta Fiori Chiari", "category": "Seafood Restaurant", "city": "Milan", "location": "974 m from Milan Cathedral", "rating": 5.0, "favorites": 5}, {"name": "Spontini (rated)", "category": "Italian Pizza", "city": "Milan", "location": "234 m from Milan Cathedral", "rating": 4.4, "favorites": 26}, {"name": "piazza Sant'Agostino", "category": "Roads", "city": "Milan", "location": "1.8 km from Milan Cathedral", "rating": None, "favorites": 2}, {"name": "Cavoli a merenda! La Terrazza", "category": "Italian Restaurant", "city": "Milan", "location": "752 m from Sforzesco Castle", "rating": None, "favorites": 2}, {"name": "Ditta Artigianale Specialty Coffee", "category": "Coffee Shop", "city": "Milan", "location": "582 m from Sforzesco Castle", "rating": None, "favorites": 2}, {"name": "Ceresio 7 Pools & Restaurant", "category": "Gastropub", "city": "Milan", "location": "2.4 km from Milan Cathedral", "rating": 4.9, "favorites": 95}, {"name": "SunEleven Rooftop Bar", "category": "Bar", "city": "Milan", "location": "247 m from Milan Cathedral", "rating": 5.0, "favorites": 47}, {"name": "The Roof Milano", "category": "Gastropub", "city": "Milan", "location": "425 m from Milan Cathedral", "rating": 4.9, "favorites": 73}, {"name": "La Rinascente Food and Restaur.", "category": "Fine Dining", "city": "Milan", "location": "143 m from Milan Cathedral", "rating": 5.0, "favorites": 31}, {"name": "Radio Rooftop Bar", "category": "Gastropub", "city": "Milan", "location": "1.7 km from Milan Cathedral", "rating": 4.9, "favorites": 100}, {"name": "Tatanka Milano", "category": "Coffee Shop", "city": "Milan", "location": "2.0 km from Theater Cinema Marti.", "rating": None, "favorites": None}, {"name": "Filante Città Studi", "category": "Pizza Fast Food", "city": "Milan", "location": "2.5 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "White Rabbit Speakeasy", "category": "Bar", "city": "Milan", "location": "2.7 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Dexter", "category": "Restaurant", "city": "Milan", "location": "2.0 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Palazzo Lombardia", "category": "Restaurant", "city": "Milan", "location": "2.5 km from Milan Cathedral", "rating": None, "favorites": 1}, {"name": "NORI WAY", "category": "Japanese Restaurant", "city": "Milan", "location": "2.5 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Street Smash Burgers Porta Venezia", "category": "Hamburger Fast Food", "city": "Milan", "location": "1.7 km from Milan Cathedral", "rating": None, "favorites": 2}, {"name": "Palazzo Litta", "category": "Landmark", "city": "Milan", "location": "1.1 km from Milan Cathedral", "rating": 4.9, "favorites": 30}, {"name": "Panini De Santis - Milan", "category": "Restaurant", "city": "Milan", "location": "544 m from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Hamerica's Camperio", "category": "Hamburger Fast Food", "city": "Milan", "location": "821 m from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Reset_Milano", "category": "Bar", "city": "Milan", "location": "2.8 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "La Mongolfiera", "category": "Italian Restaurant", "city": "Milan", "location": "2.6 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Campo Teatrale", "category": "Theater", "city": "Milan", "location": "2.0 km from Theater Cinema Marti.", "rating": None, "favorites": None}, {"name": "La Siciliana", "category": "Dessert Shop", "city": "Milan", "location": "2.9 km from BAM", "rating": None, "favorites": 1}, {"name": "Trattoria Mirta", "category": "Italian Restaurant", "city": "Milan", "location": "2.8 km from BAM", "rating": None, "favorites": None}, {"name": "ENOTECA LM - Enoteca Milano", "category": "Bar", "city": "Milan", "location": "2.0 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Pizzeria Positano Milano - Colonne", "category": "Pizza Fast Food", "city": "Milan", "location": "888 m from Milan Cathedral", "rating": None, "favorites": 11}, {"name": "Rovello 18", "category": "Italian Restaurant", "city": "Milan", "location": "1.5 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Pescatore Lobster Bar", "category": "Restaurant", "city": "Milan", "location": "1.7 km from Milan Cathedral", "rating": None, "favorites": 3}, {"name": "Trattoria Masuelli San Marco", "category": "Italian Restaurant", "city": "Milan", "location": "2.1 km from Milan Cathedral", "rating": None, "favorites": 14}, {"name": "Trattoria Bolognese da Mauro", "category": "Italian Restaurant", "city": "Milan", "location": "2.8 km from Milan Cathedral", "rating": None, "favorites": 64}, {"name": "La Latteria", "category": "Restaurant", "city": "Milan", "location": "1.4 km from Milan Cathedral", "rating": None, "favorites": 10}, {"name": "Torricelli 19", "category": "Italian Restaurant", "city": "Milan", "location": "2.5 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Al Matarel", "category": "Italian Restaurant", "city": "Milan", "location": "1.4 km from Milan Cathedral", "rating": None, "favorites": 87}, {"name": "Langosteria", "category": "Seafood Restaurant", "city": "Milan", "location": "1.9 km from Sforzesco Castle", "rating": 5.0, "favorites": 23}, {"name": "Ristorante Torre Del Mangia", "category": "Italian Restaurant", "city": "Milan", "location": "2.7 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Antica Trattoria della Pesa", "category": "Italian Restaurant", "city": "Milan", "location": "2.1 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Trattoria del Nuovo Macello", "category": "Italian Restaurant", "city": "Milan", "location": "2.8 km from Milan Cathedral", "rating": None, "favorites": 1}, {"name": "Osteria Francescana", "category": "Fine Dining", "city": "Modena", "location": "340 m from Modena Cathedral", "rating": 3.6, "favorites": 100}, {"name": "Cantine Isola dal 1896", "category": "Bar", "city": "Milan", "location": "1.2 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Ristorante Piero e Pia", "category": "Restaurant", "city": "Milan", "location": "2.5 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Ristorante Ratanà", "category": "Italian Restaurant", "city": "Milan", "location": "2.4 km from Milan Cathedral", "rating": 4.8, "favorites": 1100}, {"name": "THE DOPING", "category": "Western Restaurant", "city": "Milan", "location": "1.6 km from Milan Cathedral", "rating": 4.9, "favorites": 88}, {"name": "Bellavista Milano", "category": "Restaurant", "city": "Milan", "location": "532 m from Milan Cathedral", "rating": None, "favorites": None}, {"name": "RONIN 浪人", "category": "Gastropub", "city": "Milan", "location": "979 m from Sforzesco Castle", "rating": 5.0, "favorites": 53}, {"name": "Tipografia Alimentare", "category": "Bar", "city": "Milan", "location": "1.5 km from Arcimboldi Theater", "rating": None, "favorites": 4}, {"name": "Bar Nico", "category": "Bar", "city": "Milan", "location": "2.9 km from Milan Cathedral", "rating": None, "favorites": 4}, {"name": "Pescherie Riunite - San Marco", "category": "Seafood Restaurant", "city": "Milan", "location": "1.5 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Bentoteca Milano", "category": "Japanese Restaurant", "city": "Milan", "location": "1.4 km from Sforzesco Castle", "rating": 4.9, "favorites": 14}, {"name": "Pasticceria La Mary", "category": "Dessert Shop", "city": "Milan", "location": "2.3 km from Milan Cathedral", "rating": None, "favorites": 26}, {"name": "Café Gorille", "category": "Coffee Shop", "city": "Milan", "location": "2.4 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "BAM - Biblioteca degli Alberi Milano", "category": "Nature-Based Attraction", "city": "Milan", "location": "2.3 km from Milan Cathedral", "rating": 4.9, "favorites": 100}, {"name": "Bar Basso", "category": "Gastropub", "city": "Milan", "location": "2.4 km from Milan Cathedral", "rating": 4.8, "favorites": 13}, {"name": "PLIN Pastificio con Cucina", "category": "Italian Restaurant", "city": "Milan", "location": "1.5 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Forno Del Mastro - Negozio & La.", "category": "Bakery Shop", "city": "Monza and Brianza", "location": "1.6 km from Giardini.", "rating": None, "favorites": 5}, {"name": "CasaVietnam", "category": "Vietnamese Restaurant", "city": "Milan", "location": "2.7 km from Sforzesco Castle", "rating": None, "favorites": 1}, {"name": "Fairouz - Gerusalemme", "category": "Other Cuisine", "city": "Milan", "location": "2.9 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Mumbao", "category": "Restaurant", "city": "Milan", "location": "1.2 km from Sforzesco Castle", "rating": None, "favorites": 1}, {"name": "Takumi Ramen & Yakisoba", "category": "Ramen Restaurant", "city": "Milan", "location": "2.2 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Trattoria Sincera", "category": "Restaurant", "city": "Milan", "location": "2.9 km from PAC Pavilion", "rating": None, "favorites": None}, {"name": "Trattoria la Madonnina di Costan.", "category": "Restaurant", "city": "Milan", "location": "1.0 km from Arcimboldi Theater", "rating": None, "favorites": None}, {"name": "L'Uccellina", "category": "Italian Restaurant", "city": "Milan", "location": "2.0 km from Milan Cathedral", "rating": None, "favorites": 1}, {"name": "Hostaria Terza Carbonaia", "category": "Restaurant", "city": "Milan", "location": "2.1 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Osteria Del Binari", "category": "Italian Restaurant", "city": "Milan", "location": "2.0 km from Sforzesco Castle", "rating": None, "favorites": 4}, {"name": "Al Garghet", "category": "Italian Restaurant", "city": "Milan", "location": "Milan", "rating": 4.9, "favorites": 100}, {"name": "Katsusanderia", "category": "Japanese Restaurant", "city": "Milan", "location": "1.6 km from Milan Cathedral", "rating": None, "favorites": 3}, {"name": "Lubna Milano", "category": "Bar", "city": "Milan", "location": "2.7 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Vertigo Milano by Purobeach", "category": "Bar", "city": "Milan", "location": "2.6 km from Sforzesco Castle", "rating": None, "favorites": 16}, {"name": "The District Rooftop - Cocktail Bar", "category": "Bar", "city": "Milan", "location": "2.5 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "CONFINE - PIZZA E CANTINA", "category": "Italian Pizza", "city": "Milan", "location": "902 m from Milan Cathedral", "rating": 4.9, "favorites": 46}, {"name": "Bauscia", "category": "Italian Restaurant", "city": "Milan", "location": "656 m from Milan Cathedral", "rating": None, "favorites": 1}, {"name": "Frida", "category": "Gastropub", "city": "Milan", "location": "2.1 km from Sforzesco Castle", "rating": None, "favorites": 1}, {"name": "RĀMA by Domó", "category": "Japanese Restaurant", "city": "Milan", "location": "1.6 km from Milan Cathedral", "rating": None, "favorites": None}, {"name": "Ristorante Al Rifugio Pugliese", "category": "Restaurant", "city": "Milan", "location": "2.1 km from Sforzesco Castle", "rating": None, "favorites": None}, {"name": "Pollolo Korean Chicken & Corn D.", "category": "Korean Restaurant", "city": "Milan", "location": "2.4 km from Milan Cathedral", "rating": None, "favorites": 1}, {"name": "Spirit de Milan", "category": "Leisure", "city": "Milan", "location": "1.3 km from Villa Litta Modignani", "rating": 4.8, "favorites": 100}, {"name": "Cascina Nascosta", "category": "Italian Restaurant", "city": "Milan", "location": "649 m from Sforzesco Castle", "rating": None, "favorites": 2}, {"name": "Frizzi E Lazzi", "category": "Bar", "city": "Milan", "location": "2.3 km from Milan Cathedral", "rating": None, "favorites": None}]


@app.route('/posti')
@login_required
def posti():
    return render_template('posti.html', places=POSTI_DATA)


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
