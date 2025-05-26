import json
from flask import render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from app import app, db
from models import User, ScanResult
from scanner import SecurityScanner

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
    
    # Basic input validation
    if len(target) > 255:
        flash('Target too long. Please enter a valid domain or IP address.', 'error')
        return redirect(url_for('index'))
    
    # Remove protocol if provided for consistency
    if target.startswith(('http://', 'https://')):
        from urllib.parse import urlparse
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    
    try:
        # Perform security scan
        scanner = SecurityScanner()
        results = scanner.scan_target(target)
        
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
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
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

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
