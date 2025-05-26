from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
import secrets
import hashlib

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_premium = db.Column(db.Boolean, default=False)
    organization = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to scan results
    scan_results = db.relationship('ScanResult', backref='user', lazy=True)
    api_keys = db.relationship('APIKey', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_api_key(self, name="Default API Key"):
        """Generate a new API key for the user"""
        key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        api_key = APIKey(
            user_id=self.id,
            name=name,
            key_hash=key_hash,
            rate_limit=1000 if self.is_premium else 100
        )
        db.session.add(api_key)
        db.session.commit()
        
        return key  # Return the actual key (only time it's shown)
    
    def __repr__(self):
        return f'<User {self.username}>'

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # 'domain' or 'ip'
    results = db.Column(db.Text)  # JSON string of results
    security_score = db.Column(db.Integer)  # Overall score 0-100
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # NULL for guest scans
    
    def __repr__(self):
        return f'<ScanResult {self.target}>'

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(64), unique=True, nullable=False)
    active = db.Column(db.Boolean, default=True)
    usage_count = db.Column(db.Integer, default=0)
    rate_limit = db.Column(db.Integer, default=100)  # requests per hour
    rate_limit_reset = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, nullable=True)
    
    def increment_usage(self):
        """Increment usage counter and update last used"""
        self.usage_count += 1
        self.last_used = datetime.utcnow()
        db.session.commit()
    
    def is_rate_limited(self):
        """Check if API key has exceeded rate limit"""
        if not self.rate_limit_reset or self.rate_limit_reset < datetime.utcnow():
            # Reset rate limit window
            self.rate_limit_reset = datetime.utcnow() + timedelta(hours=1)
            self._current_hour_usage = 0
            db.session.commit()
            return False
        
        # Count usage in current hour
        hour_ago = datetime.utcnow() - timedelta(hours=1)
        # In a real implementation, you'd track this more precisely
        # For now, we'll use a simple approximation
        return self.usage_count > self.rate_limit
    
    def __repr__(self):
        return f'<APIKey {self.name}>'

class MonitoringConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    frequency = db.Column(db.String(20), default='weekly')  # daily, weekly, monthly
    email_alerts = db.Column(db.Boolean, default=True)
    score_threshold = db.Column(db.Integer, default=60)  # Alert if score below this
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_scan = db.Column(db.DateTime, nullable=True)
    next_scan = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship('User', backref='monitoring_configs')
    
    def __repr__(self):
        return f'<MonitoringConfig {self.target}>'
