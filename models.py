from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import update
from app import db
import secrets
import hashlib

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
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
            rate_limit=200
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
    usage_count = db.Column(db.Integer, default=0)       # lifetime total
    hourly_usage = db.Column(db.Integer, default=0)      # requests in current hour window
    rate_limit = db.Column(db.Integer, default=100)      # requests per hour
    rate_limit_reset = db.Column(db.DateTime, nullable=True)  # when the current window expires
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, nullable=True)

    def try_consume(self):
        """
        Atomically check the rate limit and consume one request.
        Returns True if the request is allowed, False if rate-limited.
        Uses a conditional UPDATE so concurrent workers cannot exceed the limit.
        """
        now = datetime.utcnow()

        # (Re)open the window atomically if it has expired or was never set.
        db.session.execute(
            update(APIKey)
            .where(
                APIKey.id == self.id,
                (APIKey.rate_limit_reset.is_(None)) | (APIKey.rate_limit_reset <= now),
            )
            .values(rate_limit_reset=now + timedelta(hours=1), hourly_usage=0)
        )

        # Atomically increment only if still under the limit.
        result = db.session.execute(
            update(APIKey)
            .where(APIKey.id == self.id, APIKey.hourly_usage < APIKey.rate_limit)
            .values(
                hourly_usage=APIKey.hourly_usage + 1,
                usage_count=APIKey.usage_count + 1,
                last_used=now,
            )
        )
        db.session.commit()
        db.session.refresh(self)
        return result.rowcount > 0

    def increment_usage(self):
        """Backward-compatible: consume one request unconditionally."""
        now = datetime.utcnow()
        if not self.rate_limit_reset:
            self.rate_limit_reset = now + timedelta(hours=1)
            self.hourly_usage = 0
        self.usage_count += 1
        self.hourly_usage += 1
        self.last_used = now
        db.session.commit()

    def is_rate_limited(self):
        """Check if this API key has exceeded its hourly rate limit."""
        now = datetime.utcnow()
        if not self.rate_limit_reset or self.rate_limit_reset <= now:
            self.rate_limit_reset = now + timedelta(hours=1)
            self.hourly_usage = 0
            db.session.commit()
            return False
        return self.hourly_usage >= self.rate_limit

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
