"""
Cache Manager for Security Buddy - Intelligent caching to improve performance
"""
import json
import hashlib
from datetime import datetime, timedelta
from models import ScanResult
from app import db
import logging

class ScanCache:
    def __init__(self, cache_duration_hours=6):
        self.cache_duration = timedelta(hours=cache_duration_hours)
        self.logger = logging.getLogger(__name__)
    
    def get_cache_key(self, target, scan_type='standard'):
        """Generate cache key for target and scan type"""
        cache_string = f"{target}:{scan_type}"
        return hashlib.md5(cache_string.encode()).hexdigest()
    
    def is_cache_valid(self, scan_result):
        """Check if cached result is still valid"""
        if not scan_result:
            return False
        
        cache_age = datetime.utcnow() - scan_result.created_at
        return cache_age < self.cache_duration
    
    def get_cached_result(self, target, scan_type='standard'):
        """Get cached scan result if available and valid"""
        try:
            # Find most recent scan for this target
            latest_scan = ScanResult.query.filter_by(
                target=target
            ).order_by(ScanResult.created_at.desc()).first()
            
            if self.is_cache_valid(latest_scan):
                self.logger.info(f"Cache hit for {target}")
                return latest_scan
            
            self.logger.info(f"Cache miss for {target}")
            return None
            
        except Exception as e:
            self.logger.error(f"Cache lookup error: {str(e)}")
            return None
    
    def store_result(self, target, results, security_score, user_id=None):
        """Store scan result in cache"""
        try:
            scan_result = ScanResult(
                target=target,
                scan_type=results.get('scan_type', 'domain'),
                results=json.dumps(results) if isinstance(results, dict) else results,
                security_score=security_score,
                user_id=user_id
            )
            db.session.add(scan_result)
            db.session.commit()
            
            self.logger.info(f"Cached result for {target}")
            return scan_result
            
        except Exception as e:
            self.logger.error(f"Cache store error: {str(e)}")
            return None
    
    def invalidate_cache(self, target):
        """Invalidate cache for specific target"""
        try:
            # Mark old scans as outdated (we could add a field for this)
            # For now, we rely on time-based invalidation
            self.logger.info(f"Cache invalidated for {target}")
            
        except Exception as e:
            self.logger.error(f"Cache invalidation error: {str(e)}")
    
    def cleanup_old_cache(self, days_to_keep=30):
        """Clean up old cache entries"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
            
            # Delete old scan results that don't belong to users
            old_scans = ScanResult.query.filter(
                ScanResult.created_at < cutoff_date,
                ScanResult.user_id.is_(None)
            ).all()
            
            for scan in old_scans:
                db.session.delete(scan)
            
            db.session.commit()
            self.logger.info(f"Cleaned up {len(old_scans)} old cache entries")
            
        except Exception as e:
            self.logger.error(f"Cache cleanup error: {str(e)}")

class PerformanceOptimizer:
    def __init__(self):
        self.cache = ScanCache()
        self.concurrent_limit = 5  # Max concurrent scans
        self.active_scans = set()
    
    def can_start_scan(self, target):
        """Check if we can start a new scan"""
        if len(self.active_scans) >= self.concurrent_limit:
            return False, "Too many concurrent scans. Please try again later."
        
        if target in self.active_scans:
            return False, "Scan already in progress for this target."
        
        return True, None
    
    def start_scan(self, target):
        """Mark scan as started"""
        self.active_scans.add(target)
    
    def finish_scan(self, target):
        """Mark scan as finished"""
        self.active_scans.discard(target)
    
    def get_optimized_scan_result(self, target, force_refresh=False):
        """Get scan result with caching optimization"""
        # Check cache first unless force refresh
        if not force_refresh:
            cached_result = self.cache.get_cached_result(target)
            if cached_result:
                return {
                    'cached': True,
                    'scan_result': cached_result,
                    'results': json.loads(cached_result.results) if isinstance(cached_result.results, str) else cached_result.results
                }
        
        return {'cached': False, 'scan_result': None, 'results': None}