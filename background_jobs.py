"""
Background job system for Security Buddy - Handle long-running scans asynchronously
"""
import threading
import queue
import time
import uuid
from datetime import datetime
from models import ScanResult, User
from app import db
from scanner import SecurityScanner
from premium_features import AdvancedScanner
from notification_system import NotificationSystem
import json
import logging

class BackgroundScanJob:
    def __init__(self, target, user_id=None, advanced=False, notification_email=None):
        self.target = target
        self.user_id = user_id
        self.advanced = advanced
        self.notification_email = notification_email
        self.status = 'pending'
        self.created_at = datetime.utcnow()
        self.progress = 0
        self.current_step = 'Initializing...'
        self.result = None
        self.error = None

class BackgroundJobManager:
    def __init__(self):
        self.job_queue = queue.Queue()
        self.active_jobs = {}
        self.completed_jobs = {}
        self.worker_thread = None
        self.logger = logging.getLogger(__name__)
        self.running = False
        
    def start_worker(self):
        """Start background worker thread"""
        if not self.running:
            self.running = True
            self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
            self.worker_thread.start()
            self.logger.info("Background job worker started")
    
    def stop_worker(self):
        """Stop background worker thread"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
    
    def submit_scan_job(self, target, user_id=None, advanced=False, notification_email=None):
        """Submit a new scan job to the queue"""
        job = BackgroundScanJob(target, user_id, advanced, notification_email)
        job_id = f"scan_{uuid.uuid4().hex}"
        
        self.active_jobs[job_id] = job
        self.job_queue.put((job_id, job))
        
        self.logger.info(f"Submitted scan job {job_id} for {target}")
        return job_id
    
    def get_job_status(self, job_id):
        """Get status of a specific job"""
        if job_id in self.active_jobs:
            job = self.active_jobs[job_id]
            return {
                'job_id': job_id,
                'status': job.status,
                'progress': job.progress,
                'current_step': job.current_step,
                'target': job.target,
                'created_at': job.created_at.isoformat(),
                'error': job.error
            }
        elif job_id in self.completed_jobs:
            job = self.completed_jobs[job_id]
            return {
                'job_id': job_id,
                'status': 'completed',
                'progress': 100,
                'target': job.target,
                'created_at': job.created_at.isoformat(),
                'result': job.result,
                'error': job.error
            }
        else:
            return None
    
    def _worker_loop(self):
        """Main worker loop for processing jobs"""
        while self.running:
            try:
                # Get job from queue with timeout
                job_id, job = self.job_queue.get(timeout=1)
                
                self.logger.info(f"Processing job {job_id}")
                self._process_scan_job(job_id, job)
                
                # Move to completed jobs
                self.completed_jobs[job_id] = self.active_jobs.pop(job_id)
                
                # Cleanup old completed jobs (keep last 100)
                if len(self.completed_jobs) > 100:
                    oldest_job = min(self.completed_jobs.keys(), 
                                   key=lambda k: self.completed_jobs[k].created_at)
                    del self.completed_jobs[oldest_job]
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Worker error: {str(e)}")
                if 'job_id' in locals():
                    job = self.active_jobs.get(job_id)
                    if job:
                        job.status = 'failed'
                        job.error = str(e)
    
    def _process_scan_job(self, job_id, job):
        """Process a single scan job"""
        try:
            job.status = 'running'
            job.current_step = 'Starting security scan...'
            job.progress = 10
            
            # Initialize scanner
            scanner = SecurityScanner()
            
            # Basic scan
            job.current_step = 'Checking connectivity...'
            job.progress = 20
            
            results = scanner.scan_target(job.target)
            
            job.current_step = 'Analyzing HTTPS and SSL...'
            job.progress = 50
            
            # Advanced scan for premium users
            if job.advanced and job.user_id:
                user = User.query.get(job.user_id)
                if user and user.is_premium:
                    job.current_step = 'Running advanced vulnerability scan...'
                    job.progress = 70
                    
                    advanced_scanner = AdvancedScanner()
                    advanced_results = advanced_scanner.advanced_vulnerability_scan(f"https://{job.target}")
                    results['advanced_scan'] = advanced_results
            
            job.current_step = 'Calculating security score...'
            job.progress = 85
            
            # Save to database
            scan_result = ScanResult(
                target=job.target,
                scan_type=results.get('scan_type', 'domain'),
                results=json.dumps(results),
                security_score=results.get('overall_score', 0),
                user_id=job.user_id
            )
            db.session.add(scan_result)
            db.session.commit()
            
            job.current_step = 'Scan completed!'
            job.progress = 100
            job.status = 'completed'
            job.result = {
                'scan_id': scan_result.id,
                'security_score': results.get('overall_score', 0),
                'risk_level': results.get('risk_level', 'unknown')
            }
            
            # Send notification if email provided
            if job.notification_email:
                job.current_step = 'Sending notification...'
                try:
                    notification_system = NotificationSystem()
                    notification_system.send_scan_complete_email(
                        job.notification_email, scan_result
                    )
                except Exception as e:
                    self.logger.warning(f"Failed to send notification: {str(e)}")
            
            self.logger.info(f"Job {job_id} completed successfully")
            
        except Exception as e:
            job.status = 'failed'
            job.error = str(e)
            job.current_step = f'Error: {str(e)}'
            self.logger.error(f"Job {job_id} failed: {str(e)}")

    def submit_seo_crawl_job(self, target: str, max_pages: int = 100) -> str:
        """Start a site-wide SEO crawl in a dedicated background thread."""
        job    = SEOCrawlJob(target, max_pages)
        job_id = f"seo_{uuid.uuid4().hex}"
        self.active_jobs[job_id] = job
        t = threading.Thread(
            target=self._run_seo_crawl, args=(job_id, job), daemon=True
        )
        t.start()
        self.logger.info(f"Submitted SEO crawl job {job_id} for {target}")
        return job_id

    def get_seo_crawl_status(self, job_id: str):
        """Return status dict for an SEO crawl job."""
        job = self.active_jobs.get(job_id) or self.completed_jobs.get(job_id)
        if not job:
            return None
        return {
            'job_id':        job_id,
            'status':        job.status,
            'progress':      job.progress,
            'current_step':  job.current_step,
            'pages_crawled': job.pages_crawled,
            'target':        job.target,
            'created_at':    job.created_at.isoformat(),
            'result':        job.result,
            'error':         job.error,
        }

    def _run_seo_crawl(self, job_id: str, job: 'SEOCrawlJob'):
        try:
            from seo_analyzer import SEOAnalyzer
            job.status       = 'running'
            job.current_step = 'Fetching root page…'
            job.progress     = 2

            def _progress(analysed, total):
                job.pages_crawled = analysed
                job.progress      = max(2, min(95, round(analysed / total * 88) + 5))
                job.current_step  = f'Analysed {analysed} / {total} pages…'

            result = SEOAnalyzer().analyze_site(
                job.target, max_pages=job.max_pages, progress_callback=_progress
            )
            job.pages_crawled = result.get('pages_crawled', 0)
            job.result        = result
            job.progress      = 100
            job.current_step  = 'Crawl complete!'
            job.status        = 'completed'
        except Exception as e:
            job.status       = 'failed'
            job.error        = str(e)
            job.current_step = f'Error: {str(e)}'
            self.logger.error(f"SEO crawl {job_id} failed: {e}")
        finally:
            self.completed_jobs[job_id] = self.active_jobs.pop(job_id, job)
            crawl_jobs = {k: v for k, v in self.completed_jobs.items() if k.startswith('seo_')}
            if len(crawl_jobs) > 50:
                oldest = min(crawl_jobs, key=lambda k: crawl_jobs[k].created_at)
                del self.completed_jobs[oldest]


class SEOCrawlJob:
    def __init__(self, target: str, max_pages: int = 100):
        self.target        = target
        self.max_pages     = max_pages
        self.status        = 'pending'
        self.created_at    = datetime.utcnow()
        self.progress      = 0
        self.current_step  = 'Queued…'
        self.pages_crawled = 0
        self.result        = None
        self.error         = None


# Global job manager instance
job_manager = BackgroundJobManager()

class RetryManager:
    def __init__(self, max_retries=3, base_delay=1):
        self.max_retries = max_retries
        self.base_delay = base_delay
    
    def retry_with_backoff(self, func, *args, **kwargs):
        """Execute function with exponential backoff retry"""
        for attempt in range(self.max_retries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if attempt == self.max_retries:
                    raise e
                
                delay = self.base_delay * (2 ** attempt)
                time.sleep(delay)
                logging.warning(f"Retry attempt {attempt + 1} after {delay}s delay: {str(e)}")
        
        return None