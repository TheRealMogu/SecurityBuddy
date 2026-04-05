"""
Premium features for Security Buddy including advanced scanning and analytics
"""
import json
import io
import base64
from datetime import datetime, timedelta
from collections import defaultdict

import matplotlib.pyplot as plt
import seaborn as sns

try:
    import numpy as np
    _numpy_available = True
except ImportError:
    _numpy_available = False

from models import ScanResult, User
from app import db

class PremiumAnalytics:
    def __init__(self):
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def generate_security_trend_chart(self, user_id, days=30):
        """Generate security score trend chart for user"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        scans = ScanResult.query.filter(
            ScanResult.user_id == user_id,
            ScanResult.created_at >= start_date
        ).order_by(ScanResult.created_at).all()
        
        if not scans:
            return None
        
        # Group by date and calculate average score
        daily_scores = defaultdict(list)
        for scan in scans:
            date_key = scan.created_at.date()
            daily_scores[date_key].append(scan.security_score)
        
        dates = sorted(daily_scores.keys())
        avg_scores = [sum(daily_scores[date]) / len(daily_scores[date]) for date in dates]
        
        # Create chart
        fig, ax = plt.subplots(figsize=(12, 6))
        ax.plot(dates, avg_scores, marker='o', linewidth=2, markersize=6)
        ax.set_title('Security Score Trend', fontsize=16, fontweight='bold')
        ax.set_xlabel('Date')
        ax.set_ylabel('Average Security Score')
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0, 100)
        
        # Add trend line (requires numpy)
        if len(dates) > 1 and _numpy_available:
            z = np.polyfit(range(len(dates)), avg_scores, 1)
            p = np.poly1d(z)
            ax.plot(dates, p(range(len(dates))), "--", alpha=0.8, color='red')
        
        plt.tight_layout()
        
        # Convert to base64 string
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
        buffer.seek(0)
        chart_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return chart_data
    
    def generate_domain_comparison_chart(self, user_id):
        """Generate comparison chart of all user's domains"""
        scans = ScanResult.query.filter(
            ScanResult.user_id == user_id
        ).all()
        
        if not scans:
            return None
        
        # Get latest scan for each domain
        domain_scores = {}
        for scan in scans:
            if scan.target not in domain_scores or scan.created_at > domain_scores[scan.target]['date']:
                domain_scores[scan.target] = {
                    'score': scan.security_score,
                    'date': scan.created_at
                }
        
        if len(domain_scores) < 2:
            return None
        
        domains = list(domain_scores.keys())
        scores = [domain_scores[domain]['score'] for domain in domains]
        
        # Create horizontal bar chart
        fig, ax = plt.subplots(figsize=(10, max(6, len(domains) * 0.5)))
        bars = ax.barh(domains, scores)
        
        # Color bars based on score
        for i, (bar, score) in enumerate(zip(bars, scores)):
            if score >= 80:
                bar.set_color('#34C759')
            elif score >= 60:
                bar.set_color('#FF9500')
            else:
                bar.set_color('#FF3B30')
        
        ax.set_title('Domain Security Comparison', fontsize=16, fontweight='bold')
        ax.set_xlabel('Security Score')
        ax.set_xlim(0, 100)
        
        # Add score labels on bars
        for i, score in enumerate(scores):
            ax.text(score + 1, i, f'{score}', va='center')
        
        plt.tight_layout()
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
        buffer.seek(0)
        chart_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return chart_data
    
    def generate_vulnerability_distribution(self, user_id):
        """Generate pie chart of vulnerability types found"""
        scans = ScanResult.query.filter(
            ScanResult.user_id == user_id
        ).all()
        
        if not scans:
            return None
        
        vulnerability_counts = defaultdict(int)
        
        for scan in scans:
            try:
                if isinstance(scan.results, str):
                    results = json.loads(scan.results)
                else:
                    results = scan.results
                
                checks = results.get('checks', {})
                
                # Count issues
                for check_name, check_data in checks.items():
                    if isinstance(check_data, dict) and 'issues' in check_data:
                        for issue in check_data['issues']:
                            if 'HTTPS' in issue or 'SSL' in issue:
                                vulnerability_counts['HTTPS/SSL Issues'] += 1
                            elif 'header' in issue.lower():
                                vulnerability_counts['Missing Security Headers'] += 1
                            elif 'certificate' in issue.lower():
                                vulnerability_counts['Certificate Issues'] += 1
                            else:
                                vulnerability_counts['Other Issues'] += 1
                                
            except Exception:
                continue
        
        if not vulnerability_counts:
            return None
        
        # Create pie chart
        fig, ax = plt.subplots(figsize=(8, 8))
        wedges, texts, autotexts = ax.pie(
            vulnerability_counts.values(),
            labels=vulnerability_counts.keys(),
            autopct='%1.1f%%',
            startangle=90
        )
        
        ax.set_title('Vulnerability Distribution', fontsize=16, fontweight='bold')
        
        plt.tight_layout()
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
        buffer.seek(0)
        chart_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return chart_data

class AdvancedScanner:
    def __init__(self):
        self.vulnerability_patterns = {
            'xss_indicators': [
                '<script>',
                'javascript:',
                'onerror=',
                'onload=',
                'eval(',
                'document.cookie'
            ],
            'sql_injection_indicators': [
                "' OR '1'='1",
                '" OR "1"="1',
                'UNION SELECT',
                'DROP TABLE',
                '--',
                '/*'
            ],
            'directory_traversal': [
                '../',
                '..\\',
                '/etc/passwd',
                '/windows/system32'
            ]
        }
    
    def advanced_vulnerability_scan(self, target_url):
        """Perform advanced vulnerability scanning"""
        results = {
            'target': target_url,
            'advanced_checks': {},
            'vulnerability_score': 100,
            'detected_issues': []
        }
        
        # Check for common web vulnerabilities
        results['advanced_checks']['xss_protection'] = self._check_xss_protection(target_url)
        results['advanced_checks']['clickjacking_protection'] = self._check_clickjacking_protection(target_url)
        results['advanced_checks']['content_type_options'] = self._check_content_type_options(target_url)
        results['advanced_checks']['server_information'] = self._check_server_information(target_url)
        
        # Calculate vulnerability score
        for check_name, check_result in results['advanced_checks'].items():
            if check_result.get('vulnerable', False):
                results['vulnerability_score'] -= check_result.get('severity_score', 10)
                results['detected_issues'].append({
                    'type': check_name,
                    'description': check_result.get('description', ''),
                    'severity': check_result.get('severity', 'medium')
                })
        
        results['vulnerability_score'] = max(0, results['vulnerability_score'])
        
        return results
    
    def _check_xss_protection(self, target_url):
        """Check for XSS protection headers"""
        try:
            import requests
            response = requests.get(target_url, timeout=10)
            headers = response.headers
            
            xss_protection = headers.get('X-XSS-Protection', '')
            csp = headers.get('Content-Security-Policy', '')
            
            vulnerable = False
            issues = []
            
            if not xss_protection or xss_protection == '0':
                vulnerable = True
                issues.append("X-XSS-Protection header missing or disabled")
            
            if not csp:
                vulnerable = True
                issues.append("Content-Security-Policy header missing")
            
            return {
                'vulnerable': vulnerable,
                'severity': 'medium' if vulnerable else 'low',
                'severity_score': 15 if vulnerable else 0,
                'description': "XSS protection analysis",
                'issues': issues,
                'headers_found': {
                    'X-XSS-Protection': xss_protection,
                    'Content-Security-Policy': csp[:100] + '...' if len(csp) > 100 else csp
                }
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'description': "Could not perform XSS protection check"
            }
    
    def _check_clickjacking_protection(self, target_url):
        """Check for clickjacking protection"""
        try:
            import requests
            response = requests.get(target_url, timeout=10)
            headers = response.headers
            
            frame_options = headers.get('X-Frame-Options', '')
            csp_frame = 'frame-ancestors' in headers.get('Content-Security-Policy', '')
            
            vulnerable = not frame_options and not csp_frame
            
            return {
                'vulnerable': vulnerable,
                'severity': 'medium' if vulnerable else 'low',
                'severity_score': 10 if vulnerable else 0,
                'description': "Clickjacking protection analysis",
                'issues': ["Missing clickjacking protection (X-Frame-Options or CSP frame-ancestors)"] if vulnerable else [],
                'protection_found': frame_options or 'CSP frame-ancestors' if csp_frame else 'None'
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'description': "Could not perform clickjacking check"
            }
    
    def _check_content_type_options(self, target_url):
        """Check for MIME type sniffing protection"""
        try:
            import requests
            response = requests.get(target_url, timeout=10)
            headers = response.headers
            
            content_type_options = headers.get('X-Content-Type-Options', '')
            vulnerable = content_type_options.lower() != 'nosniff'
            
            return {
                'vulnerable': vulnerable,
                'severity': 'low',
                'severity_score': 5 if vulnerable else 0,
                'description': "MIME type sniffing protection",
                'issues': ["X-Content-Type-Options: nosniff header missing"] if vulnerable else [],
                'header_value': content_type_options or 'Not set'
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'description': "Could not check content type options"
            }
    
    def _check_server_information(self, target_url):
        """Check for server information disclosure"""
        try:
            import requests
            response = requests.get(target_url, timeout=10)
            headers = response.headers
            
            server_header = headers.get('Server', '')
            powered_by = headers.get('X-Powered-By', '')
            
            vulnerable = bool(server_header or powered_by)
            disclosed_info = []
            
            if server_header:
                disclosed_info.append(f"Server: {server_header}")
            if powered_by:
                disclosed_info.append(f"X-Powered-By: {powered_by}")
            
            return {
                'vulnerable': vulnerable,
                'severity': 'low',
                'severity_score': 5 if vulnerable else 0,
                'description': "Server information disclosure",
                'issues': ["Server information disclosed in headers"] if vulnerable else [],
                'disclosed_information': disclosed_info
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'description': "Could not check server information"
            }

# Add numpy import for trend analysis
try:
    import numpy as np
except ImportError:
    # Fallback if numpy is not available
    class MockNumpy:
        def polyfit(self, x, y, degree):
            return [0, 0]
        def poly1d(self, coeffs):
            return lambda x: [0] * len(x) if isinstance(x, list) else 0
    np = MockNumpy()