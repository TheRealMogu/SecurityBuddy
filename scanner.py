import requests
import socket
import ssl
import json
import re
from urllib.parse import urlparse
from datetime import datetime, timezone
import logging

class SecurityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityBuddy/1.0 (Security Scanner)'
        })
        self.timeout = 10
    
    def scan_target(self, target):
        """Main scanning function that orchestrates all security checks"""
        results = {
            'target': target,
            'scan_time': datetime.utcnow().isoformat(),
            'checks': {},
            'overall_score': 0,
            'risk_level': 'unknown'
        }
        
        # Determine if target is domain or IP
        is_ip = self._is_ip_address(target)
        scan_type = 'ip' if is_ip else 'domain'
        results['scan_type'] = scan_type
        
        # Normalize target for HTTP requests
        if not target.startswith(('http://', 'https://')):
            target_url = f"https://{target}"
        else:
            target_url = target
            
        try:
            # Basic connectivity check
            results['checks']['connectivity'] = self._check_connectivity(target_url)
            
            # HTTPS and SSL checks
            results['checks']['https'] = self._check_https(target_url)
            results['checks']['ssl'] = self._check_ssl_certificate(target)
            
            # Security headers check
            results['checks']['headers'] = self._check_security_headers(target_url)
            
            # Basic domain info (if not IP)
            if not is_ip:
                results['checks']['domain_info'] = self._get_domain_info(target)
            
            # Calculate overall score
            results['overall_score'] = self._calculate_score(results['checks'])
            results['risk_level'] = self._determine_risk_level(results['overall_score'])
            
        except Exception as e:
            logging.error(f"Error scanning {target}: {str(e)}")
            results['error'] = str(e)
            
        return results
    
    def _is_ip_address(self, target):
        """Check if target is an IP address"""
        try:
            socket.inet_aton(target.split(':')[0])  # Remove port if present
            return True
        except socket.error:
            return False
    
    def _check_connectivity(self, target_url):
        """Check basic connectivity to target"""
        try:
            response = self.session.head(target_url, timeout=self.timeout, allow_redirects=True)
            return {
                'status': 'success',
                'reachable': True,
                'status_code': response.status_code,
                'message': 'Target is reachable'
            }
        except requests.exceptions.RequestException as e:
            return {
                'status': 'error',
                'reachable': False,
                'message': f'Target unreachable: {str(e)}'
            }
    
    def _check_https(self, target_url):
        """Check HTTPS availability and redirects"""
        results = {
            'https_available': False,
            'redirects_to_https': False,
            'mixed_content_risk': False,
            'score': 0,
            'issues': []
        }
        
        try:
            # Check HTTPS
            if target_url.startswith('https://'):
                https_response = self.session.get(target_url, timeout=self.timeout)
                results['https_available'] = True
                results['score'] += 40
            
            # Check HTTP to HTTPS redirect
            http_url = target_url.replace('https://', 'http://')
            try:
                http_response = self.session.get(http_url, timeout=self.timeout, allow_redirects=False)
                if http_response.status_code in [301, 302, 307, 308]:
                    location = http_response.headers.get('Location', '')
                    if location.startswith('https://'):
                        results['redirects_to_https'] = True
                        results['score'] += 30
                    else:
                        results['issues'].append('HTTP does not redirect to HTTPS')
                else:
                    results['issues'].append('HTTP version is accessible without redirect')
            except:
                pass
                
        except requests.exceptions.SSLError:
            results['issues'].append('SSL/TLS connection failed')
        except requests.exceptions.RequestException as e:
            results['issues'].append(f'HTTPS check failed: {str(e)}')
            
        return results
    
    def _check_ssl_certificate(self, target):
        """Check SSL certificate validity"""
        results = {
            'valid': False,
            'expires_soon': False,
            'self_signed': False,
            'days_until_expiry': None,
            'issuer': None,
            'score': 0,
            'issues': []
        }
        
        try:
            # Extract hostname and port
            if '://' in target:
                hostname = urlparse(target).netloc
            else:
                hostname = target
                
            if ':' in hostname:
                host, port = hostname.rsplit(':', 1)
                port = int(port)
            else:
                host = hostname
                port = 443
            
            # Get certificate
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_until_expiry = (expiry_date - now).days
                    
                    results['days_until_expiry'] = days_until_expiry
                    results['valid'] = True
                    results['score'] += 50
                    
                    if days_until_expiry < 30:
                        results['expires_soon'] = True
                        results['issues'].append(f'Certificate expires in {days_until_expiry} days')
                        results['score'] -= 20
                    
                    # Get issuer info
                    issuer = dict(x[0] for x in cert['issuer'])
                    results['issuer'] = issuer.get('organizationName', 'Unknown')
                    
        except ssl.SSLError as e:
            results['issues'].append(f'SSL Error: {str(e)}')
        except Exception as e:
            results['issues'].append(f'Certificate check failed: {str(e)}')
            
        return results
    
    def _check_security_headers(self, target_url):
        """Check for important security headers"""
        results = {
            'score': 0,
            'headers_found': [],
            'headers_missing': [],
            'issues': []
        }
        
        # Important security headers to check
        security_headers = {
            'Strict-Transport-Security': 'HSTS not enabled',
            'Content-Security-Policy': 'CSP not configured',
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME type sniffing protection missing',
            'Referrer-Policy': 'Referrer policy not set',
            'Permissions-Policy': 'Permissions policy not configured'
        }
        
        try:
            response = self.session.get(target_url, timeout=self.timeout)
            headers = response.headers
            
            for header, issue in security_headers.items():
                if header in headers:
                    results['headers_found'].append({
                        'name': header,
                        'value': headers[header]
                    })
                    results['score'] += 15
                else:
                    results['headers_missing'].append(header)
                    results['issues'].append(issue)
            
            # Check for server information disclosure
            if 'Server' in headers:
                server_header = headers['Server']
                if any(tech in server_header.lower() for tech in ['apache', 'nginx', 'iis']):
                    results['issues'].append('Server information disclosed in headers')
                    
        except requests.exceptions.RequestException as e:
            results['issues'].append(f'Header check failed: {str(e)}')
            
        return results
    
    def _get_domain_info(self, domain):
        """Get basic domain information"""
        results = {
            'domain': domain,
            'info_available': False,
            'issues': []
        }
        
        try:
            # Basic DNS resolution
            ip_address = socket.gethostbyname(domain)
            results['ip_address'] = ip_address
            results['info_available'] = True
            
        except socket.gaierror as e:
            results['issues'].append(f'DNS resolution failed: {str(e)}')
        except Exception as e:
            results['issues'].append(f'Domain info check failed: {str(e)}')
            
        return results
    
    def _calculate_score(self, checks):
        """Calculate overall security score"""
        total_score = 0
        max_score = 100
        
        # Weighted scoring
        if 'connectivity' in checks and checks['connectivity']['status'] == 'success':
            total_score += 10
            
        if 'https' in checks:
            total_score += min(checks['https']['score'], 30)
            
        if 'ssl' in checks:
            total_score += min(checks['ssl']['score'], 30)
            
        if 'headers' in checks:
            # Headers can contribute up to 30 points
            header_score = min(checks['headers']['score'], 30)
            total_score += header_score
            
        return min(total_score, max_score)
    
    def _determine_risk_level(self, score):
        """Determine risk level based on score"""
        if score >= 80:
            return 'low'
        elif score >= 60:
            return 'medium'
        elif score >= 40:
            return 'high'
        else:
            return 'critical'
