"""
Advanced input validation and security checks for Security Buddy
"""
import re
import socket
import ipaddress
from urllib.parse import urlparse
import dns.resolver
import logging

def is_public_ip(ip_str):
    """Return True if the IP string is a routable public address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )


def resolve_host_is_public(host):
    """
    Resolve a hostname (all A/AAAA records) and verify every address is public.
    Returns (ok, error_message). If the host does not resolve at all we allow it
    (the downstream request will simply fail) — we only block resolutions that
    point at private/internal ranges, which is the SSRF risk.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, socket.error):
        return True, None  # cannot resolve — not an SSRF vector
    for info in infos:
        ip = info[4][0]
        # strip IPv6 zone id if present
        ip = ip.split('%')[0]
        if not is_public_ip(ip):
            return False, "Target resolves to a private or reserved IP address"
    return True, None


class AdvancedValidator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def validate_target(self, target):
        """
        Advanced validation for domains, subdomains, IPs, and ports
        """
        if not target or len(target.strip()) == 0:
            return False, "Target cannot be empty"
        
        target = target.strip().lower()
        
        # Remove protocol if present
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target if target.startswith(('http://', 'https://')) else f'http://{target}')
            target = parsed.netloc or parsed.path
        
        # Check for port
        host = target
        port = None
        if ':' in target and not self._is_ipv6(target):
            try:
                host, port_str = target.rsplit(':', 1)
                port = int(port_str)
                if port < 1 or port > 65535:
                    return False, "Port must be between 1 and 65535"
            except ValueError:
                return False, "Invalid port number"
        
        # Validate IP address
        if self._is_ip_address(host):
            return self._validate_ip(host)
        
        # Validate domain
        return self._validate_domain(host)
    
    def _is_ipv6(self, target):
        """Check if target contains IPv6 address"""
        return '[' in target and ']' in target
    
    def _is_ip_address(self, host):
        """Check if host is an IP address"""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False
    
    def _validate_ip(self, ip):
        """Validate IP address"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private/reserved addresses
            if ip_obj.is_private:
                return False, "Private IP addresses are not allowed for security reasons"
            
            if ip_obj.is_loopback:
                return False, "Loopback addresses are not allowed"
            
            if ip_obj.is_multicast or ip_obj.is_reserved:
                return False, "Reserved IP addresses are not allowed"
            
            return True, None
            
        except ValueError as e:
            return False, f"Invalid IP address: {str(e)}"
    
    def _validate_domain(self, domain):
        """Validate domain name with advanced checks"""
        # Basic length check
        if len(domain) > 253:
            return False, "Domain name too long (max 253 characters)"
        
        if len(domain) == 0:
            return False, "Domain name cannot be empty"
        
        # Check for valid characters and structure
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        if not domain_pattern.match(domain):
            return False, "Invalid domain format"
        
        # Check each label
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63:
                return False, "Domain label too long (max 63 characters per label)"
            if label.startswith('-') or label.endswith('-'):
                return False, "Domain labels cannot start or end with hyphens"
        
        # Check for TLD
        if len(labels) < 2:
            return False, "Domain must have at least one dot (e.g., example.com)"
        
        tld = labels[-1]
        if len(tld) < 2:
            return False, "Top-level domain must be at least 2 characters"
        
        # Check for obviously invalid domains
        invalid_domains = ['localhost', 'test', 'example', 'invalid']
        if domain in invalid_domains:
            return False, f"'{domain}' is not a valid public domain"

        # SSRF guard: reject domains that resolve to private/internal IPs
        ok, err = resolve_host_is_public(domain)
        if not ok:
            return False, err

        return True, None
    
    def check_dns_resolution(self, domain):
        """Check if domain resolves to DNS"""
        try:
            result = dns.resolver.resolve(domain, 'A')
            return True, [str(rdata) for rdata in result]
        except dns.resolver.NXDOMAIN:
            return False, "Domain does not exist"
        except dns.resolver.NoAnswer:
            return False, "Domain exists but has no A record"
        except dns.resolver.Timeout:
            return False, "DNS query timed out"
        except Exception as e:
            return False, f"DNS resolution failed: {str(e)}"
    
    def get_enhanced_domain_info(self, domain):
        """Get comprehensive domain information"""
        info = {
            'domain': domain,
            'dns_resolution': None,
            'ip_addresses': [],
            'mx_records': [],
            'txt_records': [],
            'whois_available': False
        }
        
        try:
            # A records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                info['ip_addresses'] = [str(rdata) for rdata in a_records]
                info['dns_resolution'] = True
            except:
                info['dns_resolution'] = False
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                info['mx_records'] = [f"{rdata.preference} {rdata.exchange}" for rdata in mx_records]
            except:
                pass
            
            # TXT records (for SPF, DMARC, etc.)
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                info['txt_records'] = [str(rdata) for rdata in txt_records]
            except:
                pass
            
        except Exception as e:
            self.logger.error(f"Error getting domain info for {domain}: {str(e)}")
        
        return info

def clean_target(target):
    """Clean and normalize target input"""
    if not target:
        return ""
    
    target = target.strip().lower()
    
    # Remove protocol
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target if target.startswith(('http://', 'https://')) else f'http://{target}')
        target = parsed.netloc or parsed.path
    
    # Remove trailing slash and path
    if '/' in target:
        target = target.split('/')[0]
    
    return target