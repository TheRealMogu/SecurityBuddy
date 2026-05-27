import re
import os
import base64
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

TIMEOUT = 8

VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
ABUSEIPDB_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')


def _is_private_ip(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split('.')]
        return (
            parts[0] == 10
            or parts[0] == 127
            or parts[0] == 0
            or parts[0] >= 240
            or (parts[0] == 172 and 16 <= parts[1] <= 31)
            or (parts[0] == 192 and parts[1] == 168)
            or (parts[0] == 169 and parts[1] == 254)
        )
    except Exception:
        return False


class ThreatIntelAnalyzer:

    def search(self, query: str) -> dict:
        query = query.strip()
        if len(query) > 2048:
            return self._error_result(query, 'unknown', 'Input too long.')
        query_type = self._detect_type(query)
        if query_type == 'url':
            return self._analyze_url(query)
        elif query_type == 'ip':
            return self._analyze_ip(query)
        elif query_type == 'hash':
            return self._analyze_hash(query)
        else:
            return self._analyze_domain(query)

    def _detect_type(self, query: str) -> str:
        if re.match(r'^https?://', query, re.IGNORECASE):
            return 'url'
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', query):
            return 'ip'
        if re.match(r'^[0-9a-fA-F]{32}$', query):
            return 'hash'
        if re.match(r'^[0-9a-fA-F]{40}$', query):
            return 'hash'
        if re.match(r'^[0-9a-fA-F]{64}$', query):
            return 'hash'
        return 'domain'

    # ── Analysis methods ───────────────────────────────────────────────────

    def _analyze_url(self, url: str) -> dict:
        checks = [(self._urlhaus_url, [url]), (self._threatfox, [url])]
        if VT_API_KEY:
            checks.append((self._virustotal_url, [url]))
        sources = self._run_concurrent(checks)
        tags = self._collect_tags(sources)
        first_seen = self._first_date(sources)
        last_seen = self._last_date(sources)
        return self._build_result(url, 'url', sources, tags, first_seen, last_seen)

    def _analyze_domain(self, domain: str) -> dict:
        checks = [(self._urlhaus_host, [domain]), (self._threatfox, [domain])]
        if VT_API_KEY:
            checks.append((self._virustotal_domain, [domain]))
        sources = self._run_concurrent(checks)
        tags = self._collect_tags(sources)
        return self._build_result(domain, 'domain', sources, tags, None, None)

    def _analyze_ip(self, ip: str) -> dict:
        if _is_private_ip(ip):
            return self._error_result(ip, 'ip', 'Private or reserved IP addresses are not checked.')
        checks = [(self._urlhaus_host, [ip]), (self._threatfox, [ip])]
        if ABUSEIPDB_KEY:
            checks.append((self._abuseipdb, [ip]))
        if VT_API_KEY:
            checks.append((self._virustotal_ip, [ip]))
        sources = self._run_concurrent(checks)
        tags = self._collect_tags(sources)
        return self._build_result(ip, 'ip', sources, tags, None, None)

    def _analyze_hash(self, hash_value: str) -> dict:
        checks = [(self._malwarebazaar, [hash_value]), (self._threatfox, [hash_value])]
        if VT_API_KEY:
            checks.append((self._virustotal_file, [hash_value]))
        sources = self._run_concurrent(checks)
        tags = self._collect_tags(sources)
        first_seen = self._first_date(sources)
        last_seen = self._last_date(sources)
        return self._build_result(hash_value, 'hash', sources, tags, first_seen, last_seen)

    def _run_concurrent(self, checks: list) -> list:
        sources = []
        with ThreadPoolExecutor(max_workers=len(checks)) as ex:
            futures = {ex.submit(fn, *args): fn.__name__ for fn, args in checks}
            for future in as_completed(futures):
                try:
                    sources.append(future.result())
                except Exception:
                    pass
        return sources

    # ── Source checks ──────────────────────────────────────────────────────

    def _urlhaus_url(self, url: str) -> dict:
        src = {'name': 'URLhaus', 'status': 'unknown', 'details': {},
               'link': 'https://urlhaus.abuse.ch/', 'tags': [],
               'first_seen': None, 'last_seen': None}
        try:
            r = requests.post('https://urlhaus-api.abuse.ch/v1/url/',
                              data={'url': url}, timeout=TIMEOUT)
            data = r.json()
            qs = data.get('query_status')
            if qs == 'is_malware':
                src['status'] = 'malicious'
                src['details'] = {
                    'url_status': data.get('url_status'),
                    'threat': data.get('threat'),
                    'date_added': data.get('date_added'),
                    'reporter': data.get('reporter'),
                }
                src['tags'] = data.get('tags') or []
                src['link'] = data.get('urlhaus_reference', src['link'])
                src['first_seen'] = data.get('date_added')
                src['last_seen'] = data.get('date_added')
            elif qs == 'no_results':
                src['status'] = 'clean'
        except Exception as e:
            src['status'] = 'error'
            src['details'] = {'error': str(e)[:120]}
        return src

    def _urlhaus_host(self, host: str) -> dict:
        src = {'name': 'URLhaus', 'status': 'unknown', 'details': {},
               'link': 'https://urlhaus.abuse.ch/', 'tags': []}
        try:
            r = requests.post('https://urlhaus-api.abuse.ch/v1/host/',
                              data={'host': host}, timeout=TIMEOUT)
            data = r.json()
            qs = data.get('query_status')
            if qs == 'is_host':
                urls = data.get('urls', [])
                active = sum(1 for u in urls if u.get('url_status') in ('online', 'unknown'))
                src['status'] = 'malicious' if active > 0 else 'suspicious'
                src['details'] = {
                    'urls_count': data.get('urls_count', 0),
                    'active_urls': active,
                    'blacklists': data.get('blacklists', {}),
                    'sample_urls': [u.get('url') for u in urls[:5]],
                }
                all_tags: set = set()
                for u in urls[:30]:
                    for t in (u.get('tags') or []):
                        all_tags.add(t)
                src['tags'] = list(all_tags)
                src['link'] = data.get('urlhaus_reference', src['link'])
            elif qs == 'no_results':
                src['status'] = 'clean'
        except Exception as e:
            src['status'] = 'error'
            src['details'] = {'error': str(e)[:120]}
        return src

    def _threatfox(self, ioc: str) -> dict:
        src = {'name': 'ThreatFox', 'status': 'unknown', 'details': {},
               'link': 'https://threatfox.abuse.ch/', 'tags': [],
               'first_seen': None, 'last_seen': None}
        try:
            r = requests.post('https://threatfox-api.abuse.ch/api/v1/',
                              json={'query': 'search_ioc', 'search_term': ioc},
                              timeout=TIMEOUT)
            data = r.json()
            qs = data.get('query_status')
            if qs == 'ok':
                items = data.get('data') or []
                if items:
                    src['status'] = 'malicious'
                    first = items[0]
                    src['details'] = {
                        'ioc_type': first.get('ioc_type'),
                        'threat_type': first.get('threat_type'),
                        'malware': first.get('malware'),
                        'confidence': first.get('confidence_level'),
                        'first_seen': first.get('first_seen'),
                        'last_seen': first.get('last_seen'),
                        'total_iocs': len(items),
                    }
                    src['tags'] = list({t for item in items for t in (item.get('tags') or [])})
                    src['link'] = f'https://threatfox.abuse.ch/ioc/{first.get("id", "")}/'
                    src['first_seen'] = first.get('first_seen')
                    src['last_seen'] = first.get('last_seen')
                else:
                    src['status'] = 'clean'
            elif qs == 'no_results':
                src['status'] = 'clean'
        except Exception as e:
            src['status'] = 'error'
            src['details'] = {'error': str(e)[:120]}
        return src

    def _malwarebazaar(self, hash_value: str) -> dict:
        src = {'name': 'MalwareBazaar', 'status': 'unknown', 'details': {},
               'link': 'https://bazaar.abuse.ch/', 'tags': [],
               'first_seen': None, 'last_seen': None}
        try:
            r = requests.post('https://mb-api.abuse.ch/api/v1/',
                              data={'query': 'get_info', 'hash': hash_value},
                              timeout=TIMEOUT)
            data = r.json()
            qs = data.get('query_status')
            if qs == 'ok':
                items = data.get('data') or []
                if items:
                    src['status'] = 'malicious'
                    item = items[0]
                    src['details'] = {
                        'file_name': item.get('file_name'),
                        'file_type': item.get('file_type'),
                        'file_size': item.get('file_size'),
                        'signature': item.get('signature'),
                        'first_seen': item.get('first_seen'),
                        'last_seen': item.get('last_seen'),
                        'sha256': item.get('sha256_hash'),
                        'md5': item.get('md5_hash'),
                        'reporter': item.get('reporter'),
                    }
                    src['tags'] = item.get('tags') or []
                    src['link'] = f'https://bazaar.abuse.ch/sample/{item.get("sha256_hash", "")}/'
                    src['first_seen'] = item.get('first_seen')
                    src['last_seen'] = item.get('last_seen')
            elif qs == 'hash_not_found':
                src['status'] = 'clean'
        except Exception as e:
            src['status'] = 'error'
            src['details'] = {'error': str(e)[:120]}
        return src

    def _virustotal_url(self, url: str) -> dict:
        src = {'name': 'VirusTotal', 'status': 'unknown', 'details': {},
               'link': 'https://www.virustotal.com/', 'tags': []}
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
            r = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}',
                             headers={'x-apikey': VT_API_KEY}, timeout=TIMEOUT)
            if r.status_code == 200:
                attrs = r.json().get('data', {}).get('attributes', {})
                src = self._vt_stats(src, attrs)
                src['link'] = f'https://www.virustotal.com/gui/url/{url_id}'
            elif r.status_code == 404:
                src['status'] = 'clean'
        except Exception as e:
            src['status'] = 'error'
            src['details'] = {'error': str(e)[:120]}
        return src

    def _virustotal_domain(self, domain: str) -> dict:
        src = {'name': 'VirusTotal', 'status': 'unknown', 'details': {},
               'link': f'https://www.virustotal.com/gui/domain/{domain}', 'tags': []}
        try:
            r = requests.get(f'https://www.virustotal.com/api/v3/domains/{domain}',
                             headers={'x-apikey': VT_API_KEY}, timeout=TIMEOUT)
            if r.status_code == 200:
                attrs = r.json().get('data', {}).get('attributes', {})
                src = self._vt_stats(src, attrs)
                src['details'].update({
                    'registrar': attrs.get('registrar'),
                    'creation_date': attrs.get('creation_date'),
                })
        except Exception as e:
            src['status'] = 'error'
            src['details'] = {'error': str(e)[:120]}
        return src

    def _virustotal_ip(self, ip: str) -> dict:
        src = {'name': 'VirusTotal', 'status': 'unknown', 'details': {},
               'link': f'https://www.virustotal.com/gui/ip-address/{ip}', 'tags': []}
        try:
            r = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                             headers={'x-apikey': VT_API_KEY}, timeout=TIMEOUT)
            if r.status_code == 200:
                attrs = r.json().get('data', {}).get('attributes', {})
                src = self._vt_stats(src, attrs)
                src['details'].update({
                    'country': attrs.get('country'),
                    'asn': attrs.get('asn'),
                    'as_owner': attrs.get('as_owner'),
                    'network': attrs.get('network'),
                })
        except Exception as e:
            src['status'] = 'error'
            src['details'] = {'error': str(e)[:120]}
        return src

    def _virustotal_file(self, hash_value: str) -> dict:
        src = {'name': 'VirusTotal', 'status': 'unknown', 'details': {},
               'link': f'https://www.virustotal.com/gui/file/{hash_value}', 'tags': []}
        try:
            r = requests.get(f'https://www.virustotal.com/api/v3/files/{hash_value}',
                             headers={'x-apikey': VT_API_KEY}, timeout=TIMEOUT)
            if r.status_code == 200:
                attrs = r.json().get('data', {}).get('attributes', {})
                src = self._vt_stats(src, attrs)
                names = attrs.get('names') or []
                src['details'].update({
                    'file_name': names[0] if names else None,
                    'file_type': attrs.get('type_description'),
                    'file_size': attrs.get('size'),
                    'magic': attrs.get('magic'),
                })
                src['tags'] = list(attrs.get('tags', []))
            elif r.status_code == 404:
                src['status'] = 'clean'
        except Exception as e:
            src['status'] = 'error'
            src['details'] = {'error': str(e)[:120]}
        return src

    def _vt_stats(self, src: dict, attrs: dict) -> dict:
        stats = attrs.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        if malicious > 0:
            src['status'] = 'malicious'
        elif suspicious > 0:
            src['status'] = 'suspicious'
        elif total > 0:
            src['status'] = 'clean'
        src['details'] = {
            'malicious': malicious,
            'suspicious': suspicious,
            'undetected': stats.get('undetected', 0),
            'total': total,
        }
        cats = attrs.get('categories', {})
        src['tags'] = list(set(cats.values()))
        return src

    def _abuseipdb(self, ip: str) -> dict:
        src = {'name': 'AbuseIPDB', 'status': 'unknown', 'details': {},
               'link': f'https://www.abuseipdb.com/check/{ip}', 'tags': []}
        try:
            r = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                headers={'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'},
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                data = r.json().get('data', {})
                confidence = data.get('abuseConfidenceScore', 0)
                if confidence >= 50:
                    src['status'] = 'malicious'
                elif confidence >= 15:
                    src['status'] = 'suspicious'
                else:
                    src['status'] = 'clean'
                src['details'] = {
                    'confidence_score': confidence,
                    'country': data.get('countryCode'),
                    'usage_type': data.get('usageType'),
                    'isp': data.get('isp'),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt'),
                    'is_tor': data.get('isTor', False),
                }
                if confidence > 0:
                    src['tags'] = ['abuse']
        except Exception as e:
            src['status'] = 'error'
            src['details'] = {'error': str(e)[:120]}
        return src

    # ── Helpers ────────────────────────────────────────────────────────────

    def _collect_tags(self, sources: list) -> list:
        tags: set = set()
        for s in sources:
            if s['status'] in ('malicious', 'suspicious'):
                tags.update(s.get('tags') or [])
        return list(tags)

    def _first_date(self, sources: list):
        dates = [s.get('first_seen') for s in sources if s.get('first_seen')]
        return min(dates) if dates else None

    def _last_date(self, sources: list):
        dates = [s.get('last_seen') for s in sources if s.get('last_seen')]
        return max(dates) if dates else None

    def _build_result(self, query, query_type, sources, tags, first_seen, last_seen) -> dict:
        malicious = [s for s in sources if s['status'] == 'malicious']
        suspicious = [s for s in sources if s['status'] == 'suspicious']
        checked = [s for s in sources if s['status'] not in ('error', 'unknown')]

        if malicious:
            verdict = 'malicious'
        elif suspicious:
            verdict = 'suspicious'
        elif any(s['status'] == 'clean' for s in sources):
            verdict = 'clean'
        else:
            verdict = 'unknown'

        return {
            'query': query,
            'query_type': query_type,
            'verdict': verdict,
            'detection_count': len(malicious) + len(suspicious),
            'total_sources': len(checked),
            'sources': sources,
            'tags': tags,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'vt_enabled': bool(VT_API_KEY),
            'abuseipdb_enabled': bool(ABUSEIPDB_KEY),
            'error': None,
        }

    def _error_result(self, query, query_type, msg) -> dict:
        return {
            'query': query, 'query_type': query_type, 'verdict': 'unknown',
            'detection_count': 0, 'total_sources': 0, 'sources': [],
            'tags': [], 'first_seen': None, 'last_seen': None,
            'vt_enabled': bool(VT_API_KEY), 'abuseipdb_enabled': bool(ABUSEIPDB_KEY),
            'error': msg,
        }
