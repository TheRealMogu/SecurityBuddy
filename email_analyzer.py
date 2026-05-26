"""
Email security analyzer — MX, SPF, DMARC, DKIM, blacklists, PTR, STARTTLS.
Uses only dnspython + stdlib; no paid APIs.
"""
import base64
import re
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_DKIM_SELECTORS = [
    'default', 'google', 'mail', 'dkim', 'selector1', 'selector2',
    'k1', 'smtp', 'mta', 'key1', 'email', 'mailjet', 'sendgrid',
    'mx', 's1', 's2', 'sig1', 'pm',
]

# (dns suffix, friendly name)
IP_DNSBL = [
    ('zen.spamhaus.org',       'Spamhaus ZEN'),
    ('bl.spamcop.net',         'SpamCop'),
    ('dnsbl.sorbs.net',        'SORBS'),
    ('b.barracudacentral.org', 'Barracuda'),
    ('dnsbl-1.uceprotect.net', 'UCEPROTECT L1'),
    ('psbl.surriel.com',       'PSBL'),
    ('all.s5h.net',            'S5H'),
]

DOMAIN_DNSBL = [
    ('dbl.spamhaus.org', 'Spamhaus DBL'),
    ('multi.uribl.com',  'URIBL Multi'),
]


class EmailAnalyzer:
    def __init__(self):
        self.timeout = 8

    def analyze(self, domain: str) -> dict:
        domain = re.sub(r'^https?://', '', domain).strip('/').split('/')[0].lower()

        result: dict = {
            'domain': domain,
            'checks': {},
            'score': 0,
        }

        try:
            import dns.resolver  # noqa: F401 — verify availability early

            checks = result['checks']

            # --- sequential DNS checks ---
            checks['mx']    = self._check_mx(domain)
            checks['spf']   = self._check_spf(domain)
            checks['dmarc'] = self._check_dmarc(domain)
            checks['dkim']  = self._check_dkim(domain)

            # --- resolve MX IPs for downstream checks ---
            mx_hosts = [r['host'] for r in checks['mx'].get('records', [])]
            mx_ips   = self._resolve_ips(mx_hosts)

            # --- parallel slow checks ---
            with ThreadPoolExecutor(max_workers=6) as ex:
                bl_fut   = ex.submit(self._check_blacklists, domain, mx_ips)
                ptr_fut  = ex.submit(self._check_ptr, mx_ips)
                tls_futs = {
                    host: ex.submit(self._check_smtp, host)
                    for host in mx_hosts[:3]
                }
                checks['blacklists'] = bl_fut.result()
                checks['ptr']        = ptr_fut.result()
                checks['smtp']       = {
                    host: fut.result() for host, fut in tls_futs.items()
                }

            result['score'] = self._score(checks)

        except ImportError:
            result['error'] = 'dnspython not available'
        except Exception as e:
            logging.error('EmailAnalyzer error for %s: %s', domain, e)
            result['error'] = str(e)

        return result

    # ------------------------------------------------------------------

    def _check_mx(self, domain: str) -> dict:
        r: dict = {'records': [], 'count': 0, 'score': 0, 'issues': []}
        try:
            import dns.resolver
            for rdata in sorted(dns.resolver.resolve(domain, 'MX'),
                                key=lambda x: x.preference):
                r['records'].append({
                    'priority': rdata.preference,
                    'host':     str(rdata.exchange).rstrip('.'),
                })
            r['count'] = len(r['records'])
            if r['count'] == 0:
                r['issues'].append('No MX records — domain cannot receive email')
            elif r['count'] == 1:
                r['score'] = 7
                r['issues'].append('Only one MX server — add a backup for redundancy')
            else:
                r['score'] = 10
        except Exception as e:
            r['issues'].append(f'MX lookup failed: {e}')
        return r

    def _check_spf(self, domain: str) -> dict:
        r: dict = {
            'record': None, 'valid': False, 'policy': None,
            'lookup_count': 0, 'score': 0, 'issues': [],
        }
        try:
            import dns.resolver
            for rdata in dns.resolver.resolve(domain, 'TXT'):
                txt = str(rdata).strip('"')
                if not txt.startswith('v=spf1'):
                    continue
                r['record'] = txt
                r['valid']  = True
                r['score']  = 15

                if txt.endswith('-all'):
                    r['policy'] = 'hardfail'
                elif txt.endswith('~all'):
                    r['policy'] = 'softfail'
                    r['issues'].append(
                        'SPF uses ~all (softfail) — unauthorized senders '
                        'are marked but not rejected; upgrade to -all'
                    )
                    r['score'] -= 3
                elif txt.endswith('?all'):
                    r['policy'] = 'neutral'
                    r['issues'].append('SPF policy is "?all" (neutral) — not enforced')
                    r['score'] -= 8
                elif '+all' in txt:
                    r['policy'] = 'pass_all'
                    r['issues'].append('SPF "+all" allows everyone — effectively useless')
                    r['score'] -= 12

                lookups = len(re.findall(
                    r'\b(?:include|a|mx|ptr|exists):', txt, re.IGNORECASE
                ))
                r['lookup_count'] = lookups
                if lookups > 8:
                    r['issues'].append(
                        f'SPF has {lookups} DNS lookup mechanisms — '
                        'approaching the 10-lookup RFC limit; may cause delivery failures'
                    )
                break
        except Exception:
            pass

        if not r['valid']:
            r['issues'].append('No SPF record — domain can be used to forge email sender addresses')

        r['score'] = max(0, r['score'])
        return r

    def _check_dmarc(self, domain: str) -> dict:
        r: dict = {
            'record': None, 'valid': False,
            'policy': None, 'subdomain_policy': None,
            'pct': 100, 'rua': None, 'ruf': None,
            'adkim': None, 'aspf': None,
            'score': 0, 'issues': [],
        }
        try:
            import dns.resolver
            for rdata in dns.resolver.resolve(f'_dmarc.{domain}', 'TXT'):
                txt = str(rdata).strip('"')
                if not txt.startswith('v=DMARC1'):
                    continue
                r['record'] = txt
                r['valid']  = True
                r['score']  = 5

                def _tag(name):
                    m = re.search(rf'\b{name}=(\S+?)(?:;|$)', txt)
                    return m.group(1) if m else None

                r['policy']           = _tag('p')
                r['subdomain_policy'] = _tag('sp')
                r['adkim']            = _tag('adkim')
                r['aspf']             = _tag('aspf')
                r['rua']              = _tag('rua')
                r['ruf']              = _tag('ruf')

                pct = _tag('pct')
                if pct:
                    r['pct'] = int(pct)
                    if r['pct'] < 100:
                        r['issues'].append(
                            f'pct={r["pct"]} — policy only applies to '
                            f'{r["pct"]}% of messages; set to 100 when ready'
                        )

                if r['policy'] == 'reject':
                    r['score'] += 15
                elif r['policy'] == 'quarantine':
                    r['score'] += 10
                    r['issues'].append(
                        'DMARC p=quarantine — good, but consider upgrading to p=reject '
                        'once you have verified no legitimate mail is failing'
                    )
                else:
                    r['issues'].append(
                        'DMARC p=none — monitoring only, no emails are rejected; '
                        'upgrade to p=quarantine or p=reject'
                    )

                if not r['rua']:
                    r['issues'].append(
                        'No rua= address — you will not receive aggregate DMARC reports'
                    )
                break
        except Exception:
            pass

        if not r['valid']:
            r['issues'].append('No DMARC record — email spoofing policy not configured')

        r['score'] = max(0, r['score'])
        return r

    def _check_dkim(self, domain: str) -> dict:
        r: dict = {'selectors_found': [], 'valid': False, 'score': 0, 'issues': []}

        def _try(selector):
            try:
                import dns.resolver
                for rdata in dns.resolver.resolve(
                    f'{selector}._domainkey.{domain}', 'TXT'
                ):
                    txt = str(rdata).strip('"')
                    if 'v=DKIM1' not in txt and 'p=' not in txt:
                        continue
                    key_bits = None
                    pm = re.search(r'p=([A-Za-z0-9+/=]+)', txt)
                    if pm and pm.group(1):
                        try:
                            key_bits = len(base64.b64decode(pm.group(1) + '==')) * 8
                        except Exception:
                            pass
                    return {'selector': selector, 'key_bits': key_bits}
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(_try, s): s for s in COMMON_DKIM_SELECTORS}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    r['selectors_found'].append(res)
                    r['valid'] = True
                    if res['key_bits'] and res['key_bits'] < 1024:
                        r['issues'].append(
                            f'DKIM key "{res["selector"]}" is {res["key_bits"]} bits — '
                            'upgrade to ≥2048 bits'
                        )

        if r['valid']:
            r['score'] = 15
        else:
            r['issues'].append(
                f'No DKIM key found for {len(COMMON_DKIM_SELECTORS)} common selectors — '
                'DKIM may use a custom selector not checked here'
            )
        return r

    def _resolve_ips(self, hosts: list) -> dict:
        ips: dict = {}
        for host in hosts[:5]:
            try:
                ips[host] = socket.gethostbyname(host)
            except Exception:
                pass
        return ips

    def _check_blacklists(self, domain: str, mx_ips: dict) -> dict:
        r: dict = {
            'ip_results': {},
            'domain_results': [],
            'listed_count': 0,
            'score': 20,
            'issues': [],
        }

        def _check_ip(host, ip):
            rev = '.'.join(reversed(ip.split('.')))
            listed = []
            clean  = []
            for suffix, name in IP_DNSBL:
                try:
                    import dns.resolver
                    dns.resolver.resolve(f'{rev}.{suffix}', 'A')
                    listed.append(name)
                except Exception:
                    clean.append(name)
            return host, ip, listed, clean

        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = [ex.submit(_check_ip, h, ip) for h, ip in mx_ips.items()]
            for fut in as_completed(futs):
                host, ip, listed, clean = fut.result()
                r['ip_results'][host] = {'ip': ip, 'listed': listed, 'clean': clean}
                if listed:
                    r['listed_count'] += len(listed)
                    r['score'] -= 3 * len(listed)
                    r['issues'].append(
                        f'{ip} ({host}) listed on: {", ".join(listed)}'
                    )

        try:
            import dns.resolver
            for suffix, name in DOMAIN_DNSBL:
                try:
                    dns.resolver.resolve(f'{domain}.{suffix}', 'A')
                    r['domain_results'].append(name)
                    r['score'] -= 4
                    r['issues'].append(f'Domain listed on {name}')
                except Exception:
                    pass
        except Exception:
            pass

        r['score'] = max(0, r['score'])
        return r

    def _check_ptr(self, mx_ips: dict) -> dict:
        r: dict = {'records': {}, 'missing': [], 'score': 0, 'issues': []}
        found = 0
        for host, ip in mx_ips.items():
            try:
                ptr = socket.gethostbyaddr(ip)[0]
                r['records'][host] = {'ip': ip, 'ptr': ptr}
                found += 1
            except Exception:
                r['records'][host] = {'ip': ip, 'ptr': None}
                r['missing'].append(host)
                r['issues'].append(
                    f'No PTR record for {ip} ({host}) — '
                    'many mail servers reject senders without reverse DNS'
                )
        total = len(mx_ips)
        if total:
            r['score'] = round(found / total * 10)
        return r

    def _check_smtp(self, host: str) -> dict:
        r: dict = {
            'reachable': False, 'banner': None,
            'starttls': False, 'issues': [],
        }
        try:
            sock = socket.create_connection((host, 25), timeout=self.timeout)
            r['banner'] = sock.recv(1024).decode(errors='replace').strip()[:150]
            r['reachable'] = True
            sock.sendall(b'EHLO securitybuddy.scanner\r\n')
            ehlo = sock.recv(4096).decode(errors='replace')
            r['starttls'] = 'STARTTLS' in ehlo
            sock.sendall(b'QUIT\r\n')
            sock.close()
            if not r['starttls']:
                r['issues'].append(
                    f'{host}:25 does not advertise STARTTLS — '
                    'server-to-server email may travel unencrypted'
                )
        except Exception as e:
            r['issues'].append(f'Cannot connect to {host}:25 — {e}')
        return r

    def _score(self, checks: dict) -> int:
        total = 0
        total += min(checks.get('mx',          {}).get('score',  0), 10)
        total += min(checks.get('spf',         {}).get('score',  0), 15)
        total += min(checks.get('dmarc',       {}).get('score',  0), 20)
        total += min(checks.get('dkim',        {}).get('score',  0), 15)
        total += min(checks.get('blacklists',  {}).get('score', 20), 20)
        total += min(checks.get('ptr',         {}).get('score',  0), 10)

        # +10 bonus if all checked MX servers support STARTTLS
        smtp = checks.get('smtp', {})
        if smtp and all(v.get('starttls') for v in smtp.values()):
            total += 10

        return min(max(total, 0), 100)
