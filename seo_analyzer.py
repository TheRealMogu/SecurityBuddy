import re
import json
import time
import requests
from urllib.parse import urlparse
from html.parser import HTMLParser


class _SEOHTMLParser(HTMLParser):
    """SAX-style parser extracting SEO-relevant elements from raw HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = None
        self.meta = {}
        self.headings = {'h1': [], 'h2': [], 'h3': []}
        self.images = []
        self.links = []
        self.canonical = None
        self.open_graph = {}
        self.twitter = {}
        self.json_ld = []
        self.hreflang = []

        self._in_title = False
        self._current_heading = None
        self._in_script = False
        self._script_type = None
        self._buf = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == 'title':
            self._in_title = True
            self._buf = []
            return

        if tag == 'meta':
            name = attrs.get('name', '').lower()
            prop = attrs.get('property', '').lower()
            content = attrs.get('content', '')
            if name:
                self.meta[name] = content
            if prop.startswith('og:'):
                self.open_graph[prop[3:]] = content
            key = prop or name
            if key.startswith('twitter:'):
                self.twitter[key[8:]] = content
            return

        if tag == 'link':
            rel = attrs.get('rel', '').lower()
            href = attrs.get('href', '')
            if rel == 'canonical':
                self.canonical = href
            elif rel == 'alternate' and attrs.get('hreflang'):
                self.hreflang.append({'hreflang': attrs['hreflang'], 'href': href})
            return

        if tag in ('h1', 'h2', 'h3'):
            self._current_heading = tag
            self._buf = []
            return

        if tag == 'img':
            self.images.append({
                'src': attrs.get('src', ''),
                'alt': attrs.get('alt'),
                'loading': attrs.get('loading', ''),
            })
            return

        if tag == 'a':
            href = attrs.get('href', '')
            if href:
                self.links.append({'href': href, 'rel': attrs.get('rel', '')})
            return

        if tag == 'script':
            self._in_script = True
            self._script_type = attrs.get('type', '')
            self._buf = []

    def handle_endtag(self, tag):
        if tag == 'title' and self._in_title:
            self.title = ''.join(self._buf).strip()
            self._in_title = False
            self._buf = []
            return

        if tag in ('h1', 'h2', 'h3') and self._current_heading == tag:
            text = ' '.join(''.join(self._buf).split())
            if text:
                self.headings[tag].append(text)
            self._current_heading = None
            self._buf = []
            return

        if tag == 'script' and self._in_script:
            if 'application/ld+json' in (self._script_type or ''):
                raw = ''.join(self._buf).strip()
                if raw:
                    try:
                        parsed = json.loads(raw)
                        if isinstance(parsed, list):
                            self.json_ld.extend(parsed)
                        else:
                            self.json_ld.append(parsed)
                    except Exception:
                        pass
            self._in_script = False
            self._script_type = None
            self._buf = []

    def handle_data(self, data):
        if self._in_title or self._current_heading or self._in_script:
            self._buf.append(data)


class SEOAnalyzer:
    """High-level + detailed SEO analysis via direct HTTP requests."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            )
        })
        self.timeout = 15

    def analyze(self, target: str) -> dict:
        if not target.startswith(('http://', 'https://')):
            base_url = f'https://{target}'
        else:
            base_url = target

        result = {
            'score': 0,
            'rating': 'unknown',
            'checks': {},
        }

        try:
            t0 = time.monotonic()
            response = self.session.get(base_url, timeout=self.timeout, allow_redirects=True)
            load_ms = round((time.monotonic() - t0) * 1000)

            ct = response.headers.get('Content-Type', '')
            if 'html' not in ct.lower():
                result['error'] = f'Non-HTML response ({ct})'
                return result

            parser = _SEOHTMLParser()
            try:
                parser.feed(response.text[:500_000])
            except Exception:
                pass

            result['checks']['meta']           = self._check_meta(parser)
            result['checks']['headings']        = self._check_headings(parser)
            result['checks']['images']          = self._check_images(parser)
            result['checks']['links']           = self._check_links(parser, base_url)
            result['checks']['technical']       = self._check_technical(parser, response, load_ms)
            result['checks']['social']          = self._check_social(parser)
            result['checks']['structured_data'] = self._check_structured_data(parser)
            result['checks']['robots_txt']      = self._check_robots_txt(base_url)
            result['checks']['sitemap']         = self._check_sitemap(base_url)

            result['score']  = self._calculate_score(result['checks'])
            result['rating'] = self._rating(result['score'])

        except requests.exceptions.RequestException as e:
            result['error'] = str(e)

        return result

    # ── Individual checks ─────────────────────────────────────────────

    def _check_meta(self, parser: _SEOHTMLParser) -> dict:
        r = {
            'title':              parser.title,
            'title_length':       len(parser.title) if parser.title else 0,
            'description':        parser.meta.get('description'),
            'description_length': len(parser.meta.get('description', '')),
            'canonical':          parser.canonical,
            'noindex':            False,
            'nofollow_meta':      False,
            'score':              0,
            'issues':             [],
            'warnings':           [],
            'passed':             [],
        }

        title = parser.title
        if not title:
            r['issues'].append('Missing <title> tag — critical ranking signal, affects click-through rate')
        elif len(title) < 30:
            r['warnings'].append(f'Title too short ({len(title)} chars) — aim for 50–60 characters for best SERP display')
            r['score'] += 6
        elif len(title) > 60:
            r['warnings'].append(f'Title too long ({len(title)} chars) — will be truncated in search results, aim for 50–60 chars')
            r['score'] += 8
        else:
            r['passed'].append(f'Title length optimal ({len(title)} chars)')
            r['score'] += 12

        desc = parser.meta.get('description', '')
        if not desc:
            r['issues'].append('Missing meta description — Google may generate an unhelpful snippet')
        elif len(desc) < 120:
            r['warnings'].append(f'Meta description short ({len(desc)} chars) — aim for 150–160 characters')
            r['score'] += 5
        elif len(desc) > 160:
            r['warnings'].append(f'Meta description too long ({len(desc)} chars) — will be truncated in SERPs, aim for 150–160 chars')
            r['score'] += 6
        else:
            r['passed'].append(f'Meta description length optimal ({len(desc)} chars)')
            r['score'] += 10

        if parser.canonical:
            r['passed'].append(f'Canonical URL set')
            r['score'] += 3
        else:
            r['warnings'].append('No canonical URL — risk of duplicate content penalties')

        robots = parser.meta.get('robots', '').lower()
        if 'noindex' in robots:
            r['noindex'] = True
            r['issues'].append('Page is set to noindex — it will NOT appear in search results')
        if 'nofollow' in robots:
            r['nofollow_meta'] = True
            r['warnings'].append('Page has nofollow meta — links will not be followed by crawlers')

        return r

    def _check_headings(self, parser: _SEOHTMLParser) -> dict:
        h1s = parser.headings.get('h1', [])
        h2s = parser.headings.get('h2', [])
        h3s = parser.headings.get('h3', [])

        r = {
            'h1_count': len(h1s),
            'h1_text':  h1s[0][:80] if h1s else None,
            'h2_count': len(h2s),
            'h3_count': len(h3s),
            'score':    0,
            'issues':   [],
            'warnings': [],
            'passed':   [],
        }

        if len(h1s) == 0:
            r['issues'].append('No H1 tag — primary keyword-bearing heading is missing')
        elif len(h1s) == 1:
            r['passed'].append(f'Single H1: "{h1s[0][:60]}"')
            r['score'] += 10
        else:
            r['warnings'].append(f'{len(h1s)} H1 tags detected — use exactly one H1 per page')
            r['score'] += 4

        if h2s:
            r['passed'].append(f'{len(h2s)} H2 heading(s) — good content hierarchy')
            r['score'] += 5
        else:
            r['warnings'].append('No H2 headings — add sub-headings to improve readability and keyword signals')

        if h3s:
            r['passed'].append(f'{len(h3s)} H3 heading(s) found')

        return r

    def _check_images(self, parser: _SEOHTMLParser) -> dict:
        images      = parser.images
        missing_alt = [img for img in images if img['alt'] is None]
        empty_alt   = [img for img in images if img['alt'] == '']
        lazy        = [img for img in images if img.get('loading') == 'lazy']

        r = {
            'total':        len(images),
            'missing_alt':  len(missing_alt),
            'empty_alt':    len(empty_alt),
            'lazy_loading': len(lazy),
            'score':        0,
            'issues':       [],
            'warnings':     [],
            'passed':       [],
        }

        if not images:
            r['score'] += 5
            r['passed'].append('No images to evaluate')
        elif not missing_alt:
            r['passed'].append(f'All {len(images)} image(s) have alt attributes')
            r['score'] += 10
        else:
            pct = round(len(missing_alt) / len(images) * 100)
            r['issues'].append(
                f'{len(missing_alt)}/{len(images)} images ({pct}%) lack alt text — hurts image search rankings and accessibility'
            )
            r['score'] += max(0, 10 - len(missing_alt) * 2)

        if lazy and len(images) > 3:
            r['passed'].append(f'{len(lazy)} image(s) use lazy loading')

        return r

    def _check_links(self, parser: _SEOHTMLParser, base_url: str) -> dict:
        base_netloc = urlparse(base_url).netloc
        internal, external, nofollow = [], [], []

        for link in parser.links:
            href = link['href']
            rel  = link.get('rel', '')
            if not href or href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                continue
            if href.startswith('http'):
                if urlparse(href).netloc == base_netloc:
                    internal.append(href)
                else:
                    external.append(href)
            elif href.startswith('/'):
                internal.append(href)
            if 'nofollow' in rel:
                nofollow.append(href)

        r = {
            'total':    len(parser.links),
            'internal': len(internal),
            'external': len(external),
            'nofollow': len(nofollow),
            'score':    0,
            'issues':   [],
            'warnings': [],
            'passed':   [],
        }

        if internal:
            r['passed'].append(f'{len(internal)} internal link(s) — supports crawler discovery')
            r['score'] += 5
        else:
            r['warnings'].append('No internal links found — crawlers may not discover other pages')

        if external:
            r['passed'].append(f'{len(external)} external link(s)')

        return r

    def _check_technical(self, parser: _SEOHTMLParser, response, load_ms: int) -> dict:
        enc = response.headers.get('Content-Encoding') or None
        r = {
            'load_time_ms': load_ms,
            'page_size_kb': round(len(response.content) / 1024, 1),
            'compression':  enc,
            'viewport':     bool(parser.meta.get('viewport')),
            'score':        0,
            'issues':       [],
            'warnings':     [],
            'passed':       [],
        }

        if r['viewport']:
            r['passed'].append('Viewport meta tag present — mobile-friendly')
            r['score'] += 5
        else:
            r['issues'].append('Missing viewport meta tag — page may not be mobile-friendly, negatively affects mobile rankings')

        if enc in ('gzip', 'br', 'deflate', 'zstd'):
            r['passed'].append(f'Content compression enabled ({enc})')
            r['score'] += 5
        else:
            r['warnings'].append('No content compression (gzip/brotli) — larger transfer size hurts load speed')

        ms = load_ms
        if ms < 500:
            r['passed'].append(f'Excellent server response time ({ms} ms)')
            r['score'] += 10
        elif ms < 1500:
            r['passed'].append(f'Good server response time ({ms} ms)')
            r['score'] += 7
        elif ms < 3000:
            r['warnings'].append(f'Slow server response ({ms} ms) — aim for under 1,500 ms')
            r['score'] += 3
        else:
            r['issues'].append(f'Very slow server response ({ms} ms) — Core Web Vitals will suffer, ranking signal affected')

        kb = r['page_size_kb']
        if 0 < kb <= 2000:
            r['passed'].append(f'Page size reasonable ({kb} KB)')
        elif kb > 2000:
            r['warnings'].append(f'Large page size ({kb} KB) — split resources to improve load performance')

        return r

    def _check_social(self, parser: _SEOHTMLParser) -> dict:
        og = parser.open_graph
        tw = parser.twitter

        r = {
            'og_title':       og.get('title'),
            'og_description': og.get('description'),
            'og_image':       og.get('image'),
            'og_type':        og.get('type'),
            'twitter_card':   tw.get('card'),
            'twitter_title':  tw.get('title'),
            'twitter_image':  tw.get('image'),
            'score':          0,
            'issues':         [],
            'warnings':       [],
            'passed':         [],
        }

        present = [k for k in ('title', 'description', 'image') if og.get(k)]
        if len(present) == 3:
            r['passed'].append('Full Open Graph set (og:title, og:description, og:image)')
            r['score'] += 8
        elif present:
            missing = [k for k in ('title', 'description', 'image') if not og.get(k)]
            r['warnings'].append(f'Incomplete Open Graph — missing: og:{", og:".join(missing)}')
            r['score'] += 3
        else:
            r['warnings'].append('No Open Graph tags — social shares will lack rich image/description previews')

        if tw.get('card'):
            r['passed'].append(f'Twitter/X Card present ({tw["card"]})')
            r['score'] += 4
        else:
            r['warnings'].append('No Twitter Card meta tags — links shared on X will not show rich previews')

        return r

    def _check_structured_data(self, parser: _SEOHTMLParser) -> dict:
        items = parser.json_ld
        types = []
        for item in items:
            if isinstance(item, dict):
                t = item.get('@type')
                if isinstance(t, str):
                    types.append(t)
                elif isinstance(t, list):
                    types.extend(str(x) for x in t)

        r = {
            'json_ld_count':  len(items),
            'schema_types':   types,
            'hreflang_count': len(parser.hreflang),
            'score':          0,
            'issues':         [],
            'warnings':       [],
            'passed':         [],
        }

        if items:
            type_str = ', '.join(types) if types else 'present'
            r['passed'].append(f'JSON-LD structured data: {type_str}')
            r['score'] += 3
        else:
            r['warnings'].append('No JSON-LD structured data — add Schema.org markup to enable rich results (reviews, FAQs, breadcrumbs…)')

        if parser.hreflang:
            r['passed'].append(f'{len(parser.hreflang)} hreflang tag(s) — international SEO configured')

        return r

    def _check_robots_txt(self, base_url: str) -> dict:
        parsed     = urlparse(base_url)
        robots_url = f'{parsed.scheme}://{parsed.netloc}/robots.txt'

        r = {
            'present':          False,
            'sitemap_declared': False,
            'disallow_count':   0,
            'url':              robots_url,
            'score':            0,
            'issues':           [],
            'warnings':         [],
            'passed':           [],
        }

        try:
            resp = self.session.get(robots_url, timeout=8, allow_redirects=False)
            ct   = resp.headers.get('Content-Type', '')
            body = resp.text

            if resp.status_code == 200 and (
                'text' in ct
                or body.strip()[:12].lower().startswith(('user-agent', '#', 'sitemap'))
            ):
                r['present'] = True
                disallows = [l for l in body.splitlines() if re.match(r'(?i)disallow\s*:', l)]
                r['disallow_count'] = len(disallows)

                if re.search(r'(?im)^sitemap\s*:', body):
                    r['sitemap_declared'] = True
                    r['passed'].append('Sitemap URL declared in robots.txt')

                r['passed'].append(f'robots.txt present ({len(disallows)} Disallow rule(s))')
                r['score'] += 5

                # Detect blanket block: User-agent: * + Disallow: /
                ua_star = False
                for line in body.splitlines():
                    stripped = line.strip()
                    if re.match(r'(?i)^user-agent\s*:\s*\*', stripped):
                        ua_star = True
                    elif ua_star and re.match(r'(?i)^disallow\s*:\s*/$', stripped):
                        r['issues'].append(
                            'robots.txt blocks all crawlers (Disallow: /) — site will be excluded from all search engines'
                        )
                        break
                    elif ua_star and stripped and not stripped.startswith('#'):
                        ua_star = False
            else:
                r['warnings'].append('robots.txt not found — recommended for managing crawler access')

        except Exception as e:
            r['warnings'].append(f'robots.txt check failed: {str(e)}')

        return r

    def _check_sitemap(self, base_url: str) -> dict:
        parsed = urlparse(base_url)
        origin = f'{parsed.scheme}://{parsed.netloc}'

        r = {
            'present':   False,
            'url':       None,
            'url_count': 0,
            'score':     0,
            'issues':    [],
            'warnings':  [],
            'passed':    [],
        }

        for candidate in (
            f'{origin}/sitemap.xml',
            f'{origin}/sitemap_index.xml',
            f'{origin}/sitemap-index.xml',
        ):
            try:
                resp = self.session.get(candidate, timeout=8, allow_redirects=False)
                if resp.status_code == 200:
                    body = resp.text[:200_000]
                    if '<' in body and ('loc>' in body or 'urlset' in body or 'sitemapindex' in body):
                        r['present']   = True
                        r['url']       = candidate
                        r['url_count'] = body.count('<loc>')
                        r['passed'].append(f'XML sitemap found ({r["url_count"]} URL(s))')
                        r['score'] += 10
                        break
            except Exception:
                continue

        if not r['present']:
            r['warnings'].append('XML sitemap not found at /sitemap.xml — helps search engines discover all pages')

        return r

    # ── Score aggregation ─────────────────────────────────────────────

    def _calculate_score(self, checks: dict) -> int:
        # Max contributions: meta 25 + headings 15 + images 10 + links 5
        #                    + technical 20 + social 12 + structured 5
        #                    + robots 5 + sitemap 10 = 107 raw → capped at 100
        total = (
            min(checks.get('meta',           {}).get('score', 0), 25) +
            min(checks.get('headings',        {}).get('score', 0), 15) +
            min(checks.get('images',          {}).get('score', 0), 10) +
            min(checks.get('links',           {}).get('score', 0),  5) +
            min(checks.get('technical',       {}).get('score', 0), 20) +
            min(checks.get('social',          {}).get('score', 0), 12) +
            min(checks.get('structured_data', {}).get('score', 0),  5) +
            min(checks.get('robots_txt',      {}).get('score', 0),  5) +
            min(checks.get('sitemap',         {}).get('score', 0), 10)
        )
        return min(max(total, 0), 100)

    def _rating(self, score: int) -> str:
        if score >= 80:
            return 'excellent'
        if score >= 60:
            return 'good'
        if score >= 40:
            return 'needs_work'
        return 'poor'
