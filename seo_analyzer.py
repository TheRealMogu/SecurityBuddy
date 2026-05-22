import re
import json
import time
import requests
from urllib.parse import urlparse
from html.parser import HTMLParser

# Tags whose text content should be excluded from the body word count
_TEXT_SKIP = {'script', 'style', 'noscript', 'nav', 'footer', 'aside', 'header'}


class _SEOHTMLParser(HTMLParser):
    """SAX-style parser that extracts every SEO-relevant element in one pass."""

    def __init__(self):
        super().__init__(convert_charrefs=True)

        # ── Document-level ─────────────────────────────────────────────
        self.html_lang   = None   # <html lang="...">
        self.charset     = None   # <meta charset> or Content-Type

        # ── <head> metadata ────────────────────────────────────────────
        self.title       = None
        self.meta        = {}     # name → content
        self.canonical   = None
        self.open_graph  = {}     # og:* → content
        self.twitter     = {}     # twitter:* → content
        self.json_ld     = []     # parsed JSON-LD objects
        self.hreflang    = []     # [{hreflang, href}, …]
        self.favicon_href = None
        self.amp_url     = None
        self.pagination  = {'prev': None, 'next': None}

        # ── Body structure ──────────────────────────────────────────────
        self.headings    = {'h1': [], 'h2': [], 'h3': []}
        self.images      = []     # {src, alt, loading, width, height}
        self.links       = []     # {href, rel}
        self.has_microdata = False

        # ── Resources ──────────────────────────────────────────────────
        self.scripts      = []    # external JS src values
        self.stylesheets  = []    # external CSS href values
        self.inline_scripts = 0

        # ── Body text (for word count) ──────────────────────────────────
        self._body_parts  = []
        self._in_body     = False
        self._skip_depth  = 0    # depth inside _TEXT_SKIP tags

        # ── Internal parse state ────────────────────────────────────────
        self._in_title    = False
        self._current_heading = None
        self._in_script   = False
        self._script_type = None
        self._buf         = []

    # ── Event handlers ─────────────────────────────────────────────────

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == 'html':
            self.html_lang = attrs.get('lang') or attrs.get('xml:lang')
            return

        if tag == 'body':
            self._in_body = True
            return

        if attrs.get('itemscope') is not None:
            self.has_microdata = True

        # ── Skip-tag bookkeeping ────────────────────────────────────────
        if tag in _TEXT_SKIP:
            self._skip_depth += 1

            if tag == 'script':
                self._script_type = attrs.get('type', '')
                src = attrs.get('src')
                if src:
                    self.scripts.append(src)
                    self._in_script = False
                else:
                    self.inline_scripts += 1
                    self._in_script = True
                    self._buf = []
            return

        # ── Title ───────────────────────────────────────────────────────
        if tag == 'title':
            self._in_title = True
            self._buf = []
            return

        # ── Meta ────────────────────────────────────────────────────────
        if tag == 'meta':
            name    = attrs.get('name', '').lower()
            prop    = attrs.get('property', '').lower()
            content = attrs.get('content', '')
            charset = attrs.get('charset')

            if charset:
                self.charset = charset
            elif 'charset=' in content.lower():
                m = re.search(r'charset=([\w-]+)', content, re.I)
                if m:
                    self.charset = m.group(1)

            if name:
                self.meta[name] = content
            if prop.startswith('og:'):
                self.open_graph[prop[3:]] = content
            key = prop or name
            if key.startswith('twitter:'):
                self.twitter[key[8:]] = content
            return

        # ── Link ────────────────────────────────────────────────────────
        if tag == 'link':
            rel  = attrs.get('rel', '').lower()
            href = attrs.get('href', '')
            if rel == 'canonical':
                self.canonical = href
            elif rel == 'alternate' and attrs.get('hreflang'):
                self.hreflang.append({'hreflang': attrs['hreflang'], 'href': href})
            elif rel == 'amphtml':
                self.amp_url = href
            elif rel in ('prev', 'previous'):
                self.pagination['prev'] = href
            elif rel == 'next':
                self.pagination['next'] = href
            elif 'icon' in rel and not self.favicon_href:
                self.favicon_href = href
            elif rel == 'stylesheet' and href:
                self.stylesheets.append(href)
            return

        # ── Headings ────────────────────────────────────────────────────
        if tag in ('h1', 'h2', 'h3'):
            self._current_heading = tag
            self._buf = []
            return

        # ── Images ──────────────────────────────────────────────────────
        if tag == 'img':
            self.images.append({
                'src':    attrs.get('src', ''),
                'alt':    attrs.get('alt'),        # None = attr absent, '' = empty
                'loading': attrs.get('loading', ''),
                'width':  attrs.get('width'),
                'height': attrs.get('height'),
            })
            return

        # ── Links ───────────────────────────────────────────────────────
        if tag == 'a':
            href = attrs.get('href', '')
            if href:
                self.links.append({'href': href, 'rel': attrs.get('rel', '')})

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

        if tag in _TEXT_SKIP:
            self._skip_depth = max(0, self._skip_depth - 1)
            if tag == 'script' and self._in_script:
                if 'application/ld+json' in (self._script_type or ''):
                    raw = ''.join(self._buf).strip()
                    if raw:
                        try:
                            parsed = json.loads(raw)
                            (self.json_ld.extend if isinstance(parsed, list) else self.json_ld.append)(parsed)
                        except Exception:
                            pass
                self._in_script = False
                self._script_type = None
                self._buf = []

    def handle_data(self, data):
        if self._in_title or self._current_heading:
            self._buf.append(data)
        elif self._in_script:
            self._buf.append(data)
        elif self._in_body and self._skip_depth == 0:
            self._body_parts.append(data)

    @property
    def word_count(self) -> int:
        return len([w for w in re.split(r'\s+', ' '.join(self._body_parts)) if w.strip()])


# ══════════════════════════════════════════════════════════════════════════
# SEOAnalyzer
# ══════════════════════════════════════════════════════════════════════════

class SEOAnalyzer:
    """
    12-check SEO analyzer using only direct HTTP requests.
    No headless browser required; covers everything detectable from raw HTML.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            ),
            'Accept-Language': 'en-US,en;q=0.9',
        })
        self.timeout = 15

    def analyze(self, target: str) -> dict:
        if not target.startswith(('http://', 'https://')):
            base_url = f'https://{target}'
        else:
            base_url = target

        result = {'score': 0, 'rating': 'unknown', 'checks': {}}

        try:
            t0 = time.monotonic()
            response = self.session.get(base_url, timeout=self.timeout, allow_redirects=True)
            load_ms  = round((time.monotonic() - t0) * 1000)

            ct = response.headers.get('Content-Type', '')
            if 'html' not in ct.lower():
                result['error'] = f'Non-HTML response ({ct})'
                return result

            parser = _SEOHTMLParser()
            try:
                parser.feed(response.text[:500_000])
            except Exception:
                pass

            # ── Run all checks ──────────────────────────────────────────
            result['checks']['url']            = self._check_url(base_url, response)
            result['checks']['meta']           = self._check_meta(parser, response)
            result['checks']['content']        = self._check_content(parser)
            result['checks']['headings']       = self._check_headings(parser)
            result['checks']['images']         = self._check_images(parser)
            result['checks']['links']          = self._check_links(parser, base_url)
            result['checks']['technical']      = self._check_technical(parser, response, load_ms)
            result['checks']['resources']      = self._check_resources(parser)
            result['checks']['social']         = self._check_social(parser)
            result['checks']['structured_data'] = self._check_structured_data(parser)
            result['checks']['robots_txt']     = self._check_robots_txt(base_url)
            result['checks']['sitemap']        = self._check_sitemap(base_url)

            result['score']  = self._calculate_score(result['checks'])
            result['rating'] = self._rating(result['score'])

        except requests.exceptions.RequestException as e:
            result['error'] = str(e)

        return result

    # ── Check: URL structure & redirect chain ──────────────────────────

    def _check_url(self, base_url: str, response) -> dict:
        parsed    = urlparse(response.url)
        path      = parsed.path
        redirects = len(response.history)

        r = {
            'original_url':   base_url,
            'final_url':      response.url,
            'redirect_count': redirects,
            'redirect_chain': [{'url': h.url, 'status': h.status_code} for h in response.history],
            'url_length':     len(response.url),
            'has_underscores': '_' in path,
            'has_uppercase':  path != path.lower(),
            'has_query_params': bool(parsed.query),
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        # Redirect chain
        if redirects == 0:
            r['passed'].append('No redirects — URL resolves directly')
            r['score'] += 4
        elif redirects == 1:
            h = response.history[0]
            r['passed'].append(f'Single redirect ({h.status_code}) — acceptable')
            r['score'] += 3
        elif redirects == 2:
            r['warnings'].append(f'{redirects} redirects in chain — aim for 1 max to preserve crawl budget')
            r['score'] += 1
        else:
            r['issues'].append(
                f'{redirects} redirects in chain — critically impacts crawl budget and adds latency; '
                'fix to a single hop'
            )

        # URL length
        if r['url_length'] <= 75:
            r['passed'].append(f'URL length good ({r["url_length"]} chars)')
            r['score'] += 2
        elif r['url_length'] <= 115:
            r['warnings'].append(f'URL somewhat long ({r["url_length"]} chars) — aim for under 75 chars')
            r['score'] += 1
        else:
            r['warnings'].append(f'URL too long ({r["url_length"]} chars) — may be truncated in SERPs')

        # Underscores in path
        if '_' in path:
            r['warnings'].append(
                'Underscores in URL path — use hyphens (-) instead; Google treats underscores as word joiners, '
                'not separators'
            )
        else:
            r['score'] += 2

        # Uppercase
        if path != path.lower():
            r['warnings'].append(
                'Uppercase letters in URL — can cause duplicate content if server is case-sensitive; '
                'prefer all-lowercase URLs'
            )
        else:
            r['score'] += 2

        return r

    # ── Check: Meta tags ───────────────────────────────────────────────

    def _check_meta(self, parser: _SEOHTMLParser, response=None) -> dict:
        r = {
            'title':              parser.title,
            'title_length':       len(parser.title) if parser.title else 0,
            'description':        parser.meta.get('description'),
            'description_length': len(parser.meta.get('description', '')),
            'canonical':          parser.canonical,
            'noindex':            False,
            'nofollow_meta':      False,
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        # Title
        title = parser.title
        if not title:
            r['issues'].append(
                'Missing <title> tag — the single most important on-page SEO element; '
                'directly affects rankings and click-through rate in SERPs'
            )
        elif len(title) < 30:
            r['warnings'].append(
                f'Title too short ({len(title)} chars) — aim for 50–60 chars; '
                'short titles waste ranking keyword space'
            )
            r['score'] += 6
        elif len(title) > 60:
            r['warnings'].append(
                f'Title too long ({len(title)} chars) — Google truncates at ~60 chars in SERPs; '
                'aim for 50–60 chars'
            )
            r['score'] += 8
        else:
            r['passed'].append(f'Title length optimal ({len(title)} chars): "{title[:55]}"')
            r['score'] += 12

        # Meta description
        desc = parser.meta.get('description', '')
        if not desc:
            r['issues'].append(
                'Missing meta description — Google may auto-generate an unhelpful snippet, '
                'reducing click-through rate'
            )
        elif len(desc) < 120:
            r['warnings'].append(
                f'Meta description short ({len(desc)} chars) — aim for 150–160 chars to fill the SERP snippet'
            )
            r['score'] += 5
        elif len(desc) > 160:
            r['warnings'].append(
                f'Meta description too long ({len(desc)} chars) — truncated in SERPs after ~160 chars'
            )
            r['score'] += 7
        else:
            r['passed'].append(f'Meta description optimal ({len(desc)} chars)')
            r['score'] += 10

        # Canonical
        if parser.canonical:
            r['passed'].append(f'Canonical URL declared')
            r['score'] += 3
        else:
            r['warnings'].append(
                'No canonical URL — risk of duplicate content penalties; '
                'add <link rel="canonical" href="..."> even on unique pages'
            )

        # robots meta
        robots = parser.meta.get('robots', '').lower()
        if 'noindex' in robots:
            r['noindex'] = True
            r['issues'].append('robots meta: noindex — this page will NOT appear in any search engine')
        if 'nofollow' in robots:
            r['nofollow_meta'] = True
            r['warnings'].append('robots meta: nofollow — search engines will not follow links on this page')

        # X-Robots-Tag header (overrides meta robots)
        if response:
            xr = response.headers.get('X-Robots-Tag', '').lower()
            if 'noindex' in xr:
                r['issues'].append(f'X-Robots-Tag header: noindex — page blocked from indexing via HTTP header (overrides meta robots)')
            elif 'nofollow' in xr:
                r['warnings'].append(f'X-Robots-Tag header: nofollow')
            elif xr:
                r['passed'].append(f'X-Robots-Tag: {xr}')

        return r

    # ── Check: Content quality ─────────────────────────────────────────

    def _check_content(self, parser: _SEOHTMLParser) -> dict:
        wc      = parser.word_count
        is_spa  = wc < 50 and len(parser.scripts) > 3

        r = {
            'word_count': wc,
            'language':   parser.html_lang,
            'charset':    parser.charset,
            'is_spa':     is_spa,
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        # SPA detection
        if is_spa:
            r['warnings'].append(
                'Page appears to be a Single Page Application (SPA) — '
                'search engines may not execute JavaScript and will see little/no content; '
                'consider Server-Side Rendering (SSR) or pre-rendering'
            )

        # Word count (skip SPA penalty)
        if not is_spa:
            if wc < 100:
                r['issues'].append(
                    f'Extremely thin content ({wc} words) — Google penalises near-empty pages; '
                    'add meaningful textual content'
                )
                r['score'] += 1
            elif wc < 300:
                r['warnings'].append(
                    f'Low word count ({wc} words) — thin content risk; '
                    'aim for 300+ words minimum, 600+ for informational pages'
                )
                r['score'] += 3
            elif wc < 600:
                r['passed'].append(f'Acceptable content length ({wc} words)')
                r['score'] += 6
            else:
                r['passed'].append(f'Good content length ({wc} words)')
                r['score'] += 8

        # Language attribute
        if parser.html_lang:
            r['passed'].append(f'Language declared: lang="{parser.html_lang}"')
            r['score'] += 4
        else:
            r['warnings'].append(
                'No lang attribute on <html> element — '
                'declare the page language (e.g. <html lang="en">) '
                'for correct language detection by search engines and screen readers'
            )

        # Charset
        if parser.charset:
            r['passed'].append(f'Charset declared: {parser.charset}')
            r['score'] += 2
        else:
            r['warnings'].append(
                'No charset declaration — add <meta charset="UTF-8"> '
                'as the first element inside <head> to prevent encoding issues'
            )

        return r

    # ── Check: Heading structure ───────────────────────────────────────

    def _check_headings(self, parser: _SEOHTMLParser) -> dict:
        h1s = parser.headings.get('h1', [])
        h2s = parser.headings.get('h2', [])
        h3s = parser.headings.get('h3', [])

        r = {
            'h1_count': len(h1s),
            'h1_text':  h1s[0][:80] if h1s else None,
            'h2_count': len(h2s),
            'h3_count': len(h3s),
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        if len(h1s) == 0:
            r['issues'].append(
                'No H1 tag — primary topic signal missing; '
                'every page should have exactly one H1 with the main keyword'
            )
        elif len(h1s) == 1:
            r['passed'].append(f'Single H1: "{h1s[0][:60]}"')
            r['score'] += 10
        else:
            r['warnings'].append(
                f'{len(h1s)} H1 tags — use exactly one H1 per page; '
                'multiple H1s dilute the keyword signal'
            )
            r['score'] += 4

        if h2s:
            r['passed'].append(f'{len(h2s)} H2 heading(s) — good content hierarchy')
            r['score'] += 5
        else:
            r['warnings'].append(
                'No H2 headings — sub-headings improve readability, keyword distribution and featured snippet eligibility'
            )

        if h3s:
            r['passed'].append(f'{len(h3s)} H3 heading(s)')

        return r

    # ── Check: Images ──────────────────────────────────────────────────

    def _check_images(self, parser: _SEOHTMLParser) -> dict:
        imgs        = parser.images
        missing_alt = [i for i in imgs if i['alt'] is None]
        empty_alt   = [i for i in imgs if i['alt'] == '']
        lazy        = [i for i in imgs if i.get('loading') == 'lazy']
        no_dims     = [i for i in imgs if not i.get('width') or not i.get('height')]
        modern_fmt  = [i for i in imgs if i['src'].lower().endswith(('.webp', '.avif'))]

        r = {
            'total':             len(imgs),
            'missing_alt':       len(missing_alt),
            'empty_alt':         len(empty_alt),
            'lazy_loading':      len(lazy),
            'missing_dimensions': len(no_dims),
            'modern_formats':    len(modern_fmt),
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        if not imgs:
            r['score'] += 5
            r['passed'].append('No images to evaluate')
        else:
            # Alt text
            if not missing_alt:
                r['passed'].append(f'All {len(imgs)} image(s) have alt attributes')
                r['score'] += 8
            else:
                pct = round(len(missing_alt) / len(imgs) * 100)
                r['issues'].append(
                    f'{len(missing_alt)}/{len(imgs)} images ({pct}%) missing alt text — '
                    'hurts image search visibility and accessibility (WCAG 2.1)'
                )
                r['score'] += max(0, 8 - len(missing_alt) * 2)

            # Dimensions (CLS / Core Web Vitals)
            if no_dims:
                cls_pct = round(len(no_dims) / len(imgs) * 100)
                if cls_pct > 50:
                    r['issues'].append(
                        f'{len(no_dims)}/{len(imgs)} images ({cls_pct}%) missing width/height attributes — '
                        'causes Cumulative Layout Shift (CLS), a Core Web Vitals ranking factor'
                    )
                else:
                    r['warnings'].append(
                        f'{len(no_dims)} image(s) missing width/height — '
                        'add explicit dimensions to prevent layout shift (CLS)'
                    )

            # Lazy loading
            if len(imgs) > 3:
                if lazy:
                    r['passed'].append(f'{len(lazy)}/{len(imgs)} image(s) use lazy loading')
                else:
                    r['warnings'].append(
                        'No lazy loading detected — add loading="lazy" to all images below the fold '
                        'to speed up initial page render'
                    )

            # Modern formats
            if modern_fmt:
                r['passed'].append(f'{len(modern_fmt)} image(s) in modern format (WebP/AVIF)')
            elif len(imgs) > 0:
                r['warnings'].append(
                    'No WebP/AVIF images detected — '
                    'convert images to WebP or AVIF for 25–50% smaller file sizes'
                )

        return r

    # ── Check: Links ───────────────────────────────────────────────────

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
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        if internal:
            r['passed'].append(f'{len(internal)} internal link(s) — good for crawl depth and PageRank flow')
            r['score'] += 5
        else:
            r['warnings'].append(
                'No internal links detected in page HTML — '
                'internal links distribute PageRank and help search engines discover other pages'
            )

        if external:
            r['passed'].append(f'{len(external)} external link(s)')

        return r

    # ── Check: Technical SEO ───────────────────────────────────────────

    def _check_technical(self, parser: _SEOHTMLParser, response, load_ms: int) -> dict:
        enc      = response.headers.get('Content-Encoding') or None
        x_robots = response.headers.get('X-Robots-Tag', '')

        r = {
            'load_time_ms':  load_ms,
            'page_size_kb':  round(len(response.content) / 1024, 1),
            'compression':   enc,
            'viewport':      bool(parser.meta.get('viewport')),
            'x_robots_tag':  x_robots or None,
            'amp_version':   bool(parser.amp_url),
            'has_pagination': bool(parser.pagination['prev'] or parser.pagination['next']),
            'favicon':       bool(parser.favicon_href),
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        # Viewport
        if r['viewport']:
            r['passed'].append('Viewport meta tag present — mobile-friendly')
            r['score'] += 4
        else:
            r['issues'].append(
                'Missing viewport meta tag — page will not render correctly on mobile; '
                'Google uses mobile-first indexing'
            )

        # Compression
        if enc in ('gzip', 'br', 'deflate', 'zstd'):
            r['passed'].append(f'Content compression: {enc}')
            r['score'] += 4
        else:
            r['warnings'].append(
                'No content compression (gzip/brotli) — '
                'enable compression to reduce transfer size; '
                'impacts page speed ranking signal'
            )

        # Server response time (TTFB proxy)
        ms = load_ms
        if ms < 500:
            r['passed'].append(f'Excellent TTFB proxy ({ms} ms)')
            r['score'] += 5
        elif ms < 1500:
            r['passed'].append(f'Good response time ({ms} ms)')
            r['score'] += 4
        elif ms < 3000:
            r['warnings'].append(
                f'Slow response time ({ms} ms) — '
                'aim for under 1,500 ms; slow TTFB degrades LCP and user experience'
            )
            r['score'] += 2
        else:
            r['issues'].append(
                f'Very slow response time ({ms} ms) — '
                'Core Web Vitals (LCP) will be poor; '
                'investigate server performance, caching, or CDN'
            )

        # Page size
        kb = r['page_size_kb']
        if 0 < kb <= 2000:
            r['passed'].append(f'Page size: {kb} KB')
        elif kb > 2000:
            r['warnings'].append(f'Large page HTML ({kb} KB) — heavy pages hurt mobile users and page speed')

        # Favicon
        if r['favicon']:
            r['passed'].append('Favicon declared in HTML')
        else:
            r['warnings'].append(
                'No favicon declared — add <link rel="icon" href="/favicon.ico"> '
                'for brand recognition in browser tabs, bookmarks and search results'
            )

        # AMP
        if parser.amp_url:
            r['passed'].append('AMP version linked (rel=amphtml)')

        # Pagination
        if r['has_pagination']:
            r['passed'].append('Pagination tags present (rel=prev/next)')

        return r

    # ── Check: Page resources ──────────────────────────────────────────

    def _check_resources(self, parser: _SEOHTMLParser) -> dict:
        js_count  = len(parser.scripts)
        css_count = len(parser.stylesheets)

        r = {
            'external_js':    js_count,
            'external_css':   css_count,
            'inline_scripts': parser.inline_scripts,
            'total_requests': js_count + css_count,
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        # External JS
        if js_count <= 8:
            r['passed'].append(f'{js_count} external JS file(s)')
            r['score'] += 3
        elif js_count <= 15:
            r['warnings'].append(
                f'{js_count} external JS files — consider bundling/code-splitting '
                'to reduce HTTP requests and improve page load'
            )
            r['score'] += 1
        else:
            r['issues'].append(
                f'{js_count} external JS files — too many HTTP requests; '
                'bundle and minify JavaScript; consider lazy-loading non-critical scripts'
            )

        # External CSS
        if css_count <= 3:
            r['passed'].append(f'{css_count} external CSS file(s)')
            r['score'] += 2
        elif css_count <= 6:
            r['warnings'].append(
                f'{css_count} external CSS files — '
                'render-blocking resources delay First Contentful Paint; consider consolidating'
            )
            r['score'] += 1
        else:
            r['issues'].append(
                f'{css_count} CSS files — excessive render-blocking resources; '
                'consolidate and inline critical CSS'
            )

        return r

    # ── Check: Social / Open Graph ─────────────────────────────────────

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
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        og_present = [k for k in ('title', 'description', 'image') if og.get(k)]
        if len(og_present) == 3:
            r['passed'].append('Complete Open Graph set (og:title, og:description, og:image)')
            r['score'] += 8
        elif og_present:
            missing = [k for k in ('title', 'description', 'image') if not og.get(k)]
            r['warnings'].append(
                f'Incomplete Open Graph — missing: og:{", og:".join(missing)}; '
                'incomplete OG tags produce poor social share previews'
            )
            r['score'] += 3
        else:
            r['warnings'].append(
                'No Open Graph tags — '
                'social shares on Facebook, LinkedIn and WhatsApp will have no image or description'
            )

        if tw.get('card'):
            r['passed'].append(f'Twitter/X Card: {tw["card"]}')
            r['score'] += 4
        else:
            r['warnings'].append(
                'No Twitter Card meta tags — '
                'links shared on X/Twitter will not show rich card previews; '
                'add twitter:card, twitter:title, twitter:image'
            )

        return r

    # ── Check: Structured data ─────────────────────────────────────────

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
            'has_microdata':  parser.has_microdata,
            'hreflang_count': len(parser.hreflang),
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        if items:
            type_str = ', '.join(types) if types else 'untyped'
            r['passed'].append(f'JSON-LD structured data: {type_str}')
            r['score'] += 5
        elif parser.has_microdata:
            r['passed'].append('Microdata (itemscope/itemtype) detected')
            r['score'] += 3
        else:
            r['warnings'].append(
                'No JSON-LD or Microdata structured data — '
                'add Schema.org markup to unlock rich results: '
                'reviews, FAQs, breadcrumbs, events, products…'
            )

        if parser.hreflang:
            r['passed'].append(f'{len(parser.hreflang)} hreflang tag(s) — international targeting configured')

        return r

    # ── Check: robots.txt ──────────────────────────────────────────────

    def _check_robots_txt(self, base_url: str) -> dict:
        parsed     = urlparse(base_url)
        robots_url = f'{parsed.scheme}://{parsed.netloc}/robots.txt'

        r = {
            'present':          False,
            'sitemap_declared': False,
            'disallow_count':   0,
            'url':              robots_url,
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        try:
            resp = self.session.get(robots_url, timeout=8, allow_redirects=False)
            body = resp.text
            ct   = resp.headers.get('Content-Type', '')

            valid = resp.status_code == 200 and (
                'text' in ct
                or body.strip()[:20].lower().startswith(('user-agent', '#', 'sitemap'))
            )

            if valid:
                r['present'] = True
                disallows = [l for l in body.splitlines() if re.match(r'(?i)disallow\s*:', l)]
                r['disallow_count'] = len(disallows)

                if re.search(r'(?im)^sitemap\s*:', body):
                    r['sitemap_declared'] = True
                    r['passed'].append('Sitemap declared in robots.txt')

                r['passed'].append(f'robots.txt found ({len(disallows)} Disallow rule(s))')
                r['score'] += 5

                # Blanket block detection
                ua_star = False
                for line in body.splitlines():
                    s = line.strip()
                    if re.match(r'(?i)^user-agent\s*:\s*\*', s):
                        ua_star = True
                    elif ua_star and re.match(r'(?i)^disallow\s*:\s*/$', s):
                        r['issues'].append(
                            'robots.txt blocks ALL crawlers (Disallow: /) — '
                            'site will be de-indexed from every search engine; '
                            'remove or restrict to specific paths'
                        )
                        break
                    elif ua_star and s and not s.startswith('#'):
                        ua_star = False
            else:
                r['warnings'].append(
                    'robots.txt not found or invalid — '
                    'recommended for managing crawler access and declaring the sitemap URL'
                )

        except Exception as e:
            r['warnings'].append(f'robots.txt check failed: {str(e)}')

        return r

    # ── Check: XML Sitemap ─────────────────────────────────────────────

    def _check_sitemap(self, base_url: str) -> dict:
        parsed = urlparse(base_url)
        origin = f'{parsed.scheme}://{parsed.netloc}'

        r = {
            'present':   False,
            'url':       None,
            'url_count': 0,
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
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
            r['warnings'].append(
                'XML sitemap not found — '
                'a sitemap at /sitemap.xml ensures search engines discover all pages, '
                'especially on large or dynamically generated sites'
            )

        return r

    # ── Score aggregation ──────────────────────────────────────────────

    def _calculate_score(self, checks: dict) -> int:
        # Per-check caps (total possible = 128, naturally scales to 100)
        caps = {
            'url':            10,
            'meta':           22,
            'content':        14,
            'headings':       15,
            'images':         10,
            'links':           5,
            'technical':      13,
            'resources':       5,
            'social':         12,
            'structured_data': 7,
            'robots_txt':      5,
            'sitemap':        10,
        }
        total = sum(
            min(checks.get(k, {}).get('score', 0), cap)
            for k, cap in caps.items()
        )
        return min(max(total, 0), 100)

    def _rating(self, score: int) -> str:
        if score >= 80: return 'excellent'
        if score >= 60: return 'good'
        if score >= 40: return 'needs_work'
        return 'poor'
