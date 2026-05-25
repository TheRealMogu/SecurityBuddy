import re
import json
import time
import requests
import urllib.robotparser
from collections import Counter
from urllib.parse import urlparse, urljoin
from html.parser import HTMLParser

_TEXT_SKIP = {'script', 'style', 'noscript', 'nav', 'footer', 'aside', 'header'}

# Schema.org types deprecated by Google (no longer produce rich results as of 2026)
_DEPRECATED_SCHEMA = frozenset({
    'FAQPage',              # dropped from rich results May 2026
    'Course', 'CourseInstance',  # Course Info rich result dropped
    'ClaimReview',          # dropped
    'LearningResource',     # dropped
    'SpecialAnnouncement',  # COVID-era, dropped
    'VehicleListing',       # dropped
    'EstimatedSalary',      # salary estimate via JobPosting, dropped
})

# Article-type schema that Google validates for E-E-A-T
_ARTICLE_TYPES = frozenset({'Article', 'NewsArticle', 'BlogPosting'})

# Organisation types that unlock Knowledge Panel and trust signals
_ORG_TYPES = frozenset({'Organization', 'LocalBusiness', 'NGO', 'Corporation', 'EducationalOrganization'})

_STOPWORDS = {
    # English
    'the','a','an','and','or','but','in','on','at','to','for','of','with',
    'by','from','that','this','which','is','are','was','were','be','been',
    'it','its','as','have','has','had','do','does','did','will','would',
    'could','should','may','might','shall','can','not','no','so','if',
    'then','than','such','about','into','through','during','before',
    'after','above','below','between','each','all','both','few','more',
    'most','other','some','any','up','out','there','here','when',
    'where','how','what','who','he','she','they','we','you','me',
    'him','her','us','them','my','your','his','our','their',
    # Italian
    'il','lo','la','le','gli','un','una','del','della','dei','delle',
    'nel','nella','nei','nelle','di','da','con','su','per','tra','fra',
    'sono','come','si','ci','anche','non','che','questa','questo',
    'questi','queste','ogni','molto','bene','dopo','dove','quando',
    # Spanish
    'el','los','las','unos','unas','por','para','sin','sobre','entre',
    'hasta','desde','ante','bajo','su','sus','nos','como','este','esta',
    # French
    'du','au','aux','dans','avec','sans','sous','vers','chez','ou','et',
    'mais','donc','car','ni','que','quoi','dont','les','des','une',
    # German
    'der','die','das','des','dem','den','ein','eine','und','oder','aber',
    'von','zu','an','auf','für','mit','bei','nach','ist','sind','war',
}

_GENERIC_ANCHORS = frozenset({
    'click here', 'click', 'here', 'read more', 'more', 'learn more',
    'this', 'link', 'page', 'visit', 'go', 'continue', 'next', 'info',
    'details', 'download', 'view', 'see', 'check', 'website', 'site',
    'home', 'back', 'forward', 'open', 'get', 'start', 'now',
})


class _SEOHTMLParser(HTMLParser):
    """SAX-style parser that extracts every SEO-relevant element in one pass."""

    def __init__(self):
        super().__init__(convert_charrefs=True)

        # ── Document-level ─────────────────────────────────────────────
        self.html_lang    = None
        self.charset      = None

        # ── <head> metadata ────────────────────────────────────────────
        self.title        = None
        self.meta         = {}
        self.canonical    = None
        self.open_graph   = {}
        self.twitter      = {}
        self.json_ld      = []
        self.hreflang     = []
        self.favicon_href = None
        self.amp_url      = None
        self.pagination   = {'prev': None, 'next': None}
        self.has_manifest        = False
        self.preload_count       = 0
        self.preconnect_count    = 0
        self.has_author_link     = False   # <link rel="author">
        self.meta_refresh_delay  = None    # int seconds if <meta http-equiv="refresh">
        self.dialog_count        = 0       # <dialog> elements (intrusive interstitial proxy)
        self.srcset_images       = 0       # <img srcset="..."> responsive image count

        # ── Body structure ──────────────────────────────────────────────
        self.headings       = {'h1': [], 'h2': [], 'h3': []}
        self.images         = []
        self.links          = []        # {href, rel, text}
        self.paragraph_count = 0
        self.has_microdata  = False
        self.has_rdfa       = False     # vocab/typeof attributes

        # ── Resources ──────────────────────────────────────────────────
        self.scripts        = []
        self.stylesheets    = []
        self.inline_scripts = 0
        self.http_resources = []   # [(tag, url)] HTTP-loaded resources on this page

        # ── Body text ──────────────────────────────────────────────────
        self._body_parts   = []
        self._in_body      = False
        self._skip_depth   = 0

        # ── Parse state ────────────────────────────────────────────────
        self._in_title        = False
        self._current_heading = None
        self._in_script       = False
        self._script_type     = None
        self._buf             = []
        self._in_anchor       = False
        self._anchor_buf      = []

    # ── Event handlers ─────────────────────────────────────────────────

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == 'html':
            self.html_lang = attrs.get('lang') or attrs.get('xml:lang')
            return

        if tag == 'body':
            self._in_body = True
            return

        # RDFa detection (any tag with vocab/typeof/property from schema.org)
        if attrs.get('vocab') or attrs.get('typeof'):
            self.has_rdfa = True

        if attrs.get('itemscope') is not None:
            self.has_microdata = True

        # Paragraph count (content area only)
        if tag == 'p' and self._in_body and self._skip_depth == 0:
            self.paragraph_count += 1

        if tag in _TEXT_SKIP:
            self._skip_depth += 1
            if tag == 'script':
                self._script_type = attrs.get('type', '')
                src = attrs.get('src')
                if src:
                    if src.startswith('http://'):
                        self.http_resources.append(('script', src))
                    self.scripts.append(src)
                    self._in_script = False
                else:
                    self.inline_scripts += 1
                    self._in_script = True
                    self._buf = []
            return

        if tag == 'title':
            self._in_title = True
            self._buf = []
            return

        if tag == 'meta':
            name      = attrs.get('name', '').lower()
            prop      = attrs.get('property', '').lower()
            content   = attrs.get('content', '')
            charset   = attrs.get('charset')
            http_equiv = attrs.get('http-equiv', '').lower()
            if charset:
                self.charset = charset
            elif 'charset=' in content.lower():
                m = re.search(r'charset=([\w-]+)', content, re.I)
                if m:
                    self.charset = m.group(1)
            if http_equiv == 'refresh' and self.meta_refresh_delay is None:
                try:
                    self.meta_refresh_delay = int(re.match(r'(\d+)', content).group(1))
                except (AttributeError, ValueError):
                    self.meta_refresh_delay = 0
            if name:
                self.meta[name] = content
            if prop.startswith('og:'):
                self.open_graph[prop[3:]] = content
            key = prop or name
            if key.startswith('twitter:'):
                self.twitter[key[8:]] = content
            return

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
                if href.startswith('http://'):
                    self.http_resources.append(('stylesheet', href))
                self.stylesheets.append(href)
            elif rel == 'manifest':
                self.has_manifest = True
            elif rel == 'preload':
                self.preload_count += 1
            elif rel == 'preconnect':
                self.preconnect_count += 1
            elif rel == 'author':
                self.has_author_link = True
            return

        if tag in ('h1', 'h2', 'h3'):
            self._current_heading = tag
            self._buf = []
            return

        if tag == 'dialog' and self._in_body:
            self.dialog_count += 1

        if tag in ('iframe', 'embed', 'frame'):
            src = attrs.get('src', '')
            if src.startswith('http://'):
                self.http_resources.append((tag, src))
            return

        if tag == 'form':
            action = attrs.get('action', '')
            if action.startswith('http://'):
                self.http_resources.append(('form', action))

        if tag == 'img':
            src = attrs.get('src', '')
            if src.startswith('http://'):
                self.http_resources.append(('img', src))
            if self._in_anchor and self.links:
                self.links[-1]['has_img'] = True
            if attrs.get('srcset'):
                self.srcset_images += 1
            self.images.append({
                'src':     src,
                'alt':     attrs.get('alt'),
                'loading': attrs.get('loading', ''),
                'width':   attrs.get('width'),
                'height':  attrs.get('height'),
                'srcset':  bool(attrs.get('srcset')),
                'decoding': attrs.get('decoding', ''),
            })
            return

        if tag == 'a':
            href = attrs.get('href', '')
            if href:
                self._in_anchor = True
                self._anchor_buf = []
                self.links.append({'href': href, 'rel': attrs.get('rel', ''), 'text': '', 'has_img': False})

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

        if tag == 'a' and self._in_anchor:
            text = ' '.join(''.join(self._anchor_buf).split())
            if self.links and not self.links[-1]['text']:
                self.links[-1]['text'] = text
            self._in_anchor = False
            self._anchor_buf = []
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
            if self._in_anchor:
                self._anchor_buf.append(data)
        elif self._in_anchor:
            # Capture anchor text even inside nav/footer/aside/header
            self._anchor_buf.append(data)

    @property
    def word_count(self) -> int:
        return len([w for w in re.split(r'\s+', ' '.join(self._body_parts)) if w.strip()])

    @property
    def body_text(self) -> str:
        return ' '.join(self._body_parts)

    def top_keywords(self, n: int = 8) -> list:
        words = re.findall(r'[a-zA-ZÀ-ÿ]{4,}', self.body_text.lower())
        filtered = [w for w in words if w not in _STOPWORDS]
        return [word for word, _ in Counter(filtered).most_common(n)]


# ══════════════════════════════════════════════════════════════════════════
# SEOAnalyzer
# ══════════════════════════════════════════════════════════════════════════

class SEOAnalyzer:
    """
    13-check SEO analyzer using direct HTTP requests + urllib.robotparser.
    Covers everything detectable from raw HTML without a headless browser.
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

            html_source = response.text[:500_000]

            parser = _SEOHTMLParser()
            try:
                parser.feed(html_source)
            except Exception:
                pass

            # ── Run all checks ──────────────────────────────────────────
            result['checks']['url']             = self._check_url(base_url, response)
            result['checks']['https']           = self._check_https(response, parser)
            result['checks']['meta']            = self._check_meta(parser, response)
            result['checks']['content']         = self._check_content(parser, html_source)
            result['checks']['headings']        = self._check_headings(parser)
            result['checks']['images']          = self._check_images(parser)
            result['checks']['links']           = self._check_links(parser, base_url)
            result['checks']['technical']       = self._check_technical(parser, response, load_ms)
            result['checks']['resources']       = self._check_resources(parser)
            result['checks']['social']          = self._check_social(parser)
            result['checks']['structured_data'] = self._check_structured_data(parser)
            result['checks']['robots_txt']      = self._check_robots_txt(base_url)
            result['checks']['sitemap']         = self._check_sitemap(base_url)

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
            'original_url':    base_url,
            'final_url':       response.url,
            'redirect_count':  redirects,
            'redirect_chain':  [{'url': h.url, 'status': h.status_code} for h in response.history],
            'url_length':      len(response.url),
            'has_underscores': '_' in path,
            'has_uppercase':   path != path.lower(),
            'has_query_params': bool(parsed.query),
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        if redirects == 0:
            r['passed'].append('No redirects — URL resolves directly')
            r['score'] += 4
        elif redirects == 1:
            r['passed'].append(f'Single redirect ({response.history[0].status_code}) — acceptable')
            r['score'] += 3
        elif redirects == 2:
            r['warnings'].append(f'{redirects} redirects — aim for 1 max to preserve crawl budget')
            r['score'] += 1
        else:
            r['issues'].append(
                f'{redirects} redirects in chain — critically impacts crawl budget and adds latency; '
                'fix to a single hop'
            )

        if r['url_length'] <= 75:
            r['passed'].append(f'URL length good ({r["url_length"]} chars)')
            r['score'] += 2
        elif r['url_length'] <= 115:
            r['warnings'].append(f'URL somewhat long ({r["url_length"]} chars) — aim for under 75 chars')
            r['score'] += 1
        else:
            r['warnings'].append(f'URL too long ({r["url_length"]} chars) — may be truncated in SERPs')

        if '_' in path:
            r['warnings'].append(
                'Underscores in URL path — use hyphens (-) instead; '
                'Google treats underscores as word joiners, not separators'
            )
        else:
            r['score'] += 2

        if path != path.lower():
            r['warnings'].append(
                'Uppercase letters in URL — can cause duplicate content if server is case-sensitive; '
                'prefer all-lowercase URLs'
            )
        else:
            r['score'] += 2

        return r

    # ── Check: HTTPS & transport security ─────────────────────────────

    def _check_https(self, response, parser: '_SEOHTMLParser') -> dict:
        final_url = response.url
        is_https  = final_url.startswith('https://')
        hsts      = response.headers.get('Strict-Transport-Security', '')

        r = {
            'is_https':           is_https,
            'hsts':               hsts or None,
            'mixed_content_count': 0,
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        if is_https:
            r['passed'].append('Site served over HTTPS — encrypted connection')
            r['score'] += 6
        else:
            r['issues'].append(
                'Site not served over HTTPS — major SEO ranking penalty; '
                'Google flags HTTP pages as "Not secure" and downgrades them in results; '
                'migrate to HTTPS with a free Let\'s Encrypt certificate'
            )

        # HSTS
        if hsts:
            max_age_m = re.search(r'max-age=(\d+)', hsts)
            if max_age_m:
                days = int(max_age_m.group(1)) // 86400
                if days >= 180:
                    r['passed'].append(f'HSTS enabled — max-age={days} days (strong)')
                    r['score'] += 4
                elif days >= 30:
                    r['warnings'].append(
                        f'HSTS max-age short ({days} days) — '
                        'recommend ≥180 days to qualify for HSTS preload lists'
                    )
                    r['score'] += 2
                else:
                    r['warnings'].append(f'HSTS max-age very short ({days} days) — increase to at least 180 days')
                    r['score'] += 1
            else:
                r['passed'].append('HSTS header present')
                r['score'] += 2
        elif is_https:
            r['warnings'].append(
                'No Strict-Transport-Security (HSTS) header — '
                'add it to enforce HTTPS, prevent protocol downgrade attacks, '
                'and improve browser trust signals'
            )

        # Mixed content: HTTP-loaded resources (scripts, stylesheets, images, iframes, forms)
        # detected by the parser — does NOT flag regular <a href="http://"> links.
        if is_https:
            mixed = parser.http_resources
            r['mixed_content_count'] = len(mixed)
            if mixed:
                type_counts = Counter(t for t, _ in mixed)
                detail = ', '.join(f'{v} {k}' for k, v in type_counts.most_common())
                r['issues'].append(
                    f'{len(mixed)} mixed-content resource(s) detected ({detail}) — '
                    'HTTP resources on an HTTPS page are blocked or warned by browsers; '
                    'update all resource URLs to HTTPS'
                )
            else:
                r['passed'].append('No mixed content — all loaded resources use HTTPS')

        return r

    # ── Check: Meta tags ───────────────────────────────────────────────

    def _check_meta(self, parser: _SEOHTMLParser, response=None) -> dict:
        r = {
            'title':              parser.title,
            'title_length':       len(parser.title) if parser.title else 0,
            'description':        parser.meta.get('description'),
            'description_length': len(parser.meta.get('description', '')),
            'canonical':          parser.canonical,
            'keywords':           parser.meta.get('keywords'),
            'noindex':            False,
            'nofollow_meta':      False,
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        title = parser.title
        if not title:
            r['issues'].append(
                'Missing <title> tag — the single most important on-page SEO element; '
                'directly affects rankings and click-through rate in SERPs'
            )
        elif len(title) < 30:
            r['warnings'].append(
                f'Title too short ({len(title)} chars) — aim for 50–60 chars; '
                'short titles waste keyword ranking space'
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

        if parser.canonical:
            # Resolve relative canonical to absolute so the value is always meaningful
            canonical_abs = urljoin(response.url if response else parser.canonical, parser.canonical)
            r['canonical'] = canonical_abs
            r['passed'].append(f'Canonical URL declared')
            r['score'] += 3
        else:
            r['canonical'] = None
            r['warnings'].append(
                'No canonical URL — risk of duplicate-content issues; '
                'add <link rel="canonical" href="…"> even on unique pages'
            )

        # meta keywords (useful for Bing)
        if parser.meta.get('keywords'):
            r['passed'].append('meta keywords present (Bing signal)')

        # Meta refresh — can disrupt Googlebot indexing
        if parser.meta_refresh_delay is not None:
            if parser.meta_refresh_delay == 0:
                r['issues'].append(
                    'Instant meta refresh (content="0; url=…") detected — '
                    'Google may not pass full ranking credit through a meta refresh; '
                    'use a proper 301 HTTP redirect instead'
                )
            else:
                r['warnings'].append(
                    f'Meta refresh with delay={parser.meta_refresh_delay}s — '
                    'can disrupt crawling; use HTTP redirects for page moves'
                )

        # E-E-A-T author signal
        author = parser.meta.get('author', '')
        if author:
            r['passed'].append(f'Author declared: meta author="{author}"')
        elif parser.has_author_link:
            r['passed'].append('Author page linked via rel="author" — E-E-A-T signal')
        else:
            r['warnings'].append(
                'No author signal — add <meta name="author"> or <link rel="author"> '
                'to help Google identify the content creator (E-E-A-T)'
            )

        robots = parser.meta.get('robots', '').lower()
        if 'noindex' in robots:
            r['noindex'] = True
            r['issues'].append('robots meta: noindex — this page will NOT appear in any search engine')
        if 'nofollow' in robots:
            r['nofollow_meta'] = True
            r['warnings'].append('robots meta: nofollow — search engines will not follow links on this page')

        if response:
            xr = response.headers.get('X-Robots-Tag', '').lower()
            if 'noindex' in xr:
                r['issues'].append('X-Robots-Tag: noindex — page blocked from indexing via HTTP header')
            elif 'nofollow' in xr:
                r['warnings'].append('X-Robots-Tag: nofollow — link following blocked via HTTP header')
            elif xr:
                r['passed'].append(f'X-Robots-Tag: {xr}')

        return r

    # ── Check: Content quality ─────────────────────────────────────────

    def _check_content(self, parser: _SEOHTMLParser, html_source: str) -> dict:
        wc     = parser.word_count
        # SPA heuristic: very little server-rendered text AND many external JS files AND no H1.
        # All three conditions must hold to avoid false-flagging analytics-heavy static pages.
        is_spa = (wc < 40
                  and len(parser.scripts) > 5
                  and len(parser.headings.get('h1', [])) == 0)

        html_len  = max(len(html_source), 1)
        text_len  = len(parser.body_text)
        txt_ratio = round(text_len / html_len * 100, 1)
        keywords  = parser.top_keywords(8)

        r = {
            'word_count':    wc,
            'language':      parser.html_lang,
            'charset':       parser.charset,
            'is_spa':        is_spa,
            'paragraph_count': parser.paragraph_count,
            'text_html_ratio': txt_ratio,
            'top_keywords':  keywords,
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        if is_spa:
            r['warnings'].append(
                'Page appears to be a Single Page Application (SPA) — '
                'search engines may not execute JavaScript and will see little content; '
                'consider Server-Side Rendering (SSR) or pre-rendering'
            )

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

        if parser.html_lang:
            r['passed'].append(f'Language declared: lang="{parser.html_lang}"')
            r['score'] += 4
        else:
            r['warnings'].append(
                'No lang attribute on <html> — '
                'declare the page language (e.g. <html lang="en">) '
                'for correct language detection by search engines and screen readers'
            )

        if parser.charset:
            r['passed'].append(f'Charset declared: {parser.charset}')
            r['score'] += 2
        else:
            r['warnings'].append(
                'No charset declaration — add <meta charset="UTF-8"> '
                'as the first element inside <head>'
            )

        # Text-to-HTML ratio
        if txt_ratio >= 25:
            r['passed'].append(f'Text-to-HTML ratio {txt_ratio}% — good content density')
        elif txt_ratio >= 10:
            r['warnings'].append(
                f'Low text-to-HTML ratio ({txt_ratio}%) — '
                'page has relatively little text compared to markup; '
                'reduce boilerplate HTML or add more content'
            )
        else:
            r['warnings'].append(
                f'Very low text-to-HTML ratio ({txt_ratio}%) — '
                'minimal text content detected; crawlers will see mostly markup'
            )

        # Paragraph structure
        if not is_spa:
            if parser.paragraph_count >= 3:
                r['passed'].append(f'{parser.paragraph_count} content paragraphs — good structure')
            elif parser.paragraph_count > 0:
                r['warnings'].append(
                    f'Only {parser.paragraph_count} paragraph(s) — '
                    'use more <p> tags for readable, well-structured content'
                )

        if keywords:
            r['passed'].append(f'Top keywords: {", ".join(keywords[:5])}')

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
                'No H2 headings — sub-headings improve readability, '
                'keyword distribution and featured snippet eligibility'
            )

        if h3s:
            r['passed'].append(f'{len(h3s)} H3 heading(s) — deep content structure')

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
            'total':              len(imgs),
            'missing_alt':        len(missing_alt),
            'empty_alt':          len(empty_alt),
            'lazy_loading':       len(lazy),
            'missing_dimensions': len(no_dims),
            'modern_formats':     len(modern_fmt),
            'responsive_srcset':  parser.srcset_images,
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        if not imgs:
            r['score'] += 5
            r['passed'].append('No images to evaluate')
        else:
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

            if no_dims:
                cls_pct = round(len(no_dims) / len(imgs) * 100)
                msg = (
                    f'{len(no_dims)}/{len(imgs)} images ({cls_pct}%) missing width/height attributes — '
                    'causes Cumulative Layout Shift (CLS), a Core Web Vitals ranking factor'
                )
                if cls_pct > 50:
                    r['issues'].append(msg)
                else:
                    r['warnings'].append(msg)
            else:
                r['passed'].append('All images have width/height attributes — no CLS risk')
                r['score'] += 2

            if len(imgs) > 3:
                if lazy:
                    r['passed'].append(f'{len(lazy)}/{len(imgs)} image(s) use lazy loading')
                else:
                    r['warnings'].append(
                        'No lazy loading — add loading="lazy" to below-the-fold images '
                        'to speed up initial page render'
                    )

            if modern_fmt:
                r['passed'].append(f'{len(modern_fmt)} image(s) in modern format (WebP/AVIF)')
            elif len(imgs) > 0:
                r['warnings'].append(
                    'No WebP/AVIF images detected — '
                    'convert images to WebP or AVIF for 25–50% smaller file sizes'
                )

            if parser.srcset_images > 0:
                r['passed'].append(
                    f'{parser.srcset_images}/{len(imgs)} image(s) use srcset — responsive images configured'
                )
            elif len(imgs) > 0:
                r['warnings'].append(
                    'No srcset attribute on images — '
                    'add srcset for responsive images to serve appropriate resolution per device'
                )

        return r

    # ── Check: Links ───────────────────────────────────────────────────

    def _check_links(self, parser: _SEOHTMLParser, base_url: str) -> dict:
        base_netloc = urlparse(base_url).netloc
        internal, external, nofollow = [], [], []
        generic_anchors, empty_anchors = [], []

        for link in parser.links:
            href = link['href']
            rel  = link.get('rel', '')
            text = (link.get('text') or '').strip()

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

            # Anchor text quality — skip image-only links (<a><img></a>) which are
            # intentional logo/icon patterns and don't need descriptive text.
            text_lc = text.lower()
            has_img = link.get('has_img', False)
            if not text_lc and not has_img:
                empty_anchors.append(href)
            elif text_lc and (text_lc in _GENERIC_ANCHORS or len(text_lc) <= 2):
                generic_anchors.append(text_lc)

        r = {
            'total':           len(parser.links),
            'internal':        len(internal),
            'external':        len(external),
            'nofollow':        len(nofollow),
            'generic_anchors': len(generic_anchors),
            'empty_anchors':   len(empty_anchors),
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        if internal:
            r['passed'].append(f'{len(internal)} internal link(s) — good for crawl depth and PageRank flow')
            r['score'] += 5
        else:
            r['warnings'].append(
                'No internal links detected — '
                'internal links distribute PageRank and help crawlers discover other pages'
            )

        if external:
            r['passed'].append(f'{len(external)} external link(s)')

        if empty_anchors:
            r['warnings'].append(
                f'{len(empty_anchors)} link(s) with empty anchor text — '
                'add descriptive text to all links for SEO and accessibility'
            )

        if generic_anchors:
            r['warnings'].append(
                f'{len(generic_anchors)} link(s) with generic anchor text '
                '("click here", "read more", etc.) — '
                'use keyword-rich descriptive anchors instead'
            )

        return r

    # ── Check: Technical SEO ───────────────────────────────────────────

    def _check_technical(self, parser: _SEOHTMLParser, response, load_ms: int) -> dict:
        enc      = response.headers.get('Content-Encoding') or None
        cc       = response.headers.get('Cache-Control', '')
        etag     = response.headers.get('ETag')
        last_mod = response.headers.get('Last-Modified')

        r = {
            'load_time_ms':    load_ms,
            'page_size_kb':    round(len(response.content) / 1024, 1),
            'compression':     enc,
            'viewport':        bool(parser.meta.get('viewport')),
            'amp_version':     bool(parser.amp_url),
            'has_pagination':  bool(parser.pagination['prev'] or parser.pagination['next']),
            'favicon':         bool(parser.favicon_href),
            'has_manifest':    parser.has_manifest,
            'preload_count':   parser.preload_count,
            'preconnect_count': parser.preconnect_count,
            'dialog_count':    parser.dialog_count,
            'meta_refresh':    parser.meta_refresh_delay,
            'cache_control':   cc or None,
            'has_etag':        bool(etag),
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        if r['viewport']:
            r['passed'].append('Viewport meta tag present — mobile-friendly')
            r['score'] += 4
        else:
            r['issues'].append(
                'Missing viewport meta tag — page will not render correctly on mobile; '
                'Google uses mobile-first indexing'
            )

        if enc in ('gzip', 'br', 'deflate', 'zstd'):
            r['passed'].append(f'Content compression: {enc}')
            r['score'] += 4
        else:
            r['warnings'].append(
                'No content compression (gzip/brotli) — '
                'enable compression to reduce transfer size and improve page speed ranking signal'
            )

        ms = load_ms
        if ms < 500:
            r['passed'].append(f'Excellent server response ({ms} ms)')
            r['score'] += 5
        elif ms < 1500:
            r['passed'].append(f'Good server response ({ms} ms)')
            r['score'] += 4
        elif ms < 3000:
            r['warnings'].append(
                f'Slow response ({ms} ms) — '
                'aim for under 1,500 ms; slow TTFB degrades LCP and user experience'
            )
            r['score'] += 2
        else:
            r['issues'].append(
                f'Very slow response ({ms} ms) — '
                'Core Web Vitals (LCP) will be poor; '
                'investigate server performance, caching, or CDN'
            )

        kb = r['page_size_kb']
        if 0 < kb <= 2000:
            r['passed'].append(f'Page HTML size: {kb} KB')
        elif kb > 2000:
            r['warnings'].append(f'Large page HTML ({kb} KB) — heavy pages hurt mobile performance')

        if r['favicon']:
            r['passed'].append('Favicon declared in HTML')
        else:
            r['warnings'].append(
                'No favicon declared — add <link rel="icon" href="/favicon.ico"> '
                'for brand recognition in browser tabs and search results'
            )

        # Caching headers
        if cc:
            if any(d in cc for d in ('max-age', 's-maxage', 'public', 'no-store', 'no-cache')):
                r['passed'].append(f'Cache-Control configured: {cc[:60]}')
            else:
                r['warnings'].append(f'Cache-Control present but may not be optimal: {cc[:60]}')
        else:
            r['warnings'].append(
                'No Cache-Control header — configure caching to improve repeat-visit performance; '
                'helps CDN and browser cache behaviour'
            )

        if etag or last_mod:
            r['passed'].append('Conditional-request headers present (ETag/Last-Modified)')

        if parser.preload_count > 0:
            r['passed'].append(f'{parser.preload_count} resource(s) with rel=preload — good performance hint')

        if parser.preconnect_count > 0:
            r['passed'].append(
                f'{parser.preconnect_count} rel=preconnect hint(s) — '
                'early connection setup reduces latency for third-party origins'
            )

        if parser.dialog_count > 0:
            r['warnings'].append(
                f'{parser.dialog_count} <dialog> element(s) detected — '
                'verify these are not intrusive interstitials; '
                'Google may penalise pages where full-screen popups block content on mobile'
            )

        if parser.amp_url:
            r['passed'].append('AMP version linked (rel=amphtml)')

        if r['has_pagination']:
            r['passed'].append('Pagination tags present (rel=prev/next)')

        if parser.has_manifest:
            r['passed'].append('Web App Manifest linked (PWA signal)')

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
                'links on X/Twitter will not show rich card previews; '
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

        # Validate JSON-LD: each item should have @context and @type
        valid_items   = [i for i in items if isinstance(i, dict) and i.get('@context') and i.get('@type')]
        invalid_items = len(items) - len(valid_items)

        r = {
            'json_ld_count':  len(items),
            'valid_ld_count': len(valid_items),
            'schema_types':   types,
            'has_microdata':  parser.has_microdata,
            'has_rdfa':       parser.has_rdfa,
            'hreflang_count': len(parser.hreflang),
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        if valid_items:
            type_str = ', '.join(types) if types else 'untyped'
            r['passed'].append(f'JSON-LD structured data found: {type_str}')
            r['score'] += 5
            if invalid_items > 0:
                r['warnings'].append(
                    f'{invalid_items} JSON-LD block(s) missing @context or @type — '
                    'invalid blocks are ignored by Google Rich Results'
                )

            # Warn on deprecated types (removed from Google rich results 2025-2026)
            deprecated_found = [t for t in types if t in _DEPRECATED_SCHEMA]
            if deprecated_found:
                for dt in deprecated_found:
                    if dt == 'FAQPage':
                        r['issues'].append(
                            'FAQPage schema DEPRECATED — Google dropped FAQ rich results May 2026; '
                            'remove markup or replace with HowTo / Q&A page where appropriate'
                        )
                    else:
                        r['warnings'].append(
                            f'{dt} schema type deprecated by Google — '
                            'no longer eligible for rich results; '
                            'remove or replace with a supported type'
                        )

            # Rich result eligibility hints (exclude deprecated types)
            rich = {'HowTo', 'Recipe', 'Product', 'Review', 'Event',
                    'BreadcrumbList', 'Organization', 'Article', 'WebSite', 'Person',
                    'NewsArticle', 'BlogPosting', 'JobPosting', 'LocalBusiness',
                    'SoftwareApplication', 'Book', 'Movie', 'VideoObject'}
            found_rich = [t for t in types if t in rich and t not in _DEPRECATED_SCHEMA]
            if found_rich:
                r['passed'].append(f'Rich result eligible types: {", ".join(found_rich)}')
            elif not deprecated_found:
                r['warnings'].append(
                    'JSON-LD found but no rich-result types detected — '
                    'consider adding BreadcrumbList, Product, or HowTo schema '
                    'to unlock rich results in SERPs'
                )

            # Validate Article/BlogPosting/NewsArticle required fields for E-E-A-T
            article_items = [i for i in valid_items if i.get('@type') in _ARTICLE_TYPES]
            for article in article_items:
                missing = [f for f in ('headline', 'author', 'datePublished', 'image')
                           if not article.get(f)]
                if missing:
                    r['warnings'].append(
                        f'Article schema missing: {", ".join(missing)} — '
                        'these fields are required for Google E-E-A-T signals and article rich results'
                    )
                else:
                    r['passed'].append(
                        'Article schema complete (headline, author, datePublished, image) — E-E-A-T ready'
                    )

            # Validate Organization/LocalBusiness recommended fields
            org_items = [i for i in valid_items if i.get('@type') in _ORG_TYPES]
            for org in org_items:
                missing = [f for f in ('name', 'url', 'logo') if not org.get(f)]
                if missing:
                    r['warnings'].append(
                        f'Organization schema missing: {", ".join(missing)} — '
                        'complete org markup improves Knowledge Panel eligibility'
                    )
                else:
                    r['passed'].append('Organization schema complete (name, url, logo)')

        elif items:
            r['warnings'].append(
                f'{len(items)} JSON-LD block(s) found but missing @context/@type — validate at schema.org'
            )
            r['score'] += 1
        elif parser.has_microdata:
            r['passed'].append('Microdata (itemscope/itemtype) detected')
            r['score'] += 3
        elif parser.has_rdfa:
            r['passed'].append('RDFa markup (vocab/typeof) detected')
            r['score'] += 2
        else:
            r['warnings'].append(
                'No JSON-LD, Microdata, or RDFa structured data — '
                'add Schema.org markup to unlock rich results: '
                'FAQs, breadcrumbs, events, products, reviews…'
            )

        if parser.hreflang:
            r['passed'].append(f'{len(parser.hreflang)} hreflang tag(s) — international targeting configured')
            r['score'] += 2

        return r

    # ── Check: robots.txt ──────────────────────────────────────────────

    def _check_robots_txt(self, base_url: str) -> dict:
        parsed     = urlparse(base_url)
        robots_url = f'{parsed.scheme}://{parsed.netloc}/robots.txt'

        r = {
            'present':          False,
            'sitemap_declared': False,
            'disallow_count':   0,
            'crawl_delay':      None,
            'googlebot_blocked': False,
            'url':              robots_url,
            'score': 0, 'issues': [], 'warnings': [], 'passed': [],
        }

        try:
            resp = self.session.get(robots_url, timeout=8, allow_redirects=True)
            body = resp.text
            ct   = resp.headers.get('Content-Type', '')

            valid = resp.status_code == 200 and (
                'text' in ct
                or body.strip()[:20].lower().startswith(('user-agent', '#', 'sitemap'))
            )

            if valid:
                r['present'] = True

                # Use urllib.robotparser for proper spec-compliant parsing
                rp = urllib.robotparser.RobotFileParser()
                rp.set_url(robots_url)
                rp.parse(body.splitlines())

                # Googlebot access
                googlebot_ok = rp.can_fetch('Googlebot', '/')
                r['googlebot_blocked'] = not googlebot_ok

                # Crawl-Delay
                cd = rp.crawl_delay('*') or rp.crawl_delay('Googlebot')
                if cd is not None:
                    r['crawl_delay'] = cd
                    if cd > 10:
                        r['warnings'].append(
                            f'Crawl-Delay: {cd}s — very restrictive; '
                            'may significantly reduce indexing frequency'
                        )
                    else:
                        r['passed'].append(f'Crawl-Delay: {cd}s')

                # Sitemap declarations (site_maps() available since Python 3.8)
                sitemaps = rp.site_maps() or []
                if sitemaps:
                    r['sitemap_declared'] = True
                    r['passed'].append(f'Sitemap declared in robots.txt: {sitemaps[0]}')
                elif re.search(r'(?im)^sitemap\s*:', body):
                    r['sitemap_declared'] = True
                    r['passed'].append('Sitemap declared in robots.txt')

                disallows = [l for l in body.splitlines() if re.match(r'(?i)disallow\s*:', l)]
                r['disallow_count'] = len(disallows)

                if not googlebot_ok:
                    r['issues'].append(
                        'robots.txt is blocking Googlebot from crawling / — '
                        'site will be de-indexed; remove the blanket Disallow: /'
                    )
                else:
                    r['passed'].append(f'robots.txt found · {len(disallows)} Disallow rule(s) · Googlebot allowed')
                    r['score'] += 5

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
                'XML sitemap not found at /sitemap.xml or /sitemap_index.xml — '
                'a sitemap ensures search engines discover all pages, '
                'especially on large or dynamically generated sites'
            )

        return r

    # ── Score aggregation ──────────────────────────────────────────────

    def _calculate_score(self, checks: dict) -> int:
        caps = {
            'url':             10,
            'https':           10,
            'meta':            22,
            'content':         14,
            'headings':        15,
            'images':          10,
            'links':            5,
            'technical':       13,
            'resources':        5,
            'social':          12,
            'structured_data':  7,
            'robots_txt':       5,
            'sitemap':         10,
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
