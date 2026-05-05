"""
Security Buddy — PDF Report Generator
Produces a professional, white-label-ready PDF for every scan result.
"""
import json
import io
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing, String, Circle
from reportlab.graphics import renderPDF


# ── Colour palette ──────────────────────────────────────────────────────────
C_BG        = HexColor('#0d0f10')
C_SURFACE   = HexColor('#131618')
C_PRIMARY   = HexColor('#2dd4bf')
C_SUCCESS   = HexColor('#4ade80')
C_WARNING   = HexColor('#fbbf24')
C_DANGER    = HexColor('#f87171')
C_TEXT      = HexColor('#e8eaec')
C_MUTED     = HexColor('#8b9299')
C_BORDER    = HexColor('#2a2f34')


def _risk_colour(score: int) -> HexColor:
    if score >= 80:
        return C_SUCCESS
    if score >= 60:
        return C_WARNING
    return C_DANGER


def _risk_label(score: int) -> str:
    if score >= 80:
        return 'LOW'
    if score >= 60:
        return 'MEDIUM'
    if score >= 40:
        return 'HIGH'
    return 'CRITICAL'


def _cvss_like(score: int) -> str:
    if score >= 80:
        return 'None / Informational'
    if score >= 60:
        return 'Medium'
    if score >= 40:
        return 'High'
    return 'Critical'


def _score_gauge(score: int, size: int = 90) -> Drawing:
    colour = _risk_colour(score)
    d = Drawing(size, size)
    cx, cy, r = size / 2, size / 2, size / 2 - 4
    d.add(Circle(cx, cy, r, strokeColor=C_BORDER, strokeWidth=6, fillColor=None))
    d.add(Circle(cx, cy, r, strokeColor=colour, strokeWidth=6, fillColor=None))
    d.add(String(cx, cy + 4, str(score),
                 fontName='Helvetica-Bold', fontSize=20,
                 fillColor=colour, textAnchor='middle'))
    d.add(String(cx, cy - 12, '/100',
                 fontName='Helvetica', fontSize=8,
                 fillColor=C_MUTED, textAnchor='middle'))
    return d


class SecurityReportPDF:

    def __init__(self, brand_name: str = 'Security Buddy', brand_color: HexColor = None):
        self.brand_name  = brand_name
        self.brand_color = brand_color or C_PRIMARY
        self._init_styles()

    def _init_styles(self):
        base = getSampleStyleSheet()

        def P(name, **kw):
            return ParagraphStyle(name, parent=base['Normal'], **kw)

        self.s = {
            'title':       P('rTitle', fontSize=22, fontName='Helvetica-Bold',
                              textColor=C_TEXT, spaceAfter=4),
            'subtitle':    P('rSubtitle', fontSize=11, textColor=C_MUTED, spaceAfter=20),
            'section':     P('rSection', fontSize=13, fontName='Helvetica-Bold',
                              textColor=self.brand_color, spaceBefore=16, spaceAfter=6),
            'body':        P('rBody', fontSize=10, textColor=C_TEXT, leading=15, spaceAfter=6),
            'small':       P('rSmall', fontSize=8.5, textColor=C_MUTED, leading=13),
            'code':        P('rCode', fontSize=8.5, fontName='Courier',
                              textColor=C_PRIMARY, leading=14),
            'finding_ok':  P('rOk',   fontSize=10, textColor=C_SUCCESS),
            'finding_warn':P('rWarn', fontSize=10, textColor=C_WARNING),
            'finding_err': P('rErr',  fontSize=10, textColor=C_DANGER),
            'center':      P('rCenter', fontSize=10, textColor=C_TEXT, alignment=TA_CENTER),
        }

    # ── Public entry point ───────────────────────────────────────────────────
    def generate_report(self, scan_result, user_info: dict = None) -> io.BytesIO:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            rightMargin=18 * mm, leftMargin=18 * mm,
            topMargin=20 * mm, bottomMargin=20 * mm,
            title=f'Security Report — {scan_result.target}',
            author=self.brand_name,
        )

        results = (
            json.loads(scan_result.results)
            if isinstance(scan_result.results, str)
            else scan_result.results
        )
        score     = results.get('overall_score', 0)
        risk      = results.get('risk_level', 'unknown')
        checks    = results.get('checks', {})
        scan_date = scan_result.created_at.strftime('%Y-%m-%d %H:%M UTC')
        org       = (user_info or {}).get('organization', '')

        story = []
        story += self._cover(scan_result.target, score, risk, scan_date, org)
        story += self._executive_summary(score, risk, checks)
        story += self._findings_table(checks)
        story += self._detailed_findings(checks)
        story += self._remediation_plan(checks, score)
        story += self._footer_note()

        doc.build(story, onFirstPage=self._page_template, onLaterPages=self._page_template)
        buf.seek(0)
        return buf

    # ── Cover ────────────────────────────────────────────────────────────────
    def _cover(self, target, score, risk, scan_date, org):
        colour = _risk_colour(score)
        story  = []

        bar_data = [[
            Paragraph(
                f'<b>{self.brand_name}</b><br/>'
                f'<font size="9" color="#8b9299">Security Analysis Report</font>',
                self.s['body'],
            ),
            Paragraph(
                f'<font size="9" color="#8b9299">{scan_date}</font>',
                ParagraphStyle('rR', parent=self.s['body'], alignment=TA_RIGHT),
            ),
        ]]
        bar_tbl = Table(bar_data, colWidths=['*', '*'])
        bar_tbl.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C_SURFACE),
            ('TOPPADDING',    (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING',   (0, 0), (-1, -1), 12),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 12),
            ('LINEBELOW',     (0, 0), (-1, -1), 1, C_BORDER),
        ]))
        story.append(bar_tbl)
        story.append(Spacer(1, 20))

        gauge = _score_gauge(score, 90)
        left_rows = []
        if org:
            left_rows.append([Paragraph(f'Organization: {org}', self.s['small'])])
        left_rows += [
            [Paragraph('Target', self.s['small'])],
            [Paragraph(f'<b>{target}</b>', self.s['title'])],
            [Spacer(1, 6)],
            [Paragraph(
                f'Risk Level: <b><font color="#{colour.hexval()}">{_risk_label(score)}</font></b>',
                self.s['body'],
            )],
            [Paragraph(f'Severity: {_cvss_like(score)}', self.s['small'])],
        ]
        left_tbl = Table(left_rows, colWidths=['*'])
        left_tbl.setStyle(TableStyle([
            ('TOPPADDING',    (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))

        cover_tbl = Table([[left_tbl, gauge]], colWidths=['*', 100])
        cover_tbl.setStyle(TableStyle([
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND',    (0, 0), (-1, -1), C_SURFACE),
            ('BOX',           (0, 0), (-1, -1), 1, C_BORDER),
            ('TOPPADDING',    (0, 0), (-1, -1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
            ('LEFTPADDING',   (0, 0), (-1, -1), 14),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 14),
        ]))
        story.append(cover_tbl)
        story.append(Spacer(1, 24))
        return story

    # ── Executive Summary ────────────────────────────────────────────────────
    def _executive_summary(self, score, risk, checks):
        story = [Paragraph('Executive Summary', self.s['section'])]
        descriptions = {
            'low':      'The target demonstrates strong security posture. All critical controls are in place. '
                        'Continue routine monitoring and address informational findings as capacity allows.',
            'medium':   'The target has adequate baseline security but several controls are missing or misconfigured. '
                        'Address the medium-severity findings within 30 days to reduce exposure.',
            'high':     'Multiple high-severity security controls are absent. Exploitation is plausible without '
                        'specialized access. Remediation within 7–14 days is recommended.',
            'critical': 'Critical vulnerabilities were detected that significantly increase the risk of compromise. '
                        'Immediate remediation is required — begin within 48 hours.',
        }
        story.append(Paragraph(descriptions.get(risk, 'Security assessment completed.'), self.s['body']))
        story.append(Spacer(1, 6))
        total_issues = sum(len(c.get('issues', [])) for c in checks.values() if isinstance(c, dict))
        story.append(Paragraph(
            f'Total findings: <b>{total_issues}</b> &nbsp;|&nbsp; Score: <b>{score}/100</b>',
            self.s['small'],
        ))
        story.append(Spacer(1, 6))
        return story

    # ── Findings Table ───────────────────────────────────────────────────────
    def _findings_table(self, checks):
        story = [Paragraph('Findings Overview', self.s['section'])]

        CHECK_META = {
            'connectivity': ('Connectivity',       'Reachability of target'),
            'https':        ('HTTPS & Redirect',   'Encryption in transit'),
            'ssl':          ('SSL Certificate',    'Certificate validity & expiry'),
            'headers':      ('Security Headers',   'Browser security policy headers'),
            'cookies':      ('Cookie Security',    'HttpOnly / Secure / SameSite flags'),
            'cors':         ('CORS Policy',        'Cross-origin access control'),
            'http_methods': ('HTTP Methods',       'Exposed dangerous HTTP verbs'),
            'tech':         ('Tech Fingerprint',   'Version disclosure in headers'),
            'ports':        ('Open Ports',         'Publicly reachable risky ports'),
            'domain_info':  ('Domain Info',        'DNS resolution & IP mapping'),
        }

        rows = [[
            Paragraph('<b>Check</b>',       self.s['small']),
            Paragraph('<b>Description</b>', self.s['small']),
            Paragraph('<b>Issues</b>',      self.s['small']),
            Paragraph('<b>Status</b>',      self.s['small']),
        ]]

        for key, (name, desc) in CHECK_META.items():
            check = checks.get(key)
            if check is None:
                continue
            issues = check.get('issues', []) if isinstance(check, dict) else []
            n = len(issues)
            if n == 0:
                status_p = Paragraph('✓ Pass', self.s['finding_ok'])
            elif n <= 2:
                status_p = Paragraph('⚠ Warn', self.s['finding_warn'])
            else:
                status_p = Paragraph('✗ Fail', self.s['finding_err'])

            rows.append([
                Paragraph(name,   self.s['body']),
                Paragraph(desc,   self.s['small']),
                Paragraph(str(n), self.s['center']),
                status_p,
            ])

        tbl = Table(rows, colWidths=[110, '*', 35, 55])
        tbl.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, 0),  C_SURFACE),
            ('ROWBACKGROUNDS',(0, 1), (-1, -1), [HexColor('#0f1214'), C_SURFACE]),
            ('GRID',          (0, 0), (-1, -1), 0.5, C_BORDER),
            ('TOPPADDING',    (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING',   (0, 0), (-1, -1), 8),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 16))
        return story

    # ── Detailed Findings ────────────────────────────────────────────────────
    def _detailed_findings(self, checks):
        story = [Paragraph('Detailed Findings', self.s['section'])]

        sections = [
            ('https',        'HTTPS & Redirect'),
            ('ssl',          'SSL Certificate'),
            ('headers',      'Security Headers'),
            ('cookies',      'Cookie Security'),
            ('cors',         'CORS Policy'),
            ('http_methods', 'HTTP Methods'),
            ('tech',         'Technology Fingerprint'),
            ('ports',        'Open Ports'),
        ]

        label_style = ParagraphStyle(
            'fLabel', parent=self.s['body'],
            fontName='Helvetica-Bold', textColor=C_TEXT,
            spaceBefore=10, spaceAfter=4,
        )

        for key, label in sections:
            check = checks.get(key)
            if not check or not isinstance(check, dict):
                continue
            issues = check.get('issues', [])

            block = [
                Paragraph(label, label_style),
                HRFlowable(width='100%', thickness=0.5, color=C_BORDER, spaceAfter=4),
            ]

            if not issues:
                block.append(Paragraph('✓ No issues found.', self.s['finding_ok']))
            else:
                for issue in issues:
                    block.append(Paragraph(f'• {issue}', self.s['finding_err']))

            # Extra per-check details
            if key == 'headers':
                found   = check.get('headers_found', [])
                missing = check.get('headers_missing', [])
                if found:
                    block.append(Paragraph(
                        'Present: ' + ', '.join(h['name'] for h in found),
                        self.s['small'],
                    ))
                if missing:
                    block.append(Paragraph(
                        'Missing: ' + ', '.join(missing),
                        ParagraphStyle('ms', parent=self.s['small'], textColor=C_WARNING),
                    ))
                csp_q = check.get('csp_quality')
                if csp_q:
                    block.append(Paragraph(
                        f'CSP quality: {csp_q["rating"].upper()}' +
                        (f' — {"; ".join(csp_q["issues"])}' if csp_q['issues'] else ''),
                        self.s['small'],
                    ))

            elif key == 'cookies':
                for c in check.get('insecure_cookies', []):
                    block.append(Paragraph(
                        f'  Cookie "{c["name"]}" — missing: {", ".join(c["missing_flags"])}',
                        self.s['small'],
                    ))

            elif key == 'ports':
                for p in check.get('open_ports', []):
                    block.append(Paragraph(
                        f'  Port {p["port"]}: {p["description"]}',
                        self.s['small'],
                    ))

            story.append(KeepTogether(block))

        story.append(Spacer(1, 10))
        return story

    # ── Remediation Plan ─────────────────────────────────────────────────────
    def _remediation_plan(self, checks, score):
        story = [Paragraph('Remediation Plan', self.s['section'])]
        items = []

        https = checks.get('https', {})
        if not https.get('https_available'):
            items.append(('[CRITICAL]', 'Enable HTTPS',
                          "Obtain a TLS certificate (free via Let's Encrypt) and configure port 443. "
                          'Most hosting panels offer one-click HTTPS activation.'))
        if not https.get('redirects_to_https'):
            items.append(('[HIGH]', 'Enforce HTTPS redirect',
                          'Apache .htaccess: <font name="Courier">Redirect 301 / https://yourdomain.com/</font> — '
                          'Nginx: <font name="Courier">return 301 https://$host$request_uri;</font>'))

        ssl = checks.get('ssl', {})
        if ssl.get('expires_soon'):
            items.append(('[HIGH]', 'Renew SSL certificate',
                          f'Certificate expires in {ssl.get("days_until_expiry", "?")} days. '
                          'Run: <font name="Courier">certbot renew</font>'))
        if not ssl.get('valid'):
            items.append(('[CRITICAL]', 'Fix SSL certificate',
                          'Replace self-signed or expired certificate with a CA-signed one.'))

        cors = checks.get('cors', {})
        if cors.get('credentials_with_wildcard'):
            items.append(('[CRITICAL]', 'Fix CORS misconfiguration',
                          'Remove wildcard origin or disable credentials: replace '
                          '<font name="Courier">Access-Control-Allow-Origin: *</font> with an explicit origin.'))
        elif cors.get('wildcard_origin'):
            items.append(('[MEDIUM]', 'Restrict CORS origin',
                          'Replace <font name="Courier">Access-Control-Allow-Origin: *</font> '
                          'with <font name="Courier">Access-Control-Allow-Origin: https://your-app.com</font>'))

        missing_headers = checks.get('headers', {}).get('headers_missing', [])
        if 'Strict-Transport-Security' in missing_headers:
            items.append(('[HIGH]', 'Add HSTS header',
                          '<font name="Courier">Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</font>'))
        if 'Content-Security-Policy' in missing_headers:
            items.append(('[HIGH]', 'Add Content-Security-Policy',
                          'Start strict: <font name="Courier">Content-Security-Policy: default-src \'self\'</font> '
                          'then progressively allow required sources.'))
        if 'X-Frame-Options' in missing_headers:
            items.append(('[MEDIUM]', 'Add X-Frame-Options',
                          '<font name="Courier">X-Frame-Options: SAMEORIGIN</font>'))
        if 'X-Content-Type-Options' in missing_headers:
            items.append(('[MEDIUM]', 'Add X-Content-Type-Options',
                          '<font name="Courier">X-Content-Type-Options: nosniff</font>'))

        if checks.get('cookies', {}).get('insecure_cookies'):
            items.append(('[MEDIUM]', 'Fix cookie flags',
                          'Set all auth cookies: '
                          '<font name="Courier">Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax</font>'))

        if checks.get('tech', {}).get('version_disclosed'):
            items.append(('[LOW]', 'Remove version disclosure',
                          'Nginx: <font name="Courier">server_tokens off;</font> — '
                          'Apache: <font name="Courier">ServerTokens Prod</font>'))

        open_ports = checks.get('ports', {}).get('open_ports', [])
        if open_ports:
            ports_str = ', '.join(str(p['port']) for p in open_ports)
            items.append(('[MEDIUM]', f'Close unnecessary ports ({ports_str})',
                          f'Example: <font name="Courier">ufw deny {open_ports[0]["port"]}</font>'))

        if not items:
            story.append(Paragraph('✓ No remediation required. Continue monitoring.', self.s['finding_ok']))
        else:
            for i, (priority, title, detail) in enumerate(items, 1):
                col = (C_DANGER if 'CRITICAL' in priority
                       else C_WARNING if 'HIGH' in priority
                       else C_MUTED)
                row_tbl = Table([[
                    Paragraph(f'<b>{i}</b>', self.s['center']),
                    Paragraph(f'<font color="#{col.hexval()}"><b>{priority}</b></font>', self.s['small']),
                    [Paragraph(f'<b>{title}</b>', self.s['body']),
                     Paragraph(detail, self.s['small'])],
                ]], colWidths=[20, 65, '*'])
                row_tbl.setStyle(TableStyle([
                    ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
                    ('TOPPADDING',    (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('LEFTPADDING',   (0, 0), (-1, -1), 6),
                    ('BACKGROUND',    (0, 0), (-1, -1),
                     C_SURFACE if i % 2 else HexColor('#0f1214')),
                    ('LINEBELOW',     (0, 0), (-1, -1), 0.5, C_BORDER),
                ]))
                story.append(row_tbl)

        story.append(Spacer(1, 16))
        return story

    # ── Footer note ──────────────────────────────────────────────────────────
    def _footer_note(self):
        return [
            HRFlowable(width='100%', thickness=0.5, color=C_BORDER, spaceBefore=10, spaceAfter=8),
            Paragraph(
                f'Generated by {self.brand_name} — automated security analysis. '
                'This report is a point-in-time snapshot and does not replace a manual penetration test.',
                self.s['small'],
            ),
        ]

    # ── Page background & numbering ──────────────────────────────────────────
    def _page_template(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        canvas.setFillColor(self.brand_color)
        canvas.rect(0, A4[1] - 3, A4[0], 3, fill=1, stroke=0)
        canvas.setFillColor(C_MUTED)
        canvas.setFont('Helvetica', 8)
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f'Page {doc.page}')
        canvas.restoreState()
