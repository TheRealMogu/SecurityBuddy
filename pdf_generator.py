"""
PDF Report Generator for Security Buddy
"""
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.graphics.shapes import Drawing, Circle, Rect
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF
import io

class SecurityReportPDF:
    def __init__(self):
        self.primary_color = HexColor('#007AFF')
        self.success_color = HexColor('#34C759')
        self.warning_color = HexColor('#FF9500')
        self.danger_color = HexColor('#FF3B30')
        
    def generate_report(self, scan_result, user_info=None):
        """Generate a professional PDF report from scan results"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, 
                              rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=18)
        
        # Parse results if it's a string
        if isinstance(scan_result.results, str):
            results = json.loads(scan_result.results)
        else:
            results = scan_result.results
        
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=self.primary_color,
            alignment=TA_CENTER
        )
        
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=self.primary_color
        )
        
        # Title
        story.append(Paragraph("Security Analysis Report", title_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        score = results.get('overall_score', 0)
        risk_level = results.get('risk_level', 'unknown')
        
        summary_data = [
            ['Target:', scan_result.target],
            ['Scan Date:', scan_result.created_at.strftime('%Y-%m-%d %H:%M UTC')],
            ['Security Score:', f"{score}/100"],
            ['Risk Level:', risk_level.title()],
        ]
        
        if user_info:
            summary_data.insert(0, ['Organization:', user_info.get('organization', 'N/A')])
        
        summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#F5F7FA')),
            ('TEXTCOLOR', (0, 0), (-1, -1), HexColor('#1D2B36')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#E2E5E9')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [HexColor('#FFFFFF'), HexColor('#F5F7FA')])
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 30))
        
        # Risk Assessment
        story.append(Paragraph("Risk Assessment", subtitle_style))
        
        risk_color = self._get_risk_color(score)
        risk_text = self._get_risk_description(score, risk_level)
        
        story.append(Paragraph(risk_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Detailed Findings
        story.append(Paragraph("Detailed Security Analysis", subtitle_style))
        
        checks = results.get('checks', {})
        
        # HTTPS Analysis
        if 'https' in checks:
            story.extend(self._create_check_section("HTTPS Security", checks['https']))
        
        # SSL Certificate
        if 'ssl' in checks:
            story.extend(self._create_check_section("SSL Certificate", checks['ssl']))
        
        # Security Headers
        if 'headers' in checks:
            story.extend(self._create_check_section("Security Headers", checks['headers']))
        
        # Domain Information
        if 'domain_info' in checks:
            story.extend(self._create_check_section("Domain Information", checks['domain_info']))
        
        # Recommendations
        story.append(Paragraph("Security Recommendations", subtitle_style))
        recommendations = self._generate_recommendations(checks, score)
        
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
            story.append(Spacer(1, 6))
        
        story.append(Spacer(1, 30))
        
        # Footer
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=10,
            textColor=HexColor('#8E95A9'),
            alignment=TA_CENTER
        )
        
        story.append(Paragraph(
            "Generated by Security Buddy - Professional Web Security Scanner<br/>For more information, visit securitybuddy.app",
            footer_style
        ))
        
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def _get_risk_color(self, score):
        """Get color based on security score"""
        if score >= 80:
            return self.success_color
        elif score >= 60:
            return self.warning_color
        else:
            return self.danger_color
    
    def _get_risk_description(self, score, risk_level):
        """Get risk description based on score"""
        descriptions = {
            'low': "Your website demonstrates good security practices with minimal vulnerabilities detected.",
            'medium': "Your website has moderate security with some areas that need attention.",
            'high': "Several security issues were identified that should be addressed promptly.",
            'critical': "Critical security vulnerabilities detected requiring immediate attention."
        }
        return descriptions.get(risk_level, "Security assessment completed.")
    
    def _create_check_section(self, title, check_data):
        """Create a section for each security check"""
        story = []
        styles = getSampleStyleSheet()
        
        section_style = ParagraphStyle(
            'SectionTitle',
            parent=styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            spaceBefore=16,
            textColor=self.primary_color
        )
        
        story.append(Paragraph(title, section_style))
        
        # Create findings table
        findings = []
        
        if isinstance(check_data, dict):
            score = check_data.get('score', 0)
            issues = check_data.get('issues', [])
            
            if title == "HTTPS Security":
                findings.append(['HTTPS Available:', '✓' if check_data.get('https_available') else '✗'])
                findings.append(['HTTP Redirects to HTTPS:', '✓' if check_data.get('redirects_to_https') else '✗'])
            
            elif title == "SSL Certificate":
                findings.append(['Certificate Valid:', '✓' if check_data.get('valid') else '✗'])
                if check_data.get('days_until_expiry'):
                    findings.append(['Days Until Expiry:', str(check_data.get('days_until_expiry'))])
                if check_data.get('issuer'):
                    findings.append(['Certificate Issuer:', check_data.get('issuer')])
            
            elif title == "Security Headers":
                headers_found = check_data.get('headers_found', [])
                headers_missing = check_data.get('headers_missing', [])
                findings.append(['Headers Found:', str(len(headers_found))])
                findings.append(['Headers Missing:', str(len(headers_missing))])
                
                if headers_missing:
                    for header in headers_missing[:3]:  # Show first 3 missing headers
                        findings.append(['Missing:', header])
            
            # Add issues if any
            if issues:
                for issue in issues[:3]:  # Show first 3 issues
                    findings.append(['Issue:', issue])
        
        if findings:
            findings_table = Table(findings, colWidths=[2*inch, 3*inch])
            findings_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#E2E5E9')),
            ]))
            story.append(findings_table)
        
        story.append(Spacer(1, 12))
        return story
    
    def _generate_recommendations(self, checks, score):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # HTTPS recommendations
        https_data = checks.get('https', {})
        if not https_data.get('https_available'):
            recommendations.append("Enable HTTPS encryption to protect data in transit")
        if not https_data.get('redirects_to_https'):
            recommendations.append("Configure automatic HTTP to HTTPS redirects")
        
        # SSL recommendations
        ssl_data = checks.get('ssl', {})
        if ssl_data.get('expires_soon'):
            recommendations.append("Renew SSL certificate before expiration")
        if not ssl_data.get('valid'):
            recommendations.append("Fix SSL certificate configuration issues")
        
        # Headers recommendations
        headers_data = checks.get('headers', {})
        missing_headers = headers_data.get('headers_missing', [])
        if 'Strict-Transport-Security' in missing_headers:
            recommendations.append("Implement HSTS (HTTP Strict Transport Security) header")
        if 'Content-Security-Policy' in missing_headers:
            recommendations.append("Add Content Security Policy to prevent XSS attacks")
        if 'X-Frame-Options' in missing_headers:
            recommendations.append("Configure X-Frame-Options to prevent clickjacking")
        
        # General recommendations based on score
        if score < 60:
            recommendations.append("Consider a comprehensive security audit")
            recommendations.append("Implement a Web Application Firewall (WAF)")
        
        if not recommendations:
            recommendations.append("Your website demonstrates good security practices. Continue monitoring regularly.")
        
        return recommendations[:5]  # Return top 5 recommendations