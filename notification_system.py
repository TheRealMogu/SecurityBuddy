"""
Notification system for Security Buddy including email alerts and monitoring
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
from datetime import datetime, timedelta
from models import User, ScanResult
from app import db
import json

class NotificationSystem:
    def __init__(self):
        self.smtp_configured = False
        
    def send_scan_complete_email(self, user_email, scan_result, pdf_buffer=None):
        """Send email notification when scan is complete"""
        if not self._check_email_config():
            return False, "Email service not configured"
        
        try:
            # Parse results
            if isinstance(scan_result.results, str):
                results = json.loads(scan_result.results)
            else:
                results = scan_result.results
            
            subject = f"Security Scan Complete: {scan_result.target}"
            
            # Create email content
            html_content = self._create_scan_email_template(scan_result, results)
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = os.environ.get('SMTP_FROM_EMAIL', 'noreply@securitybuddy.app')
            msg['To'] = user_email
            
            # Add HTML content
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Add PDF attachment if provided
            if pdf_buffer:
                pdf_part = MIMEBase('application', 'octet-stream')
                pdf_part.set_payload(pdf_buffer.read())
                encoders.encode_base64(pdf_part)
                pdf_part.add_header(
                    'Content-Disposition',
                    f'attachment; filename="security_report_{scan_result.target}_{datetime.now().strftime("%Y%m%d")}.pdf"'
                )
                msg.attach(pdf_part)
            
            # Send email
            return self._send_email(msg)
            
        except Exception as e:
            return False, f"Failed to send email: {str(e)}"
    
    def send_vulnerability_alert(self, user_email, scan_result, critical_issues):
        """Send immediate alert for critical vulnerabilities"""
        if not self._check_email_config():
            return False, "Email service not configured"
        
        try:
            subject = f"🚨 Critical Security Issues Detected: {scan_result.target}"
            
            html_content = f"""
            <html>
            <body style="font-family: 'Inter', Arial, sans-serif; color: #1D2B36; line-height: 1.6;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background: linear-gradient(135deg, #FF3B30, #FF6B6B); color: white; padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 30px;">
                        <h1 style="margin: 0; font-size: 24px;">⚠️ Critical Security Alert</h1>
                        <p style="margin: 10px 0 0 0; opacity: 0.9;">Immediate attention required for {scan_result.target}</p>
                    </div>
                    
                    <div style="background: #FFF5F5; border-left: 4px solid #FF3B30; padding: 20px; margin-bottom: 20px;">
                        <h2 style="color: #FF3B30; margin-top: 0;">Critical Issues Detected</h2>
                        <ul>
            """
            
            for issue in critical_issues[:5]:  # Show top 5 critical issues
                html_content += f"<li style='margin-bottom: 8px;'>{issue}</li>"
            
            html_content += f"""
                        </ul>
                    </div>
                    
                    <div style="background: #F5F7FA; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                        <h3 style="margin-top: 0; color: #1D2B36;">Recommended Actions</h3>
                        <ol>
                            <li>Review and address the critical issues immediately</li>
                            <li>Contact your web developer or system administrator</li>
                            <li>Consider implementing a Web Application Firewall (WAF)</li>
                            <li>Schedule regular security monitoring</li>
                        </ol>
                    </div>
                    
                    <div style="text-align: center; margin-top: 30px;">
                        <a href="https://securitybuddy.app/scan/{scan_result.id}" 
                           style="background: #007AFF; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; display: inline-block; font-weight: 600;">
                            View Full Report
                        </a>
                    </div>
                    
                    <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #E2E5E9; color: #8E95A9; font-size: 14px;">
                        <p>This alert was generated by Security Buddy<br>
                        Scan completed on {scan_result.created_at.strftime('%Y-%m-%d at %H:%M UTC')}</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = os.environ.get('SMTP_FROM_EMAIL', 'noreply@securitybuddy.app')
            msg['To'] = user_email
            
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            return self._send_email(msg)
            
        except Exception as e:
            return False, f"Failed to send alert: {str(e)}"
    
    def send_monitoring_summary(self, user_email, user_id, period_days=7):
        """Send weekly/monthly monitoring summary"""
        if not self._check_email_config():
            return False, "Email service not configured"
        
        try:
            # Get scans for the period
            start_date = datetime.utcnow() - timedelta(days=period_days)
            scans = ScanResult.query.filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= start_date
            ).order_by(ScanResult.created_at.desc()).all()
            
            if not scans:
                return True, "No scans in period"
            
            # Calculate statistics
            total_scans = len(scans)
            avg_score = sum(scan.security_score for scan in scans) / total_scans
            unique_domains = len(set(scan.target for scan in scans))
            
            # Find trends
            scores = [scan.security_score for scan in scans]
            trend = "improving" if len(scores) > 1 and scores[0] > scores[-1] else "stable"
            
            subject = f"Security Monitoring Summary - {period_days} Day Report"
            
            html_content = self._create_monitoring_email_template(
                total_scans, avg_score, unique_domains, trend, scans[:5], period_days
            )
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = os.environ.get('SMTP_FROM_EMAIL', 'noreply@securitybuddy.app')
            msg['To'] = user_email
            
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            return self._send_email(msg)
            
        except Exception as e:
            return False, f"Failed to send summary: {str(e)}"
    
    def _create_scan_email_template(self, scan_result, results):
        """Create HTML email template for scan completion"""
        score = results.get('overall_score', 0)
        risk_level = results.get('risk_level', 'unknown')
        
        # Determine colors based on score
        if score >= 80:
            score_color = "#34C759"
            risk_bg = "#F0FDF4"
        elif score >= 60:
            score_color = "#FF9500"
            risk_bg = "#FFFBEB"
        else:
            score_color = "#FF3B30"
            risk_bg = "#FFF5F5"
        
        return f"""
        <html>
        <body style="font-family: 'Inter', Arial, sans-serif; color: #1D2B36; line-height: 1.6;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #007AFF, #0056CC); color: white; padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 30px;">
                    <h1 style="margin: 0; font-size: 24px;">🛡️ Security Scan Complete</h1>
                    <p style="margin: 10px 0 0 0; opacity: 0.9;">Your website security analysis is ready</p>
                </div>
                
                <div style="background: {risk_bg}; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center;">
                    <h2 style="margin: 0 0 10px 0; color: {score_color}; font-size: 32px;">{score}/100</h2>
                    <p style="margin: 0; font-size: 18px; font-weight: 600; color: #1D2B36;">{scan_result.target}</p>
                    <p style="margin: 5px 0 0 0; color: #8E95A9;">Risk Level: {risk_level.title()}</p>
                </div>
                
                <div style="background: #F5F7FA; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-top: 0; color: #1D2B36;">Key Findings</h3>
                    <ul style="margin: 0; padding-left: 20px;">
                        <li>HTTPS Status: {'✅ Enabled' if results.get('checks', {}).get('https', {}).get('https_available') else '❌ Not Enabled'}</li>
                        <li>SSL Certificate: {'✅ Valid' if results.get('checks', {}).get('ssl', {}).get('valid') else '❌ Issues Detected'}</li>
                        <li>Security Headers: {len(results.get('checks', {}).get('headers', {}).get('headers_found', []))} found</li>
                    </ul>
                </div>
                
                <div style="text-align: center; margin-top: 30px;">
                    <a href="https://securitybuddy.app/scan/{scan_result.id}" 
                       style="background: #007AFF; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; display: inline-block; font-weight: 600;">
                        View Full Report
                    </a>
                </div>
                
                <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #E2E5E9; color: #8E95A9; font-size: 14px;">
                    <p>Generated by Security Buddy - Professional Web Security Scanner<br>
                    Scan completed on {scan_result.created_at.strftime('%Y-%m-%d at %H:%M UTC')}</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def _create_monitoring_email_template(self, total_scans, avg_score, unique_domains, trend, recent_scans, period_days):
        """Create monitoring summary email template"""
        return f"""
        <html>
        <body style="font-family: 'Inter', Arial, sans-serif; color: #1D2B36; line-height: 1.6;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #007AFF, #0056CC); color: white; padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 30px;">
                    <h1 style="margin: 0; font-size: 24px;">📊 Security Monitoring Summary</h1>
                    <p style="margin: 10px 0 0 0; opacity: 0.9;">{period_days}-day security overview</p>
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 30px;">
                    <div style="background: #F5F7FA; padding: 20px; border-radius: 8px; text-align: center;">
                        <h3 style="margin: 0; color: #007AFF; font-size: 24px;">{total_scans}</h3>
                        <p style="margin: 5px 0 0 0; color: #8E95A9;">Total Scans</p>
                    </div>
                    <div style="background: #F5F7FA; padding: 20px; border-radius: 8px; text-align: center;">
                        <h3 style="margin: 0; color: #007AFF; font-size: 24px;">{avg_score:.0f}</h3>
                        <p style="margin: 5px 0 0 0; color: #8E95A9;">Avg Score</p>
                    </div>
                </div>
                
                <div style="background: #F5F7FA; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-top: 0; color: #1D2B36;">Recent Activity</h3>
                    <ul style="margin: 0; padding-left: 20px;">
        """
        
        for scan in recent_scans:
            html_content += f"<li>{scan.target}: {scan.security_score}/100 ({scan.created_at.strftime('%m/%d')})</li>"
        
        html_content += f"""
                    </ul>
                </div>
                
                <div style="text-align: center; margin-top: 30px;">
                    <a href="https://securitybuddy.app/dashboard" 
                       style="background: #007AFF; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; display: inline-block; font-weight: 600;">
                        View Dashboard
                    </a>
                </div>
                
                <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #E2E5E9; color: #8E95A9; font-size: 14px;">
                    <p>Security Buddy - Keeping your websites secure<br>
                    Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M UTC')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html_content
    
    def _check_email_config(self):
        """Check if email configuration is available"""
        required_vars = ['SMTP_SERVER', 'SMTP_PORT', 'SMTP_USERNAME', 'SMTP_PASSWORD']
        return all(os.environ.get(var) for var in required_vars)
    
    def _send_email(self, msg):
        """Send email using SMTP configuration"""
        try:
            smtp_server = os.environ.get('SMTP_SERVER')
            smtp_port = int(os.environ.get('SMTP_PORT', 587))
            smtp_username = os.environ.get('SMTP_USERNAME')
            smtp_password = os.environ.get('SMTP_PASSWORD')
            
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(smtp_username, smtp_password)
            
            text = msg.as_string()
            server.sendmail(msg['From'], msg['To'], text)
            server.quit()
            
            return True, "Email sent successfully"
            
        except Exception as e:
            return False, f"SMTP error: {str(e)}"

class MonitoringScheduler:
    def __init__(self):
        self.notification_system = NotificationSystem()
    
    def schedule_domain_monitoring(self, user_id, domain, frequency='weekly'):
        """Schedule automated monitoring for a domain"""
        # This would integrate with APScheduler or Celery for production
        pass
    
    def check_scheduled_scans(self):
        """Check and execute scheduled scans"""
        # This would be called by a cron job or scheduler
        pass