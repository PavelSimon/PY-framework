import smtplib
import secrets
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Tuple
from ..config import settings


class EmailService:
    def __init__(self):
        self.smtp_server = settings.smtp_server
        self.smtp_port = settings.smtp_port
        self.smtp_username = settings.smtp_username
        self.smtp_password = settings.smtp_password
        self.smtp_use_tls = settings.smtp_use_tls
        self.from_email = settings.from_email

    def _create_smtp_connection(self):
        """Create and return an authenticated SMTP connection"""
        if not all([self.smtp_server, self.smtp_username, self.smtp_password, self.from_email]):
            raise ValueError("Email configuration is incomplete. Check SMTP settings.")
        
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            if self.smtp_use_tls:
                server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            return server
        except Exception as e:
            raise Exception(f"Failed to connect to email server: {str(e)}")

    def send_email(self, to_email: str, subject: str, html_body: str, text_body: str = None) -> bool:
        """Send an email with both HTML and text content"""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = to_email

            if text_body:
                part1 = MIMEText(text_body, 'plain')
                msg.attach(part1)

            part2 = MIMEText(html_body, 'html')
            msg.attach(part2)

            with self._create_smtp_connection() as server:
                server.send_message(msg)
            
            print(f"Email sent successfully to {to_email}")
            return True
        
        except Exception as e:
            print(f"Failed to send email to {to_email}: {str(e)}")
            return False

    def send_verification_email(self, to_email: str, token: str, user_name: str = None) -> bool:
        """Send email verification email"""
        verification_url = f"http://localhost:8000/auth/verify/{token}"
        
        display_name = user_name or to_email.split('@')[0]
        
        subject = "Verify Your Email - PY-Framework"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
                .content {{ background: #f8fafc; padding: 30px; border-radius: 0 0 5px 5px; }}
                .button {{ display: inline-block; padding: 12px 30px; background: #2563eb; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 20px; color: #64748b; font-size: 14px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚀 PY-Framework</h1>
                </div>
                <div class="content">
                    <h2>Welcome, {display_name}!</h2>
                    <p>Thank you for registering with PY-Framework. Please verify your email address to complete your registration.</p>
                    
                    <p><a href="{verification_url}" class="button">Verify Email Address</a></p>
                    
                    <p>If the button doesn't work, copy and paste this link into your browser:</p>
                    <p><code>{verification_url}</code></p>
                    
                    <p><strong>This link will expire in 24 hours.</strong></p>
                    
                    <p>If you didn't create an account with us, please ignore this email.</p>
                </div>
                <div class="footer">
                    <p>Secure web application built with PY-Framework</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
        Welcome to PY-Framework!
        
        Hi {display_name},
        
        Thank you for registering with PY-Framework. Please verify your email address by visiting:
        
        {verification_url}
        
        This link will expire in 24 hours.
        
        If you didn't create an account with us, please ignore this email.
        
        --
        PY-Framework Team
        """
        
        return self.send_email(to_email, subject, html_body, text_body)

    def send_password_reset_email(self, to_email: str, token: str, user_name: str = None) -> bool:
        """Send password reset email"""
        reset_url = f"http://localhost:8000/auth/reset-password/{token}"
        
        display_name = user_name or to_email.split('@')[0]
        
        subject = "Reset Your Password - PY-Framework"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #dc2626; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
                .content {{ background: #f8fafc; padding: 30px; border-radius: 0 0 5px 5px; }}
                .button {{ display: inline-block; padding: 12px 30px; background: #dc2626; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 20px; color: #64748b; font-size: 14px; }}
                .warning {{ background: #fef2f2; border: 1px solid #fecaca; padding: 15px; border-radius: 5px; margin: 15px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Password Reset</h1>
                </div>
                <div class="content">
                    <h2>Hi {display_name},</h2>
                    <p>We received a request to reset your password for your PY-Framework account.</p>
                    
                    <p><a href="{reset_url}" class="button">Reset Password</a></p>
                    
                    <p>If the button doesn't work, copy and paste this link into your browser:</p>
                    <p><code>{reset_url}</code></p>
                    
                    <div class="warning">
                        <p><strong>⚠️ Important:</strong></p>
                        <ul>
                            <li>This link will expire in 1 hour</li>
                            <li>If you didn't request this reset, please ignore this email</li>
                            <li>Your password will remain unchanged until you use this link</li>
                        </ul>
                    </div>
                </div>
                <div class="footer">
                    <p>Secure web application built with PY-Framework</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
        Password Reset Request - PY-Framework
        
        Hi {display_name},
        
        We received a request to reset your password for your PY-Framework account.
        
        Reset your password by visiting:
        {reset_url}
        
        IMPORTANT:
        - This link will expire in 1 hour
        - If you didn't request this reset, please ignore this email
        - Your password will remain unchanged until you use this link
        
        --
        PY-Framework Team
        """
        
        return self.send_email(to_email, subject, html_body, text_body)

    def generate_verification_token(self, db, user_id: int) -> str:
        """Generate and store email verification token"""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=settings.email_verification_expire_hours)
        
        db.conn.execute("""
            INSERT INTO email_verification_tokens (user_id, token, expires_at)
            VALUES (?, ?, ?)
        """, [user_id, token, expires_at])
        
        return token

    def generate_password_reset_token(self, db, user_id: int) -> str:
        """Generate and store password reset token"""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=settings.password_reset_expire_hours)
        
        # Invalidate any existing password reset tokens for this user
        db.conn.execute("""
            UPDATE password_reset_tokens 
            SET used_at = CURRENT_TIMESTAMP 
            WHERE user_id = ? AND used_at IS NULL
        """, [user_id])
        
        # Create new token
        db.conn.execute("""
            INSERT INTO password_reset_tokens (user_id, token, expires_at)
            VALUES (?, ?, ?)
        """, [user_id, token, expires_at])
        
        return token

    def verify_email_token(self, db, token: str) -> Tuple[bool, Optional[int], str]:
        """Verify email verification token and return user_id if valid"""
        cursor = db.conn.execute("""
            SELECT user_id, expires_at, used_at 
            FROM email_verification_tokens 
            WHERE token = ?
        """, [token])
        
        row = cursor.fetchone()
        if not row:
            return False, None, "Invalid verification token"
        
        user_id, expires_at, used_at = row
        
        if used_at:
            return False, None, "Verification token has already been used"
        
        if expires_at < datetime.now():
            return False, None, "Verification token has expired"
        
        # Mark token as used
        db.conn.execute("""
            UPDATE email_verification_tokens 
            SET used_at = CURRENT_TIMESTAMP 
            WHERE token = ?
        """, [token])
        
        # Mark user as verified
        db.verify_user_email(user_id)
        
        return True, user_id, "Email verified successfully"

    def verify_password_reset_token(self, db, token: str) -> Tuple[bool, Optional[int], str]:
        """Verify password reset token and return user_id if valid"""
        cursor = db.conn.execute("""
            SELECT user_id, expires_at, used_at 
            FROM password_reset_tokens 
            WHERE token = ?
        """, [token])
        
        row = cursor.fetchone()
        if not row:
            return False, None, "Invalid reset token"
        
        user_id, expires_at, used_at = row
        
        if used_at:
            return False, None, "Reset token has already been used"
        
        if expires_at < datetime.now():
            return False, None, "Reset token has expired"
        
        return True, user_id, "Reset token is valid"

    def mark_password_reset_token_used(self, db, token: str):
        """Mark password reset token as used"""
        db.conn.execute("""
            UPDATE password_reset_tokens 
            SET used_at = CURRENT_TIMESTAMP 
            WHERE token = ?
        """, [token])

    def send_test_email(self, to_email: str) -> bool:
        """Send a test email to verify email configuration"""
        try:
            test_subject = "PY-Framework Email Test"
            test_body = f"""
            <h2>Email Configuration Test</h2>
            <p>This is a test email sent to {to_email} to verify your PY-Framework email configuration is working correctly.</p>
            <p>If you receive this email, your SMTP settings are properly configured!</p>
            <p><strong>Framework:</strong> PY-Framework</p>
            <p><strong>Test Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            """
            
            return self.send_email(to_email, test_subject, test_body)
        
        except Exception as e:
            print(f"Test email failed: {str(e)}")
            return False

    def test_email_configuration(self) -> Tuple[bool, str]:
        """Test email configuration by sending a test email"""
        if not self.from_email:
            return False, "No from_email configured"
        
        try:
            test_subject = "PY-Framework Email Test"
            test_body = """
            <h2>Email Configuration Test</h2>
            <p>This is a test email to verify your PY-Framework email configuration is working correctly.</p>
            <p>If you receive this email, your SMTP settings are properly configured!</p>
            """
            
            success = self.send_email(self.from_email, test_subject, test_body)
            if success:
                return True, "Test email sent successfully"
            else:
                return False, "Failed to send test email"
        
        except Exception as e:
            return False, f"Email configuration test failed: {str(e)}"