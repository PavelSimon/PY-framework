"""
Two-Factor Authentication (2FA) implementation using TOTP
"""

import secrets
import base64
import qrcode
import io
from typing import Optional, Tuple
import pyotp
from datetime import datetime, timedelta

from ..database.database import Database


class TOTPService:
    """Service for managing TOTP-based Two-Factor Authentication"""
    
    def __init__(self, db: Database = None):
        self.db = db or Database()
        self.issuer = "PY-Framework"
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret key"""
        return pyotp.random_base32()
    
    def create_totp_uri(self, secret: str, email: str) -> str:
        """Create TOTP URI for QR code generation"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=email,
            issuer_name=self.issuer
        )
    
    def generate_qr_code(self, totp_uri: str) -> bytes:
        """Generate QR code image for TOTP setup"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        return img_buffer.getvalue()
    
    def verify_totp_code(self, secret: str, code: str, window: int = 1) -> bool:
        """Verify TOTP code with tolerance window"""
        if not secret or not code:
            return False
        
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(code, valid_window=window)
        except Exception as e:
            print(f"TOTP verification error: {e}")
            return False
    
    def enable_2fa_for_user(self, user_id: int, secret: str) -> bool:
        """Enable 2FA for a user"""
        try:
            # Remove any existing 2FA setup for this user
            self.db.conn.execute("""
                DELETE FROM totp_secrets WHERE user_id = ?
            """, [user_id])
            
            # Insert new 2FA secret
            self.db.conn.execute("""
                INSERT INTO totp_secrets (user_id, secret, enabled, created_at)
                VALUES (?, ?, TRUE, CURRENT_TIMESTAMP)
            """, [user_id, secret])
            
            # Update user to indicate 2FA is enabled
            self.db.conn.execute("""
                UPDATE users SET two_factor_enabled = TRUE WHERE id = ?
            """, [user_id])
            
            return True
        except Exception as e:
            print(f"Error enabling 2FA: {e}")
            return False
    
    def disable_2fa_for_user(self, user_id: int) -> bool:
        """Disable 2FA for a user"""
        try:
            # Remove 2FA secret
            self.db.conn.execute("""
                DELETE FROM totp_secrets WHERE user_id = ?
            """, [user_id])
            
            # Update user to indicate 2FA is disabled
            self.db.conn.execute("""
                UPDATE users SET two_factor_enabled = FALSE WHERE id = ?
            """, [user_id])
            
            # Remove any backup codes
            self.db.conn.execute("""
                DELETE FROM backup_codes WHERE user_id = ?
            """, [user_id])
            
            return True
        except Exception as e:
            print(f"Error disabling 2FA: {e}")
            return False
    
    def get_user_totp_secret(self, user_id: int) -> Optional[str]:
        """Get user's TOTP secret if 2FA is enabled"""
        cursor = self.db.conn.execute("""
            SELECT secret FROM totp_secrets 
            WHERE user_id = ? AND enabled = TRUE
        """, [user_id])
        row = cursor.fetchone()
        return row[0] if row else None
    
    def is_2fa_enabled(self, user_id: int) -> bool:
        """Check if 2FA is enabled for user"""
        cursor = self.db.conn.execute("""
            SELECT COUNT(*) FROM totp_secrets 
            WHERE user_id = ? AND enabled = TRUE
        """, [user_id])
        count = cursor.fetchone()[0]
        return count > 0
    
    def generate_backup_codes(self, user_id: int, count: int = 8) -> list:
        """Generate backup codes for 2FA recovery"""
        try:
            # Remove existing backup codes
            self.db.conn.execute("""
                DELETE FROM backup_codes WHERE user_id = ?
            """, [user_id])
            
            backup_codes = []
            for _ in range(count):
                # Generate 8-character backup code
                code = secrets.token_hex(4).upper()
                backup_codes.append(code)
                
                # Store hashed version in database
                import hashlib
                code_hash = hashlib.sha256(code.encode()).hexdigest()
                
                self.db.conn.execute("""
                    INSERT INTO backup_codes (user_id, code_hash, created_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                """, [user_id, code_hash])
            
            return backup_codes
        except Exception as e:
            print(f"Error generating backup codes: {e}")
            return []
    
    def verify_backup_code(self, user_id: int, code: str) -> bool:
        """Verify and consume a backup code"""
        if not code:
            return False
        
        try:
            import hashlib
            code_hash = hashlib.sha256(code.strip().upper().encode()).hexdigest()
            
            # Check if backup code exists and hasn't been used
            cursor = self.db.conn.execute("""
                SELECT id FROM backup_codes 
                WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
            """, [user_id, code_hash])
            
            row = cursor.fetchone()
            if not row:
                return False
            
            code_id = row[0]
            
            # Mark backup code as used
            self.db.conn.execute("""
                UPDATE backup_codes 
                SET used_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            """, [code_id])
            
            return True
        except Exception as e:
            print(f"Error verifying backup code: {e}")
            return False
    
    def get_remaining_backup_codes_count(self, user_id: int) -> int:
        """Get count of remaining (unused) backup codes"""
        cursor = self.db.conn.execute("""
            SELECT COUNT(*) FROM backup_codes 
            WHERE user_id = ? AND used_at IS NULL
        """, [user_id])
        return cursor.fetchone()[0]
    
    def create_2fa_session_token(self, user_id: int) -> str:
        """Create temporary token for 2FA verification flow"""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(minutes=10)  # 10 minute expiry
        
        try:
            # Clean up expired tokens first
            self.db.conn.execute("""
                DELETE FROM two_factor_tokens 
                WHERE expires_at < CURRENT_TIMESTAMP
            """)
            
            # Insert new token
            self.db.conn.execute("""
                INSERT INTO two_factor_tokens (user_id, token, expires_at)
                VALUES (?, ?, ?)
            """, [user_id, token, expires_at])
            
            return token
        except Exception as e:
            print(f"Error creating 2FA session token: {e}")
            return None
    
    def verify_2fa_session_token(self, token: str) -> Optional[int]:
        """Verify 2FA session token and return user_id"""
        if not token:
            return None
        
        try:
            cursor = self.db.conn.execute("""
                SELECT user_id FROM two_factor_tokens 
                WHERE token = ? AND expires_at > CURRENT_TIMESTAMP
            """, [token])
            
            row = cursor.fetchone()
            if row:
                user_id = row[0]
                
                # Clean up the used token
                self.db.conn.execute("""
                    DELETE FROM two_factor_tokens WHERE token = ?
                """, [token])
                
                return user_id
            
            return None
        except Exception as e:
            print(f"Error verifying 2FA session token: {e}")
            return None
    
    def cleanup_expired_tokens(self):
        """Clean up expired 2FA session tokens"""
        try:
            self.db.conn.execute("""
                DELETE FROM two_factor_tokens 
                WHERE expires_at < CURRENT_TIMESTAMP
            """)
        except Exception as e:
            print(f"Error cleaning up expired 2FA tokens: {e}")


class TwoFactorAuthentication:
    """Main 2FA service combining TOTP and backup codes"""
    
    def __init__(self, db: Database = None):
        self.totp_service = TOTPService(db)
        self.db = db or Database()
    
    def setup_2fa(self, user_id: int, email: str) -> Tuple[str, str, bytes]:
        """Setup 2FA for user, return secret, URI, and QR code"""
        secret = self.totp_service.generate_secret()
        totp_uri = self.totp_service.create_totp_uri(secret, email)
        qr_code = self.totp_service.generate_qr_code(totp_uri)
        
        return secret, totp_uri, qr_code
    
    def confirm_2fa_setup(self, user_id: int, secret: str, verification_code: str) -> Tuple[bool, list]:
        """Confirm 2FA setup with verification code and generate backup codes"""
        if not self.totp_service.verify_totp_code(secret, verification_code):
            return False, []
        
        # Enable 2FA for user
        if not self.totp_service.enable_2fa_for_user(user_id, secret):
            return False, []
        
        # Generate backup codes
        backup_codes = self.totp_service.generate_backup_codes(user_id)
        
        return True, backup_codes
    
    def verify_2fa(self, user_id: int, code: str) -> bool:
        """Verify 2FA code (TOTP or backup code)"""
        if not code:
            return False
        
        # First try TOTP verification
        secret = self.totp_service.get_user_totp_secret(user_id)
        if secret and self.totp_service.verify_totp_code(secret, code):
            return True
        
        # If TOTP fails, try backup code
        return self.totp_service.verify_backup_code(user_id, code)
    
    def disable_2fa(self, user_id: int) -> bool:
        """Disable 2FA completely for user"""
        return self.totp_service.disable_2fa_for_user(user_id)
    
    def regenerate_backup_codes(self, user_id: int) -> list:
        """Regenerate backup codes for user"""
        if not self.totp_service.is_2fa_enabled(user_id):
            return []
        
        return self.totp_service.generate_backup_codes(user_id)
    
    def get_2fa_status(self, user_id: int) -> dict:
        """Get comprehensive 2FA status for user"""
        return {
            "enabled": self.totp_service.is_2fa_enabled(user_id),
            "backup_codes_remaining": self.totp_service.get_remaining_backup_codes_count(user_id)
        }