"""
Core Two-Factor Authentication (2FA) functionality tests
"""

import pytest
import tempfile
import os
import secrets
from datetime import datetime, timedelta
import pyotp

from src.framework.database import Database
from src.framework.auth import AuthenticationService
from src.framework.auth.totp import TOTPService, TwoFactorAuthentication


class Test2FACore:
    """Test core 2FA functionality"""
    
    def test_secret_generation(self):
        """Test TOTP secret generation"""
        totp_service = TOTPService()
        secret = totp_service.generate_secret()
        
        # Should be 32 characters (160 bits base32 encoded)
        assert len(secret) == 32
        # Should contain only valid base32 characters
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in secret)
    
    def test_totp_uri_creation(self):
        """Test TOTP URI creation"""
        # Use a minimal database for this test
        temp_file = tempfile.mktemp(suffix='.db')
        try:
            db = Database(temp_file)
            totp_service = TOTPService(db)
            secret = "JBSWY3DPEHPK3PXP"
            email = "test@example.com"
            
            uri = totp_service.create_totp_uri(secret, email)
            
            assert uri.startswith("otpauth://totp/")
            assert "test%40example.com" in uri or "test@example.com" in uri  # URL encoded or not
            assert secret in uri
            assert "PY-Framework" in uri
            
            db.close()
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def test_totp_code_verification(self):
        """Test TOTP code verification"""
        temp_file = tempfile.mktemp(suffix='.db')
        try:
            db = Database(temp_file)
            totp_service = TOTPService(db)
            secret = "JBSWY3DPEHPK3PXP"
            
            # Generate valid code
            totp = pyotp.TOTP(secret)
            code = totp.now()
            
            # Verify the code
            is_valid = totp_service.verify_totp_code(secret, code)
            assert is_valid
            
            # Invalid code should fail
            is_valid = totp_service.verify_totp_code(secret, "000000")
            assert not is_valid
            
            db.close()
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def test_qr_code_generation(self):
        """Test QR code generation"""
        temp_file = tempfile.mktemp(suffix='.db')
        try:
            db = Database(temp_file)
            totp_service = TOTPService(db)
            secret = "JBSWY3DPEHPK3PXP"
            email = "test@example.com"
            
            uri = totp_service.create_totp_uri(secret, email)
            qr_code = totp_service.generate_qr_code(uri)
            
            assert isinstance(qr_code, bytes)
            assert len(qr_code) > 0
            
            db.close()
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


class Test2FAService:
    """Test 2FA service with database integration"""
    
    @pytest.fixture
    def db_with_user(self):
        """Create database with test user"""
        temp_file = tempfile.mktemp(suffix='.db')
        db = Database(temp_file)
        
        # Create test user
        auth_service = AuthenticationService("test-secret-key")
        from src.framework.auth import UserRegistration
        
        registration = UserRegistration(
            email="test@example.com",
            password="TestPass123!",
            first_name="Test",
            last_name="User"
        )
        
        success, user_id, message = auth_service.register_user(db, registration)
        assert success
        
        yield db, user_id
        
        try:
            db.close()
            if os.path.exists(temp_file):
                os.unlink(temp_file)
        except:
            pass
    
    def test_2fa_status_disabled(self, db_with_user):
        """Test 2FA status for user without 2FA"""
        db, user_id = db_with_user
        two_fa = TwoFactorAuthentication(db)
        
        status = two_fa.get_2fa_status(user_id)
        assert not status["enabled"]
        assert status["backup_codes_remaining"] == 0
    
    def test_2fa_setup_and_confirm(self, db_with_user):
        """Test complete 2FA setup and confirmation"""
        db, user_id = db_with_user
        two_fa = TwoFactorAuthentication(db)
        
        # Setup 2FA
        secret, totp_uri, qr_code = two_fa.setup_2fa(user_id, "test@example.com")
        
        assert secret is not None
        assert len(secret) == 32
        assert totp_uri.startswith("otpauth://totp/")
        assert qr_code is not None
        
        # Confirm setup with valid code
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        success, backup_codes = two_fa.confirm_2fa_setup(user_id, secret, code)
        
        assert success
        assert len(backup_codes) == 8
        
        # Check status is now enabled
        status = two_fa.get_2fa_status(user_id)
        assert status["enabled"]
        assert status["backup_codes_remaining"] == 8
    
    def test_2fa_verification(self, db_with_user):
        """Test 2FA verification with TOTP and backup codes"""
        db, user_id = db_with_user
        two_fa = TwoFactorAuthentication(db)
        
        # Setup and confirm 2FA
        secret, _, _ = two_fa.setup_2fa(user_id, "test@example.com")
        totp = pyotp.TOTP(secret)
        code = totp.now()
        success, backup_codes = two_fa.confirm_2fa_setup(user_id, secret, code)
        assert success
        
        # Test TOTP verification
        new_code = totp.now()
        is_valid = two_fa.verify_2fa(user_id, new_code)
        assert is_valid
        
        # Test backup code verification
        backup_code = backup_codes[0]
        is_valid = two_fa.verify_2fa(user_id, backup_code)
        assert is_valid
        
        # Same backup code should not work again
        is_valid = two_fa.verify_2fa(user_id, backup_code)
        assert not is_valid
        
        # Backup code count should decrease
        status = two_fa.get_2fa_status(user_id)
        assert status["backup_codes_remaining"] == 7
    
    def test_backup_code_regeneration(self, db_with_user):
        """Test backup code regeneration"""
        db, user_id = db_with_user
        two_fa = TwoFactorAuthentication(db)
        
        # Setup and confirm 2FA
        secret, _, _ = two_fa.setup_2fa(user_id, "test@example.com")
        totp = pyotp.TOTP(secret)
        code = totp.now()
        success, original_codes = two_fa.confirm_2fa_setup(user_id, secret, code)
        assert success
        
        # Regenerate backup codes
        new_codes = two_fa.regenerate_backup_codes(user_id)
        
        assert len(new_codes) == 8
        assert set(new_codes) != set(original_codes)
        
        # Old codes should not work
        is_valid = two_fa.verify_2fa(user_id, original_codes[0])
        assert not is_valid
        
        # New codes should work
        is_valid = two_fa.verify_2fa(user_id, new_codes[0])
        assert is_valid
    
    def test_2fa_disable(self, db_with_user):
        """Test 2FA disabling"""
        db, user_id = db_with_user
        two_fa = TwoFactorAuthentication(db)
        totp_service = TOTPService(db)
        
        # Setup and confirm 2FA
        secret, _, _ = two_fa.setup_2fa(user_id, "test@example.com")
        totp = pyotp.TOTP(secret)
        code = totp.now()
        two_fa.confirm_2fa_setup(user_id, secret, code)
        
        # Verify 2FA is enabled
        assert totp_service.is_2fa_enabled(user_id)
        
        # Disable 2FA
        success = two_fa.disable_2fa(user_id)
        assert success
        
        # Verify 2FA is disabled
        assert not totp_service.is_2fa_enabled(user_id)
        
        status = two_fa.get_2fa_status(user_id)
        assert not status["enabled"]
        assert status["backup_codes_remaining"] == 0


class Test2FATokens:
    """Test 2FA session token functionality"""
    
    @pytest.fixture
    def db_with_user(self):
        """Create database with test user"""
        temp_file = tempfile.mktemp(suffix='.db')
        db = Database(temp_file)
        
        # Create test user
        auth_service = AuthenticationService("test-secret-key")
        from src.framework.auth import UserRegistration
        
        registration = UserRegistration(
            email="test@example.com",
            password="TestPass123!",
            first_name="Test",
            last_name="User"
        )
        
        success, user_id, message = auth_service.register_user(db, registration)
        assert success
        
        yield db, user_id
        
        try:
            db.close()
            if os.path.exists(temp_file):
                os.unlink(temp_file)
        except:
            pass
    
    def test_session_token_creation_and_verification(self, db_with_user):
        """Test 2FA session token creation and verification"""
        db, user_id = db_with_user
        totp_service = TOTPService(db)
        
        # Create token
        token = totp_service.create_2fa_session_token(user_id)
        assert token is not None
        assert len(token) > 20
        
        # Verify token
        verified_user_id = totp_service.verify_2fa_session_token(token)
        assert verified_user_id == user_id
        
        # Token should be consumed after verification
        verified_user_id = totp_service.verify_2fa_session_token(token)
        assert verified_user_id is None
    
    def test_invalid_session_token(self, db_with_user):
        """Test invalid session token verification"""
        db, user_id = db_with_user
        totp_service = TOTPService(db)
        
        # Invalid token should return None
        verified_user_id = totp_service.verify_2fa_session_token("invalid-token")
        assert verified_user_id is None
        
        # Empty token should return None
        verified_user_id = totp_service.verify_2fa_session_token("")
        assert verified_user_id is None


class Test2FAIntegration:
    """Test 2FA integration with authentication flow"""
    
    @pytest.fixture
    def db_with_2fa_user(self):
        """Create database with 2FA-enabled user"""
        temp_file = tempfile.mktemp(suffix='.db')
        db = Database(temp_file)
        
        # Create test user
        auth_service = AuthenticationService("test-secret-key")
        from src.framework.auth import UserRegistration
        
        registration = UserRegistration(
            email="test@example.com",
            password="TestPass123!",
            first_name="Test",
            last_name="User"
        )
        
        success, user_id, message = auth_service.register_user(db, registration)
        assert success
        
        # Enable 2FA
        two_fa = TwoFactorAuthentication(db)
        secret, _, _ = two_fa.setup_2fa(user_id, "test@example.com")
        
        totp = pyotp.TOTP(secret)
        code = totp.now()
        success, backup_codes = two_fa.confirm_2fa_setup(user_id, secret, code)
        assert success
        
        yield db, user_id, secret, backup_codes
        
        try:
            db.close()
            if os.path.exists(temp_file):
                os.unlink(temp_file)
        except:
            pass
    
    def test_complete_2fa_login_flow(self, db_with_2fa_user):
        """Test complete login flow with 2FA"""
        db, user_id, secret, backup_codes = db_with_2fa_user
        auth_service = AuthenticationService("test-secret-key")
        totp_service = TOTPService(db)
        two_fa = TwoFactorAuthentication(db)
        
        # Step 1: Regular authentication
        success, user, message = auth_service.authenticate_user(
            db, "test@example.com", "TestPass123!", "127.0.0.1"
        )
        assert success
        assert user["id"] == user_id
        
        # Step 2: Check 2FA requirement
        assert totp_service.is_2fa_enabled(user_id)
        
        # Step 3: Create 2FA session token
        token = totp_service.create_2fa_session_token(user_id)
        assert token is not None
        
        # Step 4: Verify session token and get user ID
        verified_user_id = totp_service.verify_2fa_session_token(token)
        assert verified_user_id == user_id
        
        # Step 5: Verify 2FA code
        totp = pyotp.TOTP(secret)
        code = totp.now()
        is_valid = two_fa.verify_2fa(user_id, code)
        assert is_valid
        
        # Step 6: Create final session
        session_id = auth_service.create_session(db, user_id, "127.0.0.1", "test-agent")
        assert session_id is not None
    
    def test_backup_code_in_login_flow(self, db_with_2fa_user):
        """Test using backup code in login flow"""
        db, user_id, secret, backup_codes = db_with_2fa_user
        two_fa = TwoFactorAuthentication(db)
        
        # Verify initial backup code count
        status = two_fa.get_2fa_status(user_id)
        assert status["backup_codes_remaining"] == 8
        
        # Use backup code
        backup_code = backup_codes[0]
        is_valid = two_fa.verify_2fa(user_id, backup_code)
        assert is_valid
        
        # Verify count decreased
        status = two_fa.get_2fa_status(user_id)
        assert status["backup_codes_remaining"] == 7
        
        # Same code should not work again
        is_valid = two_fa.verify_2fa(user_id, backup_code)
        assert not is_valid