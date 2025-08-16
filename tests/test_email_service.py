import pytest
import tempfile
import os
from datetime import datetime, timedelta
from src.framework.email import EmailService
from src.framework.database import Database
from src.framework.config import Settings


@pytest.fixture
def test_db():
    """Create a temporary test database"""
    # Create a temporary directory instead of a file
    import tempfile
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    
    db = Database(db_path)
    yield db
    
    db.close()
    # Clean up the temporary directory
    import shutil
    shutil.rmtree(temp_dir)


@pytest.fixture
def email_service():
    """Create email service instance"""
    return EmailService()


@pytest.fixture
def test_user(test_db):
    """Create a test user"""
    user_id = test_db.create_user(
        email="test@example.com",
        password_hash="hashed_password",
        first_name="Test",
        last_name="User"
    )
    return user_id


def test_email_service_initialization(email_service):
    """Test email service initializes correctly"""
    assert email_service is not None
    assert hasattr(email_service, 'smtp_server')
    assert hasattr(email_service, 'smtp_port')


def test_generate_verification_token(email_service, test_db, test_user):
    """Test verification token generation"""
    token = email_service.generate_verification_token(test_db, test_user)
    
    assert token is not None
    assert len(token) > 20  # URL-safe tokens should be reasonably long
    
    # Verify token exists in database
    cursor = test_db.conn.execute("""
        SELECT user_id, token, expires_at 
        FROM email_verification_tokens 
        WHERE user_id = ?
    """, [test_user])
    
    row = cursor.fetchone()
    assert row is not None
    assert row[0] == test_user
    assert row[1] == token


def test_generate_password_reset_token(email_service, test_db, test_user):
    """Test password reset token generation"""
    token = email_service.generate_password_reset_token(test_db, test_user)
    
    assert token is not None
    assert len(token) > 20
    
    # Verify token exists in database
    cursor = test_db.conn.execute("""
        SELECT user_id, token, expires_at 
        FROM password_reset_tokens 
        WHERE user_id = ?
    """, [test_user])
    
    row = cursor.fetchone()
    assert row is not None
    assert row[0] == test_user
    assert row[1] == token


def test_verify_email_token_valid(email_service, test_db, test_user):
    """Test email token verification with valid token"""
    token = email_service.generate_verification_token(test_db, test_user)
    
    success, user_id, message = email_service.verify_email_token(test_db, token)
    
    assert success is True
    assert user_id == test_user
    assert "successfully" in message.lower()
    
    # Verify user is marked as verified
    user = test_db.get_user_by_id(test_user)
    assert user['is_verified'] is True


def test_verify_email_token_invalid(email_service, test_db):
    """Test email token verification with invalid token"""
    success, user_id, message = email_service.verify_email_token(test_db, "invalid_token")
    
    assert success is False
    assert user_id is None
    assert "invalid" in message.lower()


def test_verify_email_token_used(email_service, test_db, test_user):
    """Test email token verification with already used token"""
    token = email_service.generate_verification_token(test_db, test_user)
    
    # Use token first time
    email_service.verify_email_token(test_db, token)
    
    # Try to use token again
    success, user_id, message = email_service.verify_email_token(test_db, token)
    
    assert success is False
    assert user_id is None
    assert "already been used" in message.lower()


def test_verify_password_reset_token_valid(email_service, test_db, test_user):
    """Test password reset token verification with valid token"""
    token = email_service.generate_password_reset_token(test_db, test_user)
    
    success, user_id, message = email_service.verify_password_reset_token(test_db, token)
    
    assert success is True
    assert user_id == test_user
    assert "valid" in message.lower()


def test_verify_password_reset_token_invalid(email_service, test_db):
    """Test password reset token verification with invalid token"""
    success, user_id, message = email_service.verify_password_reset_token(test_db, "invalid_token")
    
    assert success is False
    assert user_id is None
    assert "invalid" in message.lower()


def test_mark_password_reset_token_used(email_service, test_db, test_user):
    """Test marking password reset token as used"""
    token = email_service.generate_password_reset_token(test_db, test_user)
    
    # Mark token as used
    email_service.mark_password_reset_token_used(test_db, token)
    
    # Try to verify used token
    success, user_id, message = email_service.verify_password_reset_token(test_db, token)
    
    assert success is False
    assert "already been used" in message.lower()


def test_multiple_password_reset_tokens(email_service, test_db, test_user):
    """Test that generating new password reset token invalidates old ones"""
    token1 = email_service.generate_password_reset_token(test_db, test_user)
    token2 = email_service.generate_password_reset_token(test_db, test_user)
    
    # First token should be invalidated
    success1, _, _ = email_service.verify_password_reset_token(test_db, token1)
    success2, _, _ = email_service.verify_password_reset_token(test_db, token2)
    
    assert success1 is False
    assert success2 is True


def test_email_template_generation(email_service):
    """Test that email templates are generated correctly"""
    # Test verification email content
    test_email = "test@example.com"
    test_token = "test_token_123"
    test_name = "Test User"
    
    # Since we can't easily test actual email sending without SMTP,
    # we'll test that the method exists and handles parameters
    assert hasattr(email_service, 'send_verification_email')
    assert hasattr(email_service, 'send_password_reset_email')
    
    # Test that methods accept expected parameters
    try:
        # These will fail due to missing SMTP config, but we're testing parameter handling
        email_service.send_verification_email(test_email, test_token, test_name)
        email_service.send_password_reset_email(test_email, test_token, test_name)
    except Exception as e:
        # Expected to fail due to SMTP config, but parameters should be handled correctly
        assert "Email configuration" in str(e) or "Failed to connect" in str(e)


if __name__ == "__main__":
    pytest.main([__file__])