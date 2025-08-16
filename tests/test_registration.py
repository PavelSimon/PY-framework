import pytest
import tempfile
import os
import shutil
from src.framework.database import Database
from src.framework.auth import AuthenticationService, UserRegistration
from src.framework.email import EmailService
from src.framework.config import Settings


@pytest.fixture
def test_db():
    """Create a temporary test database"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    
    db = Database(db_path)
    yield db
    
    db.close()
    shutil.rmtree(temp_dir)


@pytest.fixture
def auth_service():
    """Create authentication service"""
    return AuthenticationService("test_secret_key_32_characters_long_enough")


@pytest.fixture
def email_service():
    """Create email service"""
    return EmailService()


def test_user_registration_valid(test_db, auth_service):
    """Test valid user registration"""
    registration = UserRegistration(
        email="test@example.com",
        password="TestPass123!",
        first_name="Test",
        last_name="User"
    )
    
    success, user_id, message = auth_service.register_user(test_db, registration)
    
    assert success is True
    assert user_id is not None
    assert isinstance(user_id, int)
    assert "successfully" in message.lower()
    
    # Verify user was created in database
    user = test_db.get_user_by_email("test@example.com")
    assert user is not None
    assert user['email'] == "test@example.com"
    assert user['first_name'] == "Test"
    assert user['last_name'] == "User"
    assert user['is_verified'] is False  # Should be unverified initially


def test_user_registration_invalid_email(test_db, auth_service):
    """Test registration with invalid email"""
    with pytest.raises(Exception):  # Should raise validation error
        UserRegistration(
            email="invalid-email",
            password="TestPass123!"
        )


def test_user_registration_weak_password(test_db, auth_service):
    """Test registration with weak password"""
    with pytest.raises(Exception):  # Should raise validation error
        UserRegistration(
            email="test@example.com",
            password="weak"
        )


def test_user_registration_duplicate_email(test_db, auth_service):
    """Test registration with duplicate email"""
    registration = UserRegistration(
        email="test@example.com",
        password="TestPass123!"
    )
    
    # First registration should succeed
    success1, user_id1, message1 = auth_service.register_user(test_db, registration)
    assert success1 is True
    
    # Second registration with same email should fail
    success2, user_id2, message2 = auth_service.register_user(test_db, registration)
    assert success2 is False
    assert user_id2 is None
    assert "already registered" in message2.lower()


def test_email_verification_flow(test_db, email_service):
    """Test complete email verification flow"""
    # Create a test user first
    user_id = test_db.create_user(
        email="test@example.com",
        password_hash="hashed_password",
        first_name="Test",
        last_name="User"
    )
    
    # Generate verification token
    token = email_service.generate_verification_token(test_db, user_id)
    assert token is not None
    assert len(token) > 20
    
    # Verify token works
    success, verified_user_id, message = email_service.verify_email_token(test_db, token)
    assert success is True
    assert verified_user_id == user_id
    assert "successfully" in message.lower()
    
    # Check user is now verified
    user = test_db.get_user_by_id(user_id)
    assert user['is_verified'] is True
    
    # Token should not work again
    success2, _, message2 = email_service.verify_email_token(test_db, token)
    assert success2 is False
    assert "already been used" in message2.lower()


def test_password_validation():
    """Test password validation rules"""
    # Valid passwords
    valid_passwords = [
        "TestPass123!",
        "Str0ng@Pass",
        "Complex1ty#",
        "MySecure@Pass123"
    ]
    
    for password in valid_passwords:
        try:
            UserRegistration(email="test@example.com", password=password)
        except Exception:
            pytest.fail(f"Valid password '{password}' was rejected")
    
    # Invalid passwords
    invalid_passwords = [
        "short",                    # Too short
        "alllowercase123!",        # No uppercase
        "ALLUPPERCASE123!",        # No lowercase
        "NoNumbers!",              # No numbers
        "NoSpecialChars123",       # No special characters
    ]
    
    for password in invalid_passwords:
        with pytest.raises(Exception):
            UserRegistration(email="test@example.com", password=password)


def test_verification_token_expiry(test_db, email_service):
    """Test that verification tokens can expire"""
    # Create a test user
    user_id = test_db.create_user(
        email="test@example.com",
        password_hash="hashed_password"
    )
    
    # Generate verification token
    token = email_service.generate_verification_token(test_db, user_id)
    
    # Manually expire the token by updating the database
    from datetime import datetime, timedelta
    expired_time = datetime.now() - timedelta(hours=1)
    
    test_db.conn.execute("""
        UPDATE email_verification_tokens 
        SET expires_at = ? 
        WHERE token = ?
    """, [expired_time, token])
    
    # Try to verify expired token
    success, user_id_result, message = email_service.verify_email_token(test_db, token)
    assert success is False
    assert "expired" in message.lower()


if __name__ == "__main__":
    pytest.main([__file__])