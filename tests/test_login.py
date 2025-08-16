import pytest
import tempfile
import os
import shutil
from datetime import datetime, timedelta
from src.framework.database import Database
from src.framework.auth import AuthenticationService, UserRegistration
from src.framework.email import EmailService


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


@pytest.fixture
def verified_user(test_db, auth_service):
    """Create a verified test user"""
    # Register user
    registration = UserRegistration(
        email="test@example.com",
        password="TestPass123!",
        first_name="Test",
        last_name="User"
    )
    
    success, user_id, message = auth_service.register_user(test_db, registration)
    assert success is True
    
    # Manually verify the user
    test_db.verify_user_email(user_id)
    
    return user_id, registration


def test_login_valid_credentials(test_db, auth_service, verified_user):
    """Test login with valid credentials"""
    user_id, registration = verified_user
    
    success, user, message = auth_service.authenticate_user(
        test_db, registration.email, registration.password
    )
    
    assert success is True
    assert user is not None
    assert user['email'] == registration.email
    assert user['is_verified'] is True
    assert "successful" in message.lower()


def test_login_invalid_email(test_db, auth_service):
    """Test login with invalid email"""
    success, user, message = auth_service.authenticate_user(
        test_db, "nonexistent@example.com", "TestPass123!"
    )
    
    assert success is False
    assert user is None
    assert "invalid" in message.lower()


def test_login_invalid_password(test_db, auth_service, verified_user):
    """Test login with invalid password"""
    user_id, registration = verified_user
    
    success, user, message = auth_service.authenticate_user(
        test_db, registration.email, "WrongPassword123!"
    )
    
    assert success is False
    assert user is None
    assert "invalid" in message.lower()


def test_login_unverified_user(test_db, auth_service):
    """Test login with unverified user"""
    # Register user but don't verify
    registration = UserRegistration(
        email="unverified@example.com",
        password="TestPass123!",
        first_name="Test",
        last_name="User"
    )
    
    success, user_id, message = auth_service.register_user(test_db, registration)
    assert success is True
    
    # Try to login without verification
    success, user, message = auth_service.authenticate_user(
        test_db, registration.email, registration.password
    )
    
    # Authentication should succeed but user should be unverified
    assert success is True
    assert user['is_verified'] is False


def test_account_lockout_after_failed_attempts(test_db, auth_service, verified_user):
    """Test account lockout after multiple failed login attempts"""
    user_id, registration = verified_user
    
    # Make multiple failed login attempts
    for i in range(5):
        success, user, message = auth_service.authenticate_user(
            test_db, registration.email, "WrongPassword123!"
        )
        assert success is False
    
    # Next attempt should be locked
    success, user, message = auth_service.authenticate_user(
        test_db, registration.email, "WrongPassword123!"
    )
    
    assert success is False
    assert "locked" in message.lower()


def test_session_creation(test_db, auth_service, verified_user):
    """Test session creation after successful login"""
    user_id, registration = verified_user
    
    # Create a session
    session_id = auth_service.create_session(
        test_db, user_id, "127.0.0.1", "test-user-agent"
    )
    
    assert session_id is not None
    assert len(session_id) > 20  # Should be a substantial token
    
    # Validate the session
    valid, session = auth_service.validate_session(test_db, session_id)
    
    assert valid is True
    assert session is not None
    assert session['user_id'] == user_id
    assert session['ip_address'] == "127.0.0.1"
    assert session['user_agent'] == "test-user-agent"


def test_session_validation_invalid(test_db, auth_service):
    """Test session validation with invalid session"""
    valid, session = auth_service.validate_session(test_db, "invalid_session_id")
    
    assert valid is False
    assert session is None


def test_session_expiry(test_db, auth_service, verified_user):
    """Test session expiry"""
    user_id, registration = verified_user
    
    # Create a session
    session_id = auth_service.create_session(test_db, user_id)
    
    # Manually expire the session
    expired_time = datetime.now() - timedelta(hours=1)
    test_db.conn.execute("""
        UPDATE sessions 
        SET expires_at = ? 
        WHERE id = ?
    """, [expired_time, session_id])
    
    # Session should be invalid
    valid, session = auth_service.validate_session(test_db, session_id)
    assert valid is False


def test_session_logout(test_db, auth_service, verified_user):
    """Test session logout/invalidation"""
    user_id, registration = verified_user
    
    # Create a session
    session_id = auth_service.create_session(test_db, user_id)
    
    # Validate session works
    valid, session = auth_service.validate_session(test_db, session_id)
    assert valid is True
    
    # Logout (invalidate session)
    auth_service.logout_user(test_db, session_id)
    
    # Session should now be invalid
    valid, session = auth_service.validate_session(test_db, session_id)
    assert valid is False


def test_session_cleanup(test_db, auth_service, verified_user):
    """Test automatic cleanup of expired sessions"""
    user_id, registration = verified_user
    
    # Create multiple sessions
    session_ids = []
    for i in range(3):
        session_id = auth_service.create_session(test_db, user_id)
        session_ids.append(session_id)
    
    # Manually expire some sessions
    expired_time = datetime.now() - timedelta(hours=1)
    test_db.conn.execute("""
        UPDATE sessions 
        SET expires_at = ? 
        WHERE id IN (?, ?)
    """, [expired_time, session_ids[0], session_ids[1]])
    
    # Run cleanup
    auth_service.cleanup_expired_sessions(test_db)
    
    # Check that expired sessions are marked inactive
    cursor = test_db.conn.execute("""
        SELECT id, is_active FROM sessions WHERE id IN (?, ?, ?)
    """, session_ids)
    
    results = cursor.fetchall()
    assert len(results) == 3
    
    # First two should be inactive, third should still be active
    for row in results:
        session_id, is_active = row
        if session_id in [session_ids[0], session_ids[1]]:
            assert is_active is False
        else:
            assert is_active is True


def test_password_strength_validation(auth_service):
    """Test password strength scoring"""
    # Test strong password
    score, feedback = auth_service.generate_password_strength_score("StrongPass123!")
    assert score >= 4
    assert len(feedback) <= 2  # Should have minimal feedback
    
    # Test weak password
    score, feedback = auth_service.generate_password_strength_score("weak")
    assert score < 3
    assert len(feedback) > 3  # Should have lots of feedback
    
    # Test medium password
    score, feedback = auth_service.generate_password_strength_score("MediumPass123")
    assert score >= 3
    assert "special characters" in " ".join(feedback).lower()


if __name__ == "__main__":
    pytest.main([__file__])