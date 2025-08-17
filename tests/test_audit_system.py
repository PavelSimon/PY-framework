import pytest
import tempfile
import os
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from src.framework.audit import (
    AuditService, AuditEventType, AuditEvent, AuditManager,
    get_audit_service, log_auth_event, log_security_event, log_admin_event
)
from src.framework.database.database import Database


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    import uuid
    db_path = f"test_audit_{uuid.uuid4().hex}.db"
    
    db = Database(db_path)
    yield db
    
    # Cleanup
    if hasattr(db, '_conn') and db._conn:
        db._conn.close()
    try:
        os.unlink(db_path)
    except:
        pass


@pytest.fixture
def audit_service(temp_db):
    """Create audit service with temporary database"""
    import uuid
    log_path = f"test_audit_{uuid.uuid4().hex}.log"
    
    service = AuditService(temp_db, log_path)
    yield service
    
    # Cleanup
    try:
        os.unlink(log_path)
    except:
        pass


@pytest.fixture
def audit_manager_reset():
    """Reset audit manager between tests"""
    AuditManager.reset_instance()
    yield
    AuditManager.reset_instance()


class TestAuditEvent:
    """Test audit event model"""
    
    def test_audit_event_creation(self):
        """Test creating audit event"""
        event = AuditEvent(
            event_type=AuditEventType.USER_LOGIN_SUCCESS,
            user_id=1,
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            session_id="session123",
            success=True,
            details={"login_method": "password"}
        )
        
        assert event.event_type == AuditEventType.USER_LOGIN_SUCCESS
        assert event.user_id == 1
        assert event.ip_address == "192.168.1.1"
        assert event.user_agent == "Mozilla/5.0"
        assert event.session_id == "session123"
        assert event.success is True
        assert event.details["login_method"] == "password"
        assert isinstance(event.timestamp, datetime)
    
    def test_audit_event_to_dict(self):
        """Test converting audit event to dictionary"""
        event = AuditEvent(
            event_type=AuditEventType.USER_REGISTRATION,
            user_id=2,
            details={"first_name": "John"}
        )
        
        event_dict = event.to_dict()
        
        assert event_dict['event_type'] == 'user_registration'
        assert event_dict['user_id'] == 2
        assert event_dict['details']['first_name'] == "John"
        assert event_dict['success'] is True
        assert 'timestamp' in event_dict
    
    def test_audit_event_string_representation(self):
        """Test audit event string representation"""
        event = AuditEvent(
            event_type=AuditEventType.USER_LOGIN_FAILED,
            user_id=3,
            ip_address="10.0.0.1",
            success=False
        )
        
        event_str = str(event)
        
        assert "USER_LOGIN_FAILED" in event_str
        assert "FAILED" in event_str
        assert "user_id=3" in event_str
        assert "ip=10.0.0.1" in event_str


class TestAuditService:
    """Test audit service functionality"""
    
    def test_audit_service_initialization(self, temp_db):
        """Test audit service initialization"""
        service = AuditService(temp_db)
        
        assert service.db == temp_db
        assert service.logger is not None
        
        # Check that audit table was created
        cursor = temp_db.conn.execute("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_name = 'audit_events'
        """)
        assert cursor.fetchone() is not None
    
    def test_log_basic_event(self, audit_service):
        """Test logging a basic audit event"""
        event = AuditEvent(
            event_type=AuditEventType.USER_LOGIN_SUCCESS,
            user_id=1,
            ip_address="192.168.1.1",
            success=True
        )
        
        audit_service.log_event(event)
        
        # Verify event was stored in database
        cursor = audit_service.db.conn.execute("""
            SELECT event_type, user_id, ip_address, success
            FROM audit_events
            WHERE user_id = 1
        """)
        row = cursor.fetchone()
        
        assert row is not None
        assert row[0] == 'user_login_success'
        assert row[1] == 1
        assert row[2] == '192.168.1.1'
        assert row[3] is True
    
    def test_log_authentication_event(self, audit_service):
        """Test logging authentication event with convenience method"""
        audit_service.log_authentication_event(
            event_type=AuditEventType.PASSWORD_RESET_REQUEST,
            email="test@example.com",
            ip_address="10.0.0.1",
            user_agent="TestAgent",
            success=True,
            details={"reset_token": "token123"}
        )
        
        # Verify event was stored
        cursor = audit_service.db.conn.execute("""
            SELECT event_type, details, success
            FROM audit_events
            WHERE event_type = 'password_reset_request'
        """)
        row = cursor.fetchone()
        
        assert row is not None
        assert row[0] == 'password_reset_request'
        assert '"email": "test@example.com"' in row[1]
        assert '"reset_token": "token123"' in row[1]
        assert row[2] is True
    
    def test_log_security_event(self, audit_service):
        """Test logging security event"""
        audit_service.log_security_event(
            event_type=AuditEventType.CSRF_TOKEN_VALIDATION_FAILED,
            ip_address="192.168.1.100",
            user_agent="MaliciousBot",
            details={"attempted_action": "user_update"}
        )
        
        # Verify security event was stored
        cursor = audit_service.db.conn.execute("""
            SELECT event_type, ip_address, success, details
            FROM audit_events
            WHERE event_type = 'csrf_token_validation_failed'
        """)
        row = cursor.fetchone()
        
        assert row is not None
        assert row[0] == 'csrf_token_validation_failed'
        assert row[1] == '192.168.1.100'
        assert row[2] is False  # Security events default to failure
        assert '"attempted_action": "user_update"' in row[3]
    
    def test_log_admin_event(self, audit_service):
        """Test logging admin event"""
        audit_service.log_admin_event(
            event_type=AuditEventType.ADMIN_USER_MANAGEMENT,
            admin_user_id=1,
            target_user_id=5,
            ip_address="10.0.0.10",
            details={"action": "role_change", "new_role": "admin"}
        )
        
        # Verify admin event was stored
        cursor = audit_service.db.conn.execute("""
            SELECT event_type, user_id, details
            FROM audit_events
            WHERE event_type = 'admin_user_management'
        """)
        row = cursor.fetchone()
        
        assert row is not None
        assert row[0] == 'admin_user_management'
        assert row[1] == 1  # Admin user ID
        assert '"target_user_id": 5' in row[2]
        assert '"action": "role_change"' in row[2]
    
    def test_get_user_activity(self, audit_service):
        """Test retrieving user activity"""
        # Create test events
        events = [
            AuditEvent(AuditEventType.USER_LOGIN_SUCCESS, user_id=1),
            AuditEvent(AuditEventType.PROFILE_UPDATED, user_id=1),
            AuditEvent(AuditEventType.PASSWORD_CHANGE, user_id=1),
            AuditEvent(AuditEventType.USER_LOGIN_SUCCESS, user_id=2)  # Different user
        ]
        
        for event in events:
            audit_service.log_event(event)
        
        # Get activity for user 1
        activity = audit_service.get_user_activity(user_id=1, limit=10)
        
        assert len(activity) == 3
        assert activity[0]['event_type'] == 'password_change'  # Most recent first
        assert activity[1]['event_type'] == 'profile_updated'
        assert activity[2]['event_type'] == 'user_login_success'
    
    def test_get_user_activity_filtered(self, audit_service):
        """Test retrieving filtered user activity"""
        # Create test events
        events = [
            AuditEvent(AuditEventType.USER_LOGIN_SUCCESS, user_id=1),
            AuditEvent(AuditEventType.USER_LOGOUT, user_id=1),
            AuditEvent(AuditEventType.PROFILE_UPDATED, user_id=1)
        ]
        
        for event in events:
            audit_service.log_event(event)
        
        # Get only login/logout events
        activity = audit_service.get_user_activity(
            user_id=1,
            event_types=[AuditEventType.USER_LOGIN_SUCCESS, AuditEventType.USER_LOGOUT]
        )
        
        assert len(activity) == 2
        event_types = [a['event_type'] for a in activity]
        assert 'user_logout' in event_types
        assert 'user_login_success' in event_types
        assert 'profile_updated' not in event_types
    
    def test_get_security_events(self, audit_service):
        """Test retrieving security events"""
        # Create security events
        security_events = [
            AuditEvent(AuditEventType.RATE_LIMIT_EXCEEDED, success=False),
            AuditEvent(AuditEventType.USER_LOGIN_FAILED, user_id=1, success=False),
            AuditEvent(AuditEventType.CSRF_TOKEN_VALIDATION_FAILED, success=False),
            AuditEvent(AuditEventType.USER_LOGIN_SUCCESS, user_id=1, success=True)  # Should be excluded
        ]
        
        for event in security_events:
            audit_service.log_event(event)
        
        # Get security events
        events = audit_service.get_security_events(hours=24, limit=10)
        
        assert len(events) == 3  # Only failed events
        event_types = [e['event_type'] for e in events]
        assert 'csrf_token_validation_failed' in event_types
        assert 'rate_limit_exceeded' in event_types
        assert 'user_login_failed' in event_types
        assert 'user_login_success' not in event_types
    
    def test_get_login_statistics(self, audit_service):
        """Test login statistics calculation"""
        # Create login events
        login_events = [
            AuditEvent(AuditEventType.USER_LOGIN_SUCCESS, user_id=1),
            AuditEvent(AuditEventType.USER_LOGIN_SUCCESS, user_id=2),
            AuditEvent(AuditEventType.USER_LOGIN_SUCCESS, user_id=1),  # Same user again
            AuditEvent(AuditEventType.USER_LOGIN_FAILED, user_id=3, success=False),
            AuditEvent(AuditEventType.OAUTH_LOGIN_SUCCESS, user_id=4),
        ]
        
        for event in login_events:
            audit_service.log_event(event)
        
        # Get statistics
        stats = audit_service.get_login_statistics(days=30)
        
        assert stats['successful_logins'] == 3
        assert stats['failed_logins'] == 1
        assert stats['unique_users'] == 3  # users 1, 2, 1 (unique: 1, 2, 4)
        assert stats['oauth_logins'] == 1
        assert stats['total_attempts'] == 4
        assert stats['success_rate'] == 75.0  # 3/4 * 100
    
    def test_cleanup_old_events(self, audit_service):
        """Test cleaning up old audit events"""
        # Create events with different timestamps
        old_time = datetime.now() - timedelta(days=100)
        recent_time = datetime.now() - timedelta(days=10)
        
        old_event = AuditEvent(AuditEventType.USER_LOGIN_SUCCESS, user_id=1, timestamp=old_time)
        recent_event = AuditEvent(AuditEventType.USER_LOGIN_SUCCESS, user_id=2, timestamp=recent_time)
        
        audit_service.log_event(old_event)
        audit_service.log_event(recent_event)
        
        # Verify both events exist
        cursor = audit_service.db.conn.execute("SELECT COUNT(*) FROM audit_events")
        assert cursor.fetchone()[0] == 2
        
        # Cleanup events older than 90 days
        deleted_count = audit_service.cleanup_old_events(days=90)
        
        assert deleted_count == 1
        
        # Verify only recent event remains
        cursor = audit_service.db.conn.execute("SELECT COUNT(*) FROM audit_events")
        assert cursor.fetchone()[0] == 1
        
        cursor = audit_service.db.conn.execute("SELECT user_id FROM audit_events")
        assert cursor.fetchone()[0] == 2  # Recent event user


class TestAuditManager:
    """Test audit manager singleton"""
    
    def test_audit_manager_singleton(self, temp_db, audit_manager_reset):
        """Test audit manager singleton behavior"""
        # First call should create instance
        service1 = AuditManager.get_instance(temp_db)
        assert service1 is not None
        
        # Second call should return same instance
        service2 = AuditManager.get_instance()
        assert service1 is service2
    
    def test_audit_manager_requires_database_first(self, audit_manager_reset):
        """Test that first call to audit manager requires database"""
        with pytest.raises(ValueError, match="Database instance required"):
            AuditManager.get_instance()
    
    def test_get_audit_service_convenience(self, temp_db, audit_manager_reset):
        """Test convenience function for getting audit service"""
        service = get_audit_service(temp_db)
        assert service is not None
        assert isinstance(service, AuditService)
    
    def test_convenience_logging_functions(self, temp_db, audit_manager_reset):
        """Test convenience logging functions"""
        service = get_audit_service(temp_db)
        
        # Test auth event logging
        log_auth_event(
            service,
            event_type=AuditEventType.USER_LOGIN_SUCCESS,
            user_id=1,
            email="test@example.com",
            success=True
        )
        
        # Test security event logging
        log_security_event(
            service,
            event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
            ip_address="192.168.1.1"
        )
        
        # Test admin event logging
        log_admin_event(
            service,
            event_type=AuditEventType.ADMIN_USER_MANAGEMENT,
            admin_user_id=1,
            target_user_id=2
        )
        
        # Verify events were logged
        cursor = service.db.conn.execute("SELECT COUNT(*) FROM audit_events")
        assert cursor.fetchone()[0] == 3


class TestAuditEventTypes:
    """Test audit event type coverage"""
    
    def test_all_authentication_events_covered(self):
        """Test that all authentication event types are defined"""
        auth_events = [
            AuditEventType.USER_LOGIN_SUCCESS,
            AuditEventType.USER_LOGIN_FAILED,
            AuditEventType.USER_LOGOUT,
            AuditEventType.USER_REGISTRATION,
            AuditEventType.EMAIL_VERIFICATION,
            AuditEventType.PASSWORD_RESET_REQUEST,
            AuditEventType.PASSWORD_RESET_COMPLETE,
            AuditEventType.PASSWORD_CHANGE,
            AuditEventType.ACCOUNT_LOCKED,
            AuditEventType.ACCOUNT_UNLOCKED
        ]
        
        for event_type in auth_events:
            assert isinstance(event_type, AuditEventType)
            assert isinstance(event_type.value, str)
    
    def test_all_oauth_events_covered(self):
        """Test that OAuth event types are defined"""
        oauth_events = [
            AuditEventType.OAUTH_LOGIN_SUCCESS,
            AuditEventType.OAUTH_LOGIN_FAILED,
            AuditEventType.OAUTH_ACCOUNT_LINKED,
            AuditEventType.OAUTH_STATE_VALIDATION_FAILED
        ]
        
        for event_type in oauth_events:
            assert isinstance(event_type, AuditEventType)
            assert isinstance(event_type.value, str)
    
    def test_all_2fa_events_covered(self):
        """Test that 2FA event types are defined"""
        twofa_events = [
            AuditEventType.TWO_FA_ENABLED,
            AuditEventType.TWO_FA_DISABLED,
            AuditEventType.TWO_FA_VERIFICATION_SUCCESS,
            AuditEventType.TWO_FA_VERIFICATION_FAILED,
            AuditEventType.TWO_FA_BACKUP_CODE_USED,
            AuditEventType.TWO_FA_BACKUP_CODES_REGENERATED
        ]
        
        for event_type in twofa_events:
            assert isinstance(event_type, AuditEventType)
            assert isinstance(event_type.value, str)
    
    def test_all_security_events_covered(self):
        """Test that security event types are defined"""
        security_events = [
            AuditEventType.CSRF_TOKEN_VALIDATION_FAILED,
            AuditEventType.RATE_LIMIT_EXCEEDED,
            AuditEventType.INVALID_SESSION_ACCESS,
            AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
            AuditEventType.SUSPICIOUS_LOGIN_ACTIVITY
        ]
        
        for event_type in security_events:
            assert isinstance(event_type, AuditEventType)
            assert isinstance(event_type.value, str)
    
    def test_all_admin_events_covered(self):
        """Test that admin event types are defined"""
        admin_events = [
            AuditEventType.ADMIN_USER_MANAGEMENT,
            AuditEventType.ADMIN_ROLE_ASSIGNMENT,
            AuditEventType.ADMIN_SESSION_MONITORING,
            AuditEventType.ADMIN_USER_DELETION
        ]
        
        for event_type in admin_events:
            assert isinstance(event_type, AuditEventType)
            assert isinstance(event_type.value, str)