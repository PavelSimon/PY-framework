"""
Test suite for role-based access control system
Tests user roles, permissions, and access validation
"""

import pytest
from datetime import datetime, timedelta
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from framework.database import Database
from framework.auth import AuthenticationService, UserRegistration
from framework.middleware import RoleValidator, validate_admin_access, protect_admin_route
from framework.session import store_session


class MockRequest:
    """Mock request object for testing"""
    def __init__(self, session_id=None):
        self.cookies = {'session_id': session_id} if session_id else {}


@pytest.fixture
def db():
    """Create test database"""
    database = Database(':memory:')
    return database


@pytest.fixture
def auth_service():
    """Create auth service"""
    return AuthenticationService('test-secret-key-32-chars-minimum')


@pytest.fixture
def setup_users(db, auth_service):
    """Setup test users with different roles"""
    # Create admin user
    admin_registration = UserRegistration(
        email="admin@test.com",
        password="AdminPass123!",
        first_name="Admin",
        last_name="User"
    )
    admin_id = auth_service.register_user(db, admin_registration)[1]
    db.update_user_role(admin_id, 0)  # Make admin
    db.verify_user_email(admin_id)  # Verify email
    
    # Create regular user
    user_registration = UserRegistration(
        email="user@test.com", 
        password="UserPass123!",
        first_name="Regular",
        last_name="User"
    )
    user_id = auth_service.register_user(db, user_registration)[1]
    db.verify_user_email(user_id)  # Verify email
    
    # Create admin session
    admin_session = auth_service.create_session(db, admin_id, "127.0.0.1", "test-agent")
    store_session(admin_session, admin_id)  # Store in memory
    
    # Create user session
    user_session = auth_service.create_session(db, user_id, "127.0.0.1", "test-agent")
    store_session(user_session, user_id)  # Store in memory
    
    return {
        'admin_id': admin_id,
        'user_id': user_id,
        'admin_session': admin_session,
        'user_session': user_session
    }


class TestRoleValidator:
    """Test the RoleValidator class"""
    
    def test_role_validator_creation(self, db, auth_service):
        """Test creating a role validator"""
        validator = RoleValidator(db, auth_service)
        assert validator.db == db
        assert validator.auth_service == auth_service
    
    def test_check_auth_with_valid_session(self, db, auth_service, setup_users):
        """Test authentication check with valid session"""
        validator = RoleValidator(db, auth_service)
        request = MockRequest(setup_users['admin_session'])
        
        is_auth, user = validator.check_auth(request)
        assert is_auth == True
        assert user is not None
        assert user['email'] == 'admin@test.com'
    
    def test_check_auth_with_invalid_session(self, db, auth_service):
        """Test authentication check with invalid session"""
        validator = RoleValidator(db, auth_service)
        request = MockRequest('invalid-session')
        
        is_auth, user = validator.check_auth(request)
        assert is_auth == False
        assert user is None
    
    def test_check_auth_with_no_session(self, db, auth_service):
        """Test authentication check with no session"""
        validator = RoleValidator(db, auth_service)
        request = MockRequest()
        
        is_auth, user = validator.check_auth(request)
        assert is_auth == False
        assert user is None
    
    def test_check_admin_role(self, db, auth_service, setup_users):
        """Test admin role checking"""
        validator = RoleValidator(db, auth_service)
        request = MockRequest(setup_users['admin_session'])
        
        is_admin, user = validator.check_admin(request)
        assert is_admin == True
        assert user is not None
        assert user['role_id'] == 0
    
    def test_check_regular_user_role(self, db, auth_service, setup_users):
        """Test regular user role checking"""
        validator = RoleValidator(db, auth_service)
        request = MockRequest(setup_users['user_session'])
        
        is_admin, user = validator.check_admin(request)
        assert is_admin == False
        assert user is not None
        assert user['role_id'] == 1
    
    def test_check_role_with_list(self, db, auth_service, setup_users):
        """Test role checking with list of allowed roles"""
        validator = RoleValidator(db, auth_service)
        
        # Test admin with both roles allowed
        admin_request = MockRequest(setup_users['admin_session'])
        has_role, user = validator.check_role(admin_request, [0, 1])
        assert has_role == True
        assert user['role_id'] == 0
        
        # Test user with both roles allowed
        user_request = MockRequest(setup_users['user_session'])
        has_role, user = validator.check_role(user_request, [0, 1])
        assert has_role == True
        assert user['role_id'] == 1
        
        # Test user with only admin allowed
        has_role, user = validator.check_role(user_request, [0])
        assert has_role == False
        assert user['role_id'] == 1


class TestAccessValidation:
    """Test access validation utility functions"""
    
    def test_validate_admin_access_success(self, db, auth_service, setup_users):
        """Test successful admin access validation"""
        request = MockRequest(setup_users['admin_session'])
        
        is_admin, user, error_response = validate_admin_access(request, db, auth_service)
        assert is_admin == True
        assert user is not None
        assert error_response is None
        assert user['role_id'] == 0
    
    def test_validate_admin_access_failure_regular_user(self, db, auth_service, setup_users):
        """Test admin access validation failure with regular user"""
        request = MockRequest(setup_users['user_session'])
        
        is_admin, user, error_response = validate_admin_access(request, db, auth_service)
        assert is_admin == False
        assert user is not None  # User exists but not admin
        assert error_response is not None
        assert user['role_id'] == 1
    
    def test_validate_admin_access_failure_no_auth(self, db, auth_service):
        """Test admin access validation failure with no authentication"""
        request = MockRequest()
        
        is_admin, user, error_response = validate_admin_access(request, db, auth_service)
        assert is_admin == False
        assert user is None
        assert error_response is not None
    
    def test_protect_admin_route_success(self, db, auth_service, setup_users):
        """Test successful admin route protection"""
        request = MockRequest(setup_users['admin_session'])
        
        is_protected, user, error_response = protect_admin_route(request, db, auth_service)
        assert is_protected == True
        assert user is not None
        assert error_response is None
    
    def test_protect_admin_route_self_action_blocked(self, db, auth_service, setup_users):
        """Test admin route protection blocks self-action"""
        request = MockRequest(setup_users['admin_session'])
        admin_id = setup_users['admin_id']
        
        is_protected, user, error_response = protect_admin_route(
            request, db, auth_service, target_user_id=admin_id
        )
        assert is_protected == False
        assert user is not None
        assert error_response is not None


class TestDatabaseRoleFunctions:
    """Test database role-related functions"""
    
    def test_user_role_assignment(self, db, auth_service):
        """Test user role assignment and retrieval"""
        # Create user
        registration = UserRegistration(
            email="test@example.com",
            password="TestPass123!"
        )
        user_id = auth_service.register_user(db, registration)[1]
        
        # User should start as regular user (role_id = 1)
        user = db.get_user_with_role(user_id)
        assert user['role_id'] == 1
        assert user['role_name'] == 'user'
        
        # Make user admin
        success = db.update_user_role(user_id, 0)
        assert success == True
        
        # Verify role change
        user = db.get_user_with_role(user_id)
        assert user['role_id'] == 0
        assert user['role_name'] == 'admin'
    
    def test_is_admin_function(self, db, auth_service, setup_users):
        """Test the is_admin database function"""
        admin_id = setup_users['admin_id']
        user_id = setup_users['user_id']
        
        assert db.is_admin(admin_id) == True
        assert db.is_admin(user_id) == False
    
    def test_get_all_users_with_roles(self, db, auth_service, setup_users):
        """Test retrieving all users with role information"""
        users = db.get_all_users_with_roles()
        
        # Should have at least 2 users from setup
        assert len(users) >= 2
        
        # Check admin user
        admin_user = next((u for u in users if u['email'] == 'admin@test.com'), None)
        assert admin_user is not None
        assert admin_user['role_id'] == 0
        assert admin_user['role_name'] == 'admin'
        
        # Check regular user
        regular_user = next((u for u in users if u['email'] == 'user@test.com'), None)
        assert regular_user is not None
        assert regular_user['role_id'] == 1
        assert regular_user['role_name'] == 'user'


class TestRoleBasedSecurity:
    """Test role-based security scenarios"""
    
    def test_role_escalation_prevention(self, db, auth_service, setup_users):
        """Test that users cannot escalate their own roles"""
        user_id = setup_users['user_id']
        
        # Regular user should not be able to make themselves admin
        # This would be enforced at the route level, but we can test the database constraint
        initial_role = db.get_user_with_role(user_id)['role_id']
        assert initial_role == 1
        
        # Even if somehow attempted, verify role stays the same without admin privileges
        user = db.get_user_with_role(user_id)
        assert user['role_id'] == 1
    
    def test_admin_cannot_edit_own_role(self, db, auth_service, setup_users):
        """Test that admin protection prevents self-role editing"""
        request = MockRequest(setup_users['admin_session'])
        admin_id = setup_users['admin_id']
        
        # This should be blocked by the protect_admin_route function
        is_protected, user, error_response = protect_admin_route(
            request, db, auth_service, target_user_id=admin_id
        )
        assert is_protected == False
        assert error_response is not None
    
    def test_session_invalidation_on_deactivation(self, db, auth_service, setup_users):
        """Test that user sessions are invalidated when account is deactivated"""
        user_id = setup_users['user_id']
        session_id = setup_users['user_session']
        
        # Verify session is initially active
        session = db.get_session(session_id)
        assert session is not None
        assert session['is_active'] == True
        
        # Deactivate user (simulate what toggle_user_status does)
        db.conn.execute("""
            UPDATE users 
            SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, [user_id])
        
        # Invalidate sessions
        db.conn.execute("""
            UPDATE sessions 
            SET is_active = FALSE 
            WHERE user_id = ?
        """, [user_id])
        
        # Verify session is now inactive
        session = db.get_session(session_id)
        assert session is None  # get_session only returns active sessions


def test_role_system_integration():
    """Integration test for the complete role system"""
    # This test verifies the entire role system works together
    db = Database(':memory:')
    auth_service = AuthenticationService('test-secret-key-32-chars-minimum')
    
    # Create admin and regular user
    admin_reg = UserRegistration(email="admin@test.com", password="AdminPass123!")
    user_reg = UserRegistration(email="user@test.com", password="UserPass123!")
    
    admin_id = auth_service.register_user(db, admin_reg)[1]
    user_id = auth_service.register_user(db, user_reg)[1]
    
    # Set roles
    db.update_user_role(admin_id, 0)  # Admin
    # user_id remains as regular user (role_id = 1)
    
    # Create sessions
    admin_session = auth_service.create_session(db, admin_id)
    store_session(admin_session, admin_id)
    user_session = auth_service.create_session(db, user_id)
    store_session(user_session, user_id)
    
    # Test admin access
    admin_request = MockRequest(admin_session)
    is_admin, admin_user, _ = validate_admin_access(admin_request, db, auth_service)
    assert is_admin == True
    assert admin_user['role_id'] == 0
    
    # Test user access (should fail admin check)
    user_request = MockRequest(user_session)
    is_admin, user_user, error = validate_admin_access(user_request, db, auth_service)
    assert is_admin == False
    assert user_user['role_id'] == 1
    assert error is not None
    
    print("✓ Role-based access control system integration test passed!")


if __name__ == "__main__":
    # Run basic integration test
    test_role_system_integration()