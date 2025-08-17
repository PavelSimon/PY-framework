"""
Test OAuth integration functionality
"""

import pytest
import asyncio
import secrets
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

# Import OAuth components
from src.framework.oauth.oauth_service import (
    OAuthService, GoogleOAuthProvider, GitHubOAuthProvider
)
from src.framework.database.database import Database


class TestOAuthService:
    """Test OAuth service functionality"""
    
    @pytest.fixture
    def oauth_service(self, db):
        """Create OAuth service for testing"""
        return OAuthService(db)
    
    @pytest.fixture 
    def db(self):
        """Create test database"""
        db = Database(":memory:")
        return db
    
    def test_oauth_service_initialization(self, oauth_service):
        """Test OAuth service creates with providers"""
        assert oauth_service is not None
        assert "google" in oauth_service.providers
        assert "github" in oauth_service.providers
        assert isinstance(oauth_service.providers["google"], GoogleOAuthProvider)
        assert isinstance(oauth_service.providers["github"], GitHubOAuthProvider)
    
    def test_generate_state_token(self, oauth_service):
        """Test state token generation"""
        state = oauth_service.generate_state_token("google", "session123")
        assert state is not None
        assert len(state) > 20  # Should be a decent length token
        
        # Verify token is stored in database
        cursor = oauth_service.db.conn.execute("""
            SELECT provider, session_id FROM oauth_state_tokens WHERE state_token = ?
        """, [state])
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == "google"
        assert row[1] == "session123"
    
    def test_validate_state_token_valid(self, oauth_service):
        """Test valid state token validation"""
        state = oauth_service.generate_state_token("github")
        assert oauth_service.validate_state_token(state, "github") is True
    
    def test_validate_state_token_invalid_provider(self, oauth_service):
        """Test state token validation with wrong provider"""
        state = oauth_service.generate_state_token("google")
        assert oauth_service.validate_state_token(state, "github") is False
    
    def test_validate_state_token_expired(self, oauth_service):
        """Test expired state token validation"""
        state = oauth_service.generate_state_token("google")
        # Manually expire the token in database
        oauth_service.db.conn.execute("""
            UPDATE oauth_state_tokens 
            SET expires_at = ? 
            WHERE state_token = ?
        """, [datetime.now() - timedelta(minutes=1), state])
        
        assert oauth_service.validate_state_token(state, "google") is False
        
        # Token should be cleaned up from database
        cursor = oauth_service.db.conn.execute("""
            SELECT COUNT(*) FROM oauth_state_tokens WHERE state_token = ?
        """, [state])
        assert cursor.fetchone()[0] == 0
    
    def test_validate_state_token_nonexistent(self, oauth_service):
        """Test validation of non-existent state token"""
        fake_state = secrets.token_urlsafe(32)
        assert oauth_service.validate_state_token(fake_state, "google") is False
    
    def test_get_provider(self, oauth_service):
        """Test getting OAuth providers"""
        google_provider = oauth_service.get_provider("google")
        github_provider = oauth_service.get_provider("github")
        invalid_provider = oauth_service.get_provider("invalid")
        
        assert isinstance(google_provider, GoogleOAuthProvider)
        assert isinstance(github_provider, GitHubOAuthProvider)
        assert invalid_provider is None
    
    def test_get_auth_url(self, oauth_service):
        """Test getting authorization URLs"""
        google_url = oauth_service.get_auth_url("google")
        github_url = oauth_service.get_auth_url("github")
        invalid_url = oauth_service.get_auth_url("invalid")
        
        assert google_url is not None
        assert "accounts.google.com" in google_url
        assert "state=" in google_url
        
        assert github_url is not None
        assert "github.com" in github_url
        assert "state=" in github_url
        
        assert invalid_url is None
    
    def test_cleanup_expired_states(self, oauth_service):
        """Test cleanup of expired state tokens"""
        # Create some tokens
        valid_state = oauth_service.generate_state_token("google")
        expired_state = oauth_service.generate_state_token("github")
        
        # Manually expire one token in database
        oauth_service.db.conn.execute("""
            UPDATE oauth_state_tokens 
            SET expires_at = ? 
            WHERE state_token = ?
        """, [datetime.now() - timedelta(minutes=1), expired_state])
        
        # Count tokens before cleanup
        cursor = oauth_service.db.conn.execute("SELECT COUNT(*) FROM oauth_state_tokens")
        assert cursor.fetchone()[0] == 2
        
        oauth_service.cleanup_expired_states()
        
        # Only valid token should remain
        cursor = oauth_service.db.conn.execute("SELECT COUNT(*) FROM oauth_state_tokens")
        assert cursor.fetchone()[0] == 1
        
        cursor = oauth_service.db.conn.execute("""
            SELECT state_token FROM oauth_state_tokens
        """)
        remaining_token = cursor.fetchone()[0]
        assert remaining_token == valid_state
    
    def test_link_oauth_account(self, oauth_service, db):
        """Test linking OAuth account to user"""
        # Create test user
        from src.framework.auth.auth import AuthenticationService
        auth_service = AuthenticationService("test-secret-key-32-chars-minimum")
        password_hash = auth_service.hash_password("TestPassword123!")
        user_id = db.create_user("test@example.com", password_hash, "Test", "User")
        
        # Link OAuth account
        success = oauth_service.link_oauth_account(
            user_id=user_id,
            provider="google",
            provider_user_id="12345",
            provider_email="test@example.com",
            access_token="access123",
            refresh_token="refresh123"
        )
        
        assert success is True
        
        # Verify the account was linked
        oauth_account = db.get_oauth_account("google", "12345")
        assert oauth_account is not None
        assert oauth_account["user_id"] == user_id
        assert oauth_account["provider"] == "google"
        assert oauth_account["provider_user_id"] == "12345"
        assert oauth_account["provider_email"] == "test@example.com"
    
    def test_find_user_by_oauth(self, oauth_service, db):
        """Test finding user by OAuth account"""
        # Create test user and OAuth account
        from src.framework.auth.auth import AuthenticationService
        auth_service = AuthenticationService("test-secret-key-32-chars-minimum")
        password_hash = auth_service.hash_password("TestPassword123!")
        user_id = db.create_user("test@example.com", password_hash, "Test", "User")
        
        oauth_service.link_oauth_account(
            user_id=user_id,
            provider="github",
            provider_user_id="67890",
            provider_email="test@example.com"
        )
        
        # Find user by OAuth
        user = oauth_service.find_user_by_oauth("github", "67890")
        assert user is not None
        assert user["id"] == user_id
        assert user["email"] == "test@example.com"
        
        # Test non-existent OAuth account
        no_user = oauth_service.find_user_by_oauth("github", "nonexistent")
        assert no_user is None
    
    def test_create_user_from_oauth(self, oauth_service):
        """Test creating user from OAuth information"""
        user_info = {
            "provider_user_id": "oauth123",
            "email": "newuser@example.com",
            "name": "New User",
            "given_name": "New",
            "family_name": "User",
            "verified_email": True
        }
        
        user_id = oauth_service.create_user_from_oauth(
            provider="google",
            user_info=user_info,
            access_token="access123"
        )
        
        assert user_id is not None
        assert isinstance(user_id, int)
        
        # Verify user was created
        user = oauth_service.db.get_user_by_email("newuser@example.com")
        assert user is not None
        assert user["first_name"] == "New"
        assert user["last_name"] == "User"
        assert user["is_verified"] is True  # Should be verified since OAuth provider verified
        
        # Verify OAuth account was linked
        oauth_account = oauth_service.db.get_oauth_account("google", "oauth123")
        assert oauth_account is not None
        assert oauth_account["user_id"] == user_id


class TestGoogleOAuthProvider:
    """Test Google OAuth provider"""
    
    @pytest.fixture
    def google_provider(self):
        """Create Google OAuth provider for testing"""
        return GoogleOAuthProvider()
    
    def test_google_provider_initialization(self, google_provider):
        """Test Google provider initializes correctly"""
        assert google_provider.auth_url == "https://accounts.google.com/o/oauth2/v2/auth"
        assert google_provider.token_url == "https://oauth2.googleapis.com/token"
        assert google_provider.user_info_url == "https://www.googleapis.com/oauth2/v2/userinfo"
        assert "openid email profile" in google_provider.scope
    
    def test_generate_auth_url(self, google_provider):
        """Test generating Google auth URL"""
        state = "test_state_123"
        auth_url = google_provider.generate_auth_url(state)
        
        assert "accounts.google.com/o/oauth2/v2/auth" in auth_url
        assert f"state={state}" in auth_url
        assert "scope=openid+email+profile" in auth_url
        assert "response_type=code" in auth_url
        assert "access_type=offline" in auth_url
    
    @pytest.mark.asyncio
    async def test_exchange_code_for_token_success(self, google_provider):
        """Test successful token exchange"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "access123",
            "refresh_token": "refresh123",
            "expires_in": 3600,
            "token_type": "Bearer"
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
            
            result = await google_provider.exchange_code_for_token("auth_code")
            
            assert result is not None
            assert result["access_token"] == "access123"
            assert result["refresh_token"] == "refresh123"
            assert result["expires_in"] == 3600
            assert result["token_type"] == "Bearer"
    
    @pytest.mark.asyncio
    async def test_exchange_code_for_token_failure(self, google_provider):
        """Test failed token exchange"""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
            
            result = await google_provider.exchange_code_for_token("invalid_code")
            assert result is None
    
    @pytest.mark.asyncio
    async def test_get_user_info_success(self, google_provider):
        """Test successful user info retrieval"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "12345",
            "email": "user@gmail.com",
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "picture": "https://example.com/pic.jpg",
            "verified_email": True
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            result = await google_provider.get_user_info("access_token")
            
            assert result is not None
            assert result["provider_user_id"] == "12345"
            assert result["email"] == "user@gmail.com"
            assert result["name"] == "Test User"
            assert result["given_name"] == "Test"
            assert result["family_name"] == "User"
            assert result["verified_email"] is True
    
    @pytest.mark.asyncio
    async def test_get_user_info_failure(self, google_provider):
        """Test failed user info retrieval"""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            result = await google_provider.get_user_info("invalid_token")
            assert result is None


class TestGitHubOAuthProvider:
    """Test GitHub OAuth provider"""
    
    @pytest.fixture
    def github_provider(self):
        """Create GitHub OAuth provider for testing"""
        return GitHubOAuthProvider()
    
    def test_github_provider_initialization(self, github_provider):
        """Test GitHub provider initializes correctly"""
        assert github_provider.auth_url == "https://github.com/login/oauth/authorize"
        assert github_provider.token_url == "https://github.com/login/oauth/access_token"
        assert github_provider.user_info_url == "https://api.github.com/user"
        assert github_provider.scope == "user:email"
    
    def test_generate_auth_url(self, github_provider):
        """Test generating GitHub auth URL"""
        state = "test_state_456"
        auth_url = github_provider.generate_auth_url(state)
        
        assert "github.com/login/oauth/authorize" in auth_url
        assert f"state={state}" in auth_url
        assert "scope=user%3Aemail" in auth_url
        assert "allow_signup=true" in auth_url
    
    @pytest.mark.asyncio
    async def test_exchange_code_for_token_success(self, github_provider):
        """Test successful GitHub token exchange"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "github_access123",
            "token_type": "bearer",
            "scope": "user:email"
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
            
            result = await github_provider.exchange_code_for_token("auth_code")
            
            assert result is not None
            assert result["access_token"] == "github_access123"
            assert result["token_type"] == "bearer"
            assert result["scope"] == "user:email"
    
    @pytest.mark.asyncio
    async def test_get_user_info_success(self, github_provider):
        """Test successful GitHub user info retrieval"""
        # Mock user profile response
        mock_user_response = Mock()
        mock_user_response.status_code = 200
        mock_user_response.json.return_value = {
            "id": 67890,
            "login": "testuser",
            "name": "Test GitHub User",
            "email": "user@github.com",
            "avatar_url": "https://github.com/avatar.jpg",
            "company": "Test Co",
            "location": "Test City"
        }
        
        # Mock email response
        mock_email_response = Mock()
        mock_email_response.status_code = 200
        mock_email_response.json.return_value = [
            {
                "email": "user@github.com",
                "primary": True,
                "verified": True
            },
            {
                "email": "alt@github.com",
                "primary": False,
                "verified": False
            }
        ]
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_async_client = mock_client.return_value.__aenter__.return_value
            mock_async_client.get = AsyncMock(side_effect=[mock_user_response, mock_email_response])
            
            result = await github_provider.get_user_info("access_token")
            
            assert result is not None
            assert result["provider_user_id"] == "67890"
            assert result["email"] == "user@github.com"
            assert result["name"] == "Test GitHub User"
            assert result["login"] == "testuser"
            assert result["verified_email"] is True
            assert result["company"] == "Test Co"
            assert result["location"] == "Test City"
    
    @pytest.mark.asyncio
    async def test_get_user_info_no_primary_email(self, github_provider):
        """Test GitHub user info when no primary email is found"""
        # Mock user profile response
        mock_user_response = Mock()
        mock_user_response.status_code = 200
        mock_user_response.json.return_value = {
            "id": 67890,
            "login": "testuser",
            "name": "Test User",
            "email": "fallback@github.com"
        }
        
        # Mock email response with no primary email
        mock_email_response = Mock()
        mock_email_response.status_code = 200
        mock_email_response.json.return_value = [
            {
                "email": "alt@github.com",
                "primary": False,
                "verified": False
            }
        ]
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_async_client = mock_client.return_value.__aenter__.return_value
            mock_async_client.get = AsyncMock(side_effect=[mock_user_response, mock_email_response])
            
            result = await github_provider.get_user_info("access_token")
            
            assert result is not None
            assert result["email"] == "fallback@github.com"  # Should use profile email
            assert result["verified_email"] is False


class TestOAuthIntegration:
    """Test OAuth integration with main application"""
    
    @pytest.fixture
    def db(self):
        """Create test database"""
        return Database(":memory:")
    
    def test_oauth_account_linking_existing_user(self, db):
        """Test linking OAuth account to existing user"""
        # Create existing user
        from src.framework.auth.auth import AuthenticationService
        auth_service = AuthenticationService("test-secret-key-32-chars-minimum")
        password_hash = auth_service.hash_password("TestPassword123!")
        user_id = db.create_user("existing@example.com", password_hash, "Existing", "User")
        
        oauth_service = OAuthService(db)
        
        # Link OAuth account
        success = oauth_service.link_oauth_account(
            user_id=user_id,
            provider="google",
            provider_user_id="oauth123",
            provider_email="existing@example.com",
            access_token="access123"
        )
        
        assert success is True
        
        # Verify user can be found by OAuth
        found_user = oauth_service.find_user_by_oauth("google", "oauth123")
        assert found_user is not None
        assert found_user["id"] == user_id
        assert found_user["email"] == "existing@example.com"
    
    def test_oauth_account_creation(self):
        """Test creating new user via OAuth"""
        db = Database(":memory:")
        oauth_service = OAuthService(db)
        
        user_info = {
            "provider_user_id": "new_oauth123",
            "email": f"newuser{secrets.token_hex(4)}@example.com",
            "name": "New OAuth User",
            "given_name": "New",
            "family_name": "User",
            "verified_email": True
        }
        
        user_id = oauth_service.create_user_from_oauth(
            provider="github",
            user_info=user_info,
            access_token="new_access123"
        )
        
        assert user_id is not None
        
        # Verify user was created correctly
        user = oauth_service.db.get_user_with_role(user_id)
        assert user is not None
        assert user["email"] == user_info["email"]
        assert user["first_name"] == "New"
        assert user["last_name"] == "User"
        assert user["is_verified"] is True
        assert user["role_id"] == 1  # Should be regular user by default
        
        # Verify OAuth account was linked
        oauth_account = oauth_service.db.get_oauth_account("github", "new_oauth123")
        assert oauth_account is not None
        assert oauth_account["user_id"] == user_id
    
    def test_oauth_duplicate_account_prevention(self, db):
        """Test preventing duplicate OAuth account linking"""
        # Create user and link OAuth account
        from src.framework.auth.auth import AuthenticationService
        auth_service = AuthenticationService("test-secret-key-32-chars-minimum")
        password_hash = auth_service.hash_password("TestPassword123!")
        user_id_1 = db.create_user("user1@example.com", password_hash, "User", "One")
        user_id_2 = db.create_user("user2@example.com", password_hash, "User", "Two")
        
        oauth_service = OAuthService(db)
        
        # Link OAuth account to first user
        success1 = oauth_service.link_oauth_account(
            user_id=user_id_1,
            provider="google",
            provider_user_id="shared_oauth",
            provider_email="user1@example.com"
        )
        assert success1 is True
        
        # Try to link same OAuth account to second user (should update, not create duplicate)
        success2 = oauth_service.link_oauth_account(
            user_id=user_id_2,
            provider="google",
            provider_user_id="shared_oauth",
            provider_email="user2@example.com"
        )
        assert success2 is True
        
        # Verify the OAuth account now points to the second user
        oauth_account = db.get_oauth_account("google", "shared_oauth")
        assert oauth_account["user_id"] == user_id_1  # Should still be first user
        assert oauth_account["provider_email"] == "user2@example.com"  # Email should be updated


# Integration test for OAuth state management
def test_oauth_state_lifecycle():
    """Test complete OAuth state lifecycle"""
    db = Database(":memory:")
    oauth_service = OAuthService(db)
    
    # Generate state
    state = oauth_service.generate_state_token("google", "session123")
    
    # Verify state exists in database
    cursor = db.conn.execute("""
        SELECT COUNT(*) FROM oauth_state_tokens WHERE state_token = ?
    """, [state])
    assert cursor.fetchone()[0] == 1
    
    # Validate state (this should consume the token)
    assert oauth_service.validate_state_token(state, "google") is True
    
    # State should be removed after validation (one-time use)
    cursor = db.conn.execute("""
        SELECT COUNT(*) FROM oauth_state_tokens WHERE state_token = ?
    """, [state])
    assert cursor.fetchone()[0] == 0