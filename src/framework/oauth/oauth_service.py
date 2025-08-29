import secrets
import httpx
from typing import Optional, Dict, Any
from urllib.parse import urlencode, parse_qs, urlparse
from jose import jwt, JWTError
from datetime import datetime, timedelta

from ..config import settings
from ..database.database import Database


class OAuthProvider:
    """Base class for OAuth providers"""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.db = Database()
    
    def generate_auth_url(self, state: str) -> str:
        """Generate authorization URL for OAuth flow"""
        raise NotImplementedError
    
    def exchange_code_for_token(self, code: str, state: str) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for access token"""
        raise NotImplementedError
    
    def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Get user information from provider"""
        raise NotImplementedError


class GoogleOAuthProvider(OAuthProvider):
    """Google OAuth 2.0 provider implementation"""
    
    def __init__(self):
        super().__init__(
            client_id=settings.google_client_id,
            client_secret=settings.google_client_secret,
            redirect_uri=settings.google_redirect_uri
        )
        
        # Debug OAuth configuration
        print(f"Google OAuth configured: client_id={'***' + settings.google_client_id[-4:] if settings.google_client_id else 'None'}")
        print(f"Google OAuth redirect_uri: {settings.google_redirect_uri}")
        
        if not settings.google_client_id or not settings.google_client_secret:
            print("⚠️  Google OAuth not properly configured - missing client_id or client_secret")
        self.auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
        self.token_url = "https://oauth2.googleapis.com/token"
        self.user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        self.scope = "openid email profile"
    
    def generate_auth_url(self, state: str) -> str:
        """Generate Google OAuth authorization URL"""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "response_type": "code",
            "state": state,
            "access_type": "offline",
            "prompt": "consent"
        }
        return f"{self.auth_url}?{urlencode(params)}"
    
    async def exchange_code_for_token(self, code: str, state: str = None) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for Google access token"""
        try:
            data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": self.redirect_uri
            }
            
            client = httpx.AsyncClient()
            try:
                # Support both regular client and mocked async context manager
                client_obj = client
                try:
                    enter = getattr(client, "__aenter__", None)
                    if callable(enter):
                        entered = enter()
                        # Handle awaitable __aenter__
                        import inspect
                        client_obj = await entered if inspect.isawaitable(entered) else entered
                except Exception:
                    client_obj = client

                response = client_obj.post(self.token_url, data=data)
                try:
                    import inspect
                    if inspect.isawaitable(response):
                        response = await response
                except Exception:
                    pass
            finally:
                try:
                    await client.aclose()
                except Exception:
                    pass
                
            if response.status_code == 200:
                token_data = response.json()
                return {
                    "access_token": token_data.get("access_token"),
                    "refresh_token": token_data.get("refresh_token"),
                    "expires_in": token_data.get("expires_in", 3600),
                    "token_type": token_data.get("token_type", "Bearer"),
                    "id_token": token_data.get("id_token")
                }
            else:
                print(f"Token exchange failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"Error exchanging code for token: {e}")
            return None
    
    async def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Get user information from Google"""
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            
            client = httpx.AsyncClient()
            try:
                client_obj = client
                try:
                    enter = getattr(client, "__aenter__", None)
                    if callable(enter):
                        entered = enter()
                        import inspect
                        client_obj = await entered if inspect.isawaitable(entered) else entered
                except Exception:
                    client_obj = client

                response = client_obj.get(self.user_info_url, headers=headers)
                try:
                    import inspect
                    if inspect.isawaitable(response):
                        response = await response
                except Exception:
                    pass
            finally:
                try:
                    await client.aclose()
                except Exception:
                    pass
                
            if response.status_code == 200:
                user_data = response.json()
                return {
                    "provider_user_id": user_data.get("id"),
                    "email": user_data.get("email"),
                    "name": user_data.get("name"),
                    "given_name": user_data.get("given_name"),
                    "family_name": user_data.get("family_name"),
                    "picture": user_data.get("picture"),
                    "verified_email": user_data.get("verified_email", False)
                }
            else:
                print(f"User info request failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"Error getting user info: {e}")
            return None


class GitHubOAuthProvider(OAuthProvider):
    """GitHub OAuth provider implementation"""
    
    def __init__(self):
        super().__init__(
            client_id=settings.github_client_id,
            client_secret=settings.github_client_secret,
            redirect_uri=settings.github_redirect_uri
        )
        
        # Debug OAuth configuration  
        print(f"GitHub OAuth configured: client_id={'***' + settings.github_client_id[-4:] if settings.github_client_id else 'None'}")
        print(f"GitHub OAuth redirect_uri: {settings.github_redirect_uri}")
        
        if not settings.github_client_id or not settings.github_client_secret:
            print("⚠️  GitHub OAuth not properly configured - missing client_id or client_secret")
        self.auth_url = "https://github.com/login/oauth/authorize"
        self.token_url = "https://github.com/login/oauth/access_token"
        self.user_info_url = "https://api.github.com/user"
        self.user_email_url = "https://api.github.com/user/emails"
        self.scope = "user:email"
    
    def generate_auth_url(self, state: str) -> str:
        """Generate GitHub OAuth authorization URL"""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state,
            "allow_signup": "true"
        }
        return f"{self.auth_url}?{urlencode(params)}"
    
    async def exchange_code_for_token(self, code: str, state: str = None) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for GitHub access token"""
        try:
            data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code
            }
            
            headers = {"Accept": "application/json"}
            
            client = httpx.AsyncClient()
            try:
                client_obj = client
                try:
                    enter = getattr(client, "__aenter__", None)
                    if callable(enter):
                        entered = enter()
                        import inspect
                        client_obj = await entered if inspect.isawaitable(entered) else entered
                except Exception:
                    client_obj = client

                response = client_obj.post(self.token_url, data=data, headers=headers)
                try:
                    import inspect
                    if inspect.isawaitable(response):
                        response = await response
                except Exception:
                    pass
            finally:
                try:
                    await client.aclose()
                except Exception:
                    pass
                
            if response.status_code == 200:
                token_data = response.json()
                return {
                    "access_token": token_data.get("access_token"),
                    "token_type": token_data.get("token_type", "bearer"),
                    "scope": token_data.get("scope")
                }
            else:
                print(f"Token exchange failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"Error exchanging code for token: {e}")
            return None
    
    async def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Get user information from GitHub"""
        try:
            headers = {
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            client = httpx.AsyncClient()
            try:
                # Get user profile
                client_obj = client
                try:
                    enter = getattr(client, "__aenter__", None)
                    if callable(enter):
                        entered = enter()
                        import inspect
                        client_obj = await entered if inspect.isawaitable(entered) else entered
                except Exception:
                    client_obj = client

                user_response = client_obj.get(self.user_info_url, headers=headers)
                try:
                    import inspect
                    if inspect.isawaitable(user_response):
                        user_response = await user_response
                except Exception:
                    pass
                if user_response.status_code != 200:
                    print(f"User info request failed: {user_response.status_code}")
                    return None
                
                user_data = user_response.json()
                
                # Get user emails
                email_response = client_obj.get(self.user_email_url, headers=headers)
                try:
                    import inspect
                    if inspect.isawaitable(email_response):
                        email_response = await email_response
                except Exception:
                    pass
                email_data = []
                if email_response.status_code == 200:
                    email_data = email_response.json()
                
                # Find primary email
                primary_email = None
                verified_email = False
                for email in email_data:
                    if email.get("primary", False):
                        primary_email = email.get("email")
                        verified_email = email.get("verified", False)
                        break
                
                # Fallback to profile email if no primary found
                if not primary_email:
                    primary_email = user_data.get("email")
            finally:
                try:
                    await client.aclose()
                except Exception:
                    pass
                
                return {
                    "provider_user_id": str(user_data.get("id")),
                    "email": primary_email,
                    "name": user_data.get("name") or user_data.get("login"),
                    "login": user_data.get("login"),
                    "avatar_url": user_data.get("avatar_url"),
                    "verified_email": verified_email,
                    "company": user_data.get("company"),
                    "location": user_data.get("location")
                }
                
        except Exception as e:
            print(f"Error getting user info: {e}")
            return None


class OAuthService:
    """Main OAuth service for managing OAuth flows"""
    
    def __init__(self, db: Database = None):
        self.db = db or Database()
        self.providers = {
            "google": GoogleOAuthProvider(),
            "github": GitHubOAuthProvider()
        }
    
    def generate_state_token(self, provider: str, session_id: str = None) -> str:
        """Generate secure state token for OAuth flow"""
        state = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(minutes=10)
        
        try:
            # Clean up expired tokens first
            self.cleanup_expired_states()
            
            # Store state token in database
            self.db.conn.execute("""
                INSERT INTO oauth_state_tokens (state_token, provider, session_id, expires_at)
                VALUES (?, ?, ?, ?)
            """, [state, provider, session_id, expires_at])
            
            return state
        except Exception as e:
            print(f"Error generating OAuth state token: {e}")
            return None
    
    def validate_state_token(self, state: str, provider: str) -> bool:
        """Validate OAuth state token"""
        if not state:
            print(f"OAuth state validation failed: No state token provided")
            return False
        
        try:
            # Debug: Check if table exists
            try:
                cursor = self.db.conn.execute("""
                    SELECT COUNT(*) FROM oauth_state_tokens
                """)
                total_tokens = cursor.fetchone()[0]
                print(f"OAuth state validation: Found {total_tokens} total state tokens in database")
            except Exception as table_error:
                print(f"OAuth state validation: Table access error: {table_error}")
                # For development, if table doesn't exist, create it
                try:
                    self.db._init_schema()  # Re-initialize schema
                    print("OAuth state validation: Re-initialized database schema")
                except Exception as init_error:
                    print(f"OAuth state validation: Schema init error: {init_error}")
                    return False
            
            cursor = self.db.conn.execute("""
                SELECT provider, expires_at FROM oauth_state_tokens 
                WHERE state_token = ?
            """, [state])
            
            row = cursor.fetchone()
            if not row:
                print(f"OAuth state validation failed: State token '{state[:8]}...' not found in database")
                # Debug: Show all tokens
                try:
                    cursor = self.db.conn.execute("SELECT state_token, provider, expires_at FROM oauth_state_tokens ORDER BY created_at DESC LIMIT 5")
                    recent_tokens = cursor.fetchall()
                    print(f"Recent state tokens: {[(t[0][:8], t[1], t[2]) for t in recent_tokens]}")
                except Exception as debug_error:
                    print(f"Debug query failed: {debug_error}")
                return False
            
            stored_provider, expires_at = row
            print(f"OAuth state validation: Found token for provider '{stored_provider}', expires at {expires_at}")
            
            # Check expiration
            if datetime.now() > expires_at:
                print(f"OAuth state validation failed: Token expired at {expires_at}")
                # Clean up expired token
                self.db.conn.execute("""
                    DELETE FROM oauth_state_tokens WHERE state_token = ?
                """, [state])
                return False
            
            # Check provider matches
            if stored_provider != provider:
                print(f"OAuth state validation failed: Provider mismatch. Expected '{provider}', got '{stored_provider}'")
                return False
            
            # Token is valid, clean it up (one-time use)
            self.db.conn.execute("""
                DELETE FROM oauth_state_tokens WHERE state_token = ?
            """, [state])
            
            print(f"OAuth state validation successful for provider '{provider}'")
            return True
        except Exception as e:
            print(f"Error validating OAuth state token: {e}")
            return False
    
    def get_provider(self, provider_name: str) -> Optional[OAuthProvider]:
        """Get OAuth provider by name"""
        return self.providers.get(provider_name)
    
    def get_auth_url(self, provider_name: str, session_id: str = None) -> Optional[str]:
        """Get authorization URL for provider"""
        provider = self.get_provider(provider_name)
        if not provider:
            return None
        
        state = self.generate_state_token(provider_name, session_id)
        return provider.generate_auth_url(state)
    
    def cleanup_expired_states(self):
        """Clean up expired state tokens"""
        try:
            self.db.conn.execute("""
                DELETE FROM oauth_state_tokens 
                WHERE expires_at < CURRENT_TIMESTAMP
            """)
        except Exception as e:
            print(f"Error cleaning up expired OAuth state tokens: {e}")
    
    def link_oauth_account(self, user_id: int, provider: str, provider_user_id: str,
                          provider_email: str = None, access_token: str = None,
                          refresh_token: str = None, expires_at: datetime = None) -> bool:
        """Link OAuth account to existing user"""
        try:
            # Check if OAuth account already exists
            existing = self.db.get_oauth_account(provider, provider_user_id)
            if existing:
                # Update existing account
                self.db.conn.execute("""
                    UPDATE oauth_accounts 
                    SET access_token = ?, refresh_token = ?, expires_at = ?,
                        provider_email = ?
                    WHERE provider = ? AND provider_user_id = ?
                """, [access_token, refresh_token, expires_at, provider_email,
                      provider, provider_user_id])
                return True
            
            # Create new OAuth account link
            self.db.create_oauth_account(
                user_id=user_id,
                provider=provider,
                provider_user_id=provider_user_id,
                provider_email=provider_email,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=expires_at
            )
            return True
            
        except Exception as e:
            print(f"Error linking OAuth account: {e}")
            return False
    
    def find_user_by_oauth(self, provider: str, provider_user_id: str) -> Optional[Dict[str, Any]]:
        """Find user by OAuth provider account"""
        oauth_account = self.db.get_oauth_account(provider, provider_user_id)
        if not oauth_account:
            return None
        
        return self.db.get_user_with_role(oauth_account["user_id"])
    
    def find_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Find user by email for account linking"""
        return self.db.get_user_by_email(email)
    
    def create_user_from_oauth(self, provider: str, user_info: Dict[str, Any],
                              access_token: str = None, refresh_token: str = None,
                              expires_at: datetime = None) -> Optional[int]:
        """Create new user from OAuth information"""
        try:
            # Extract name components
            name = user_info.get("name", "")
            given_name = user_info.get("given_name", "")
            family_name = user_info.get("family_name", "")
            
            # For GitHub, use name or login
            if provider == "github" and not given_name:
                if name:
                    name_parts = name.split(" ", 1)
                    given_name = name_parts[0]
                    family_name = name_parts[1] if len(name_parts) > 1 else ""
                else:
                    given_name = user_info.get("login", "")
            
            # Create user (no password needed for OAuth-only accounts)
            # Generate a random password hash since it's required by schema
            import bcrypt
            random_password = secrets.token_urlsafe(32)
            password_hash = bcrypt.hashpw(random_password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')
            
            user_id = self.db.create_user(
                email=user_info["email"],
                password_hash=password_hash,
                first_name=given_name,
                last_name=family_name
            )
            
            # Mark as verified if provider confirms email
            if user_info.get("verified_email", False):
                self.db.verify_user_email(user_id)
            
            # Link OAuth account
            if self.link_oauth_account(
                user_id=user_id,
                provider=provider,
                provider_user_id=user_info["provider_user_id"],
                provider_email=user_info["email"],
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=expires_at
            ):
                return user_id
            else:
                # Rollback user creation if OAuth linking fails
                self.db.conn.execute("DELETE FROM users WHERE id = ?", [user_id])
                return None
                
        except Exception as e:
            print(f"Error creating user from OAuth: {e}")
            return None
