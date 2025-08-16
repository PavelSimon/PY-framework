"""
CSRF (Cross-Site Request Forgery) protection for PY-Framework
Provides token generation, validation, and middleware for secure forms
"""

import secrets
import hashlib
import hmac
from typing import Optional, Dict, Any
from fasthtml.common import *
from datetime import datetime, timedelta


class CSRFProtection:
    def __init__(self, secret_key: str, token_lifetime_minutes: int = 60):
        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        self.token_lifetime = timedelta(minutes=token_lifetime_minutes)
        self._active_tokens = {}  # In production, use Redis or database
    
    def generate_token(self, session_id: str = None) -> str:
        """Generate a new CSRF token"""
        # Create a random token
        random_token = secrets.token_urlsafe(32)
        # Use timestamp as integer to avoid colon issues
        timestamp = str(int(datetime.now().timestamp()))
        
        # Create the token data
        token_data = f"{random_token}|{timestamp}"
        if session_id:
            token_data = f"{session_id}|{token_data}"
        
        # Sign the token with HMAC
        signature = hmac.new(
            self.secret_key,
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Combine token data and signature
        full_token = f"{token_data}|{signature}"
        
        # Store token temporarily (in production, use proper storage)
        self._active_tokens[random_token] = {
            'created_at': datetime.now(),
            'session_id': session_id,
            'used': False
        }
        
        return full_token
    
    def validate_token(self, token: str, session_id: str = None, consume: bool = True) -> bool:
        """Validate a CSRF token"""
        try:
            if not token:
                return False
            
            # Split token parts using pipe separator
            parts = token.split('|')
            if len(parts) < 3:
                return False
            
            # Extract components based on whether session was used during generation
            if len(parts) == 4:
                # Token includes session ID
                token_session_id, random_token, timestamp, signature = parts
                if session_id and token_session_id != session_id:
                    return False
                token_data = f"{token_session_id}|{random_token}|{timestamp}"
            else:
                # Token without session ID
                random_token, timestamp, signature = parts
                token_data = f"{random_token}|{timestamp}"
            
            # Verify signature
            expected_signature = hmac.new(
                self.secret_key,
                token_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return False
            
            # Check if token exists and is not used
            if random_token not in self._active_tokens:
                return False
            
            token_info = self._active_tokens[random_token]
            if token_info['used'] and consume:
                return False
            
            # Check token expiration
            token_age = datetime.now() - token_info['created_at']
            if token_age > self.token_lifetime:
                # Remove expired token
                del self._active_tokens[random_token]
                return False
            
            # Mark token as used if consuming
            if consume:
                token_info['used'] = True
            
            return True
            
        except Exception as e:
            print(f"CSRF token validation error: {e}")
            return False
    
    def cleanup_expired_tokens(self):
        """Remove expired tokens from storage"""
        current_time = datetime.now()
        expired_tokens = []
        
        for token, info in self._active_tokens.items():
            if current_time - info['created_at'] > self.token_lifetime:
                expired_tokens.append(token)
        
        for token in expired_tokens:
            del self._active_tokens[token]
    
    def create_csrf_input(self, session_id: str = None) -> Input:
        """Create a hidden input field with CSRF token"""
        token = self.generate_token(session_id)
        return Input(type="hidden", name="csrf_token", value=token)
    
    def create_csrf_meta(self, session_id: str = None) -> Meta:
        """Create a meta tag with CSRF token for AJAX requests"""
        token = self.generate_token(session_id)
        return Meta(name="csrf-token", content=token)


def csrf_protect(csrf_protection: CSRFProtection):
    """Decorator to protect routes with CSRF validation"""
    def decorator(func):
        def wrapper(request, *args, **kwargs):
            # Only check CSRF for state-changing methods
            if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                # Get CSRF token from form data or headers
                csrf_token = None
                
                # Try to get from form data first
                if hasattr(request, 'form'):
                    csrf_token = request.form.get('csrf_token')
                
                # Try to get from headers (for AJAX requests)
                if not csrf_token:
                    csrf_token = request.headers.get('X-CSRF-Token')
                
                # Get session ID for validation
                session_id = request.cookies.get('session_id')
                
                # Validate token
                if not csrf_protection.validate_token(csrf_token, session_id):
                    return Response(
                        content="CSRF token validation failed",
                        status_code=403,
                        headers={"Content-Type": "text/plain"}
                    )
            
            return func(request, *args, **kwargs)
        return wrapper
    return decorator


def add_csrf_middleware(app, csrf_protection: CSRFProtection):
    """Add CSRF protection middleware to FastHTML app"""
    
    @app.middleware("http")
    async def csrf_middleware(request, call_next):
        # Add CSRF protection to request for easy access in routes
        request.csrf = csrf_protection
        
        # Process the request
        response = await call_next(request)
        
        # Clean up expired tokens periodically
        if secrets.randbelow(100) < 5:  # 5% chance to cleanup
            csrf_protection.cleanup_expired_tokens()
        
        return response


# Helper function to add CSRF token to forms
def add_csrf_to_form(form_element, csrf_protection: CSRFProtection, session_id: str = None):
    """Add CSRF token to an existing form element"""
    csrf_input = csrf_protection.create_csrf_input(session_id)
    
    # If form_element has children, add to them
    if hasattr(form_element, 'children') and form_element.children:
        form_element.children.append(csrf_input)
    else:
        # Create new form with CSRF token
        return Form(csrf_input, form_element)
    
    return form_element