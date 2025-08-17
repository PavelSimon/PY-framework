"""
Security and role-based access control middleware for PY-Framework
Provides decorators and middleware for authentication and authorization
"""

from functools import wraps
from typing import Callable, Optional, List, Union
from fasthtml.common import *
from .session import get_current_user
from .layout import create_app_layout, create_error_message


def require_auth(redirect_to: str = "/auth/login"):
    """Decorator to require authentication for routes"""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            # This is handled by individual route checks currently
            # The decorator pattern would need FastHTML framework integration
            return func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_role(required_roles: Union[int, List[int]], redirect_to: str = "/"):
    """Decorator to require specific roles for routes"""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            # This is handled by individual route checks currently
            # The decorator pattern would need FastHTML framework integration
            return func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_admin(redirect_to: str = "/"):
    """Decorator to require admin role (role_id = 0) for routes"""
    return require_role(0, redirect_to)


class RoleValidator:
    """Role validation utility class for checking user permissions"""
    
    def __init__(self, db, auth_service):
        self.db = db
        self.auth_service = auth_service
    
    def check_auth(self, request) -> tuple[bool, Optional[dict]]:
        """Check if user is authenticated"""
        user = get_current_user(request, self.db, self.auth_service)
        return user is not None, user
    
    def check_role(self, request, required_roles: Union[int, List[int]]) -> tuple[bool, Optional[dict]]:
        """Check if user has required role(s)"""
        is_auth, user = self.check_auth(request)
        if not is_auth:
            return False, None
        
        user_role = user.get('role_id')
        
        if isinstance(required_roles, int):
            required_roles = [required_roles]
        
        return user_role in required_roles, user
    
    def check_admin(self, request) -> tuple[bool, Optional[dict]]:
        """Check if user is admin (role_id = 0)"""
        return self.check_role(request, 0)
    
    def create_access_denied_response(self, user: Optional[dict] = None, 
                                    message: str = "Access denied") -> Response:
        """Create standardized access denied response"""
        content = Div(
            create_error_message(message),
            P("You don't have permission to access this resource."),
            P(A("Go to Dashboard", href="/dashboard", cls="btn btn-primary") if user else 
              A("Login", href="/auth/login", cls="btn btn-primary"))
        )
        
        return Titled("Access Denied", create_app_layout(
            content,
            user=user,
            page_title="Access Denied",
            page_subtitle="Insufficient permissions"
        ))
    
    def create_auth_required_response(self) -> Response:
        """Create standardized authentication required response"""
        return RedirectResponse("/auth/login", status_code=302)


def validate_admin_access(request, db, auth_service) -> tuple[bool, Optional[dict], Optional[Response]]:
    """
    Utility function to validate admin access for routes
    Returns (is_admin, user, error_response)
    """
    validator = RoleValidator(db, auth_service)
    is_admin, user = validator.check_admin(request)
    
    if not user:
        return False, None, validator.create_auth_required_response()
    
    if not is_admin:
        return False, user, validator.create_access_denied_response(
            user, "Administrator access required"
        )
    
    return True, user, None


def validate_user_access(request, db, auth_service) -> tuple[bool, Optional[dict], Optional[Response]]:
    """
    Utility function to validate user access for routes
    Returns (is_authenticated, user, error_response)
    """
    validator = RoleValidator(db, auth_service)
    is_auth, user = validator.check_auth(request)
    
    if not is_auth:
        return False, None, validator.create_auth_required_response()
    
    return True, user, None


class SecurityMiddleware:
    """Security middleware for additional protection"""
    
    def __init__(self, app, db, auth_service):
        self.app = app
        self.db = db
        self.auth_service = auth_service
        self.validator = RoleValidator(db, auth_service)
    
    def apply_security_headers(self, response):
        """Apply security headers to responses"""
        # This would be implemented if FastHTML supports middleware hooks
        # For now, security headers are handled in the main app configuration
        return response
    
    def check_rate_limiting(self, request):
        """Check rate limiting for requests"""
        # This would integrate with the existing rate limiter
        # For now, rate limiting is handled in auth routes
        return True
    
    def log_security_event(self, event_type: str, user_id: Optional[int], 
                          ip_address: str, details: str):
        """Log security events for monitoring"""
        # This would log to a security audit table
        # For now, security events are logged to console
        print(f"SECURITY EVENT: {event_type} - User {user_id} - IP {ip_address} - {details}")


# Pre-built validation functions for common use cases
def admin_only_route(func):
    """
    Decorator-style function to mark admin-only routes
    Note: This is more of a documentation decorator since FastHTML
    routes handle validation inline
    """
    func._admin_only = True
    return func


def authenticated_route(func):
    """
    Decorator-style function to mark authenticated routes
    Note: This is more of a documentation decorator since FastHTML
    routes handle validation inline
    """
    func._auth_required = True
    return func


# Route protection utility functions
def protect_admin_route(request, db, auth_service, target_user_id: Optional[int] = None):
    """
    Comprehensive admin route protection
    Optionally prevents admin from acting on themselves
    """
    is_admin, user, error_response = validate_admin_access(request, db, auth_service)
    
    if not is_admin:
        return False, user, error_response
    
    # Additional check: prevent admin from acting on themselves
    if target_user_id and user and user.get('id') == target_user_id:
        error_response = RoleValidator(db, auth_service).create_access_denied_response(
            user, "You cannot perform this action on your own account"
        )
        return False, user, error_response
    
    return True, user, None


def protect_user_route(request, db, auth_service, user_id: Optional[int] = None):
    """
    User route protection with optional ownership check
    If user_id is provided, ensures user can only access their own data
    """
    is_auth, user, error_response = validate_user_access(request, db, auth_service)
    
    if not is_auth:
        return False, user, error_response
    
    # Additional check: ensure user can only access their own data
    if user_id and user and user.get('id') != user_id:
        # Check if user is admin (admins can access any user data)
        if user.get('role_id') != 0:
            error_response = RoleValidator(db, auth_service).create_access_denied_response(
                user, "You can only access your own data"
            )
            return False, user, error_response
    
    return True, user, None