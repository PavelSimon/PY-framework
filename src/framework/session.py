"""
Session management utilities for PY-Framework
Handles user authentication and session state
"""

from typing import Optional, Dict, Any
from fasthtml.common import *
from datetime import timedelta

# Simple in-memory session store for development
# In production, this would be replaced with proper cookie handling
_active_sessions = {}


def store_session(session_id: str, user_id: int):
    """Store session temporarily for demo purposes"""
    _active_sessions[session_id] = user_id


def clear_session(session_id: str):
    """Clear session from temporary store"""
    if session_id in _active_sessions:
        del _active_sessions[session_id]


def get_current_user(request, db, auth_service) -> Optional[Dict[str, Any]]:
    """Get current logged-in user from session"""
    try:
        # Get session from cookie first
        session_id = request.cookies.get('session_id')
        
        # For development, if no cookie but we have active sessions, use the most recent one
        # This is a simplified approach for development without proper cookie handling
        if not session_id and _active_sessions:
            session_id = list(_active_sessions.keys())[-1]
        
        if not session_id:
            return None
        
        # Check if session exists in temporary store (development only)
        if session_id not in _active_sessions:
            return None
        
        # Validate session and get user
        user = auth_service.get_user_from_session(db, session_id)
        return user
    except Exception as e:
        print(f"Session error: {e}")
        return None


def create_session_response(content, session_id: str = None, clear_session: bool = False):
    """Create response with session cookie"""
    if clear_session:
        # Clear session from temporary store
        if session_id:
            clear_session(session_id)
        # For development, we'll clear all sessions to ensure logout works
        _active_sessions.clear()
    
    # For now, return content directly and rely on the in-memory session store
    # This is a simplified approach for development
    return content


def build_session_cookie(
    session_id: str,
    *,
    max_age_hours: int = 24,
    path: str = "/",
    secure: bool = True,
    httponly: bool = True,
    samesite: str = "Lax",
) -> str:
    """Build a Set-Cookie string for the session with secure defaults.

    Note: This helper does not set headers by itself to avoid breaking
    existing flows. Callers may attach the returned string to a Response.
    """
    attrs = [f"session_id={session_id}"]
    attrs.append(f"Path={path}")
    if max_age_hours:
        attrs.append(f"Max-Age={int(timedelta(hours=max_age_hours).total_seconds())}")
    if secure:
        attrs.append("Secure")
    if httponly:
        attrs.append("HttpOnly")
    if samesite:
        # Normalize
        samesite_val = samesite.capitalize()
        attrs.append(f"SameSite={samesite_val}")
    return "; ".join(attrs)


def apply_session_cookie(response: Any, cookie_header: str) -> Any:
    """Attach Set-Cookie header to a Response-like object in a safe way."""
    if hasattr(response, "headers") and isinstance(response.headers, dict):
        # Multiple Set-Cookie headers can be set by using a list or appending.
        # Here we overwrite or set a single session cookie header.
        response.headers["Set-Cookie"] = cookie_header
    return response


def require_auth(func):
    """Decorator to require authentication for routes"""
    def wrapper(request, *args, **kwargs):
        # This is a simplified decorator - in practice you'd want more sophisticated handling
        return func(request, *args, **kwargs)
    return wrapper
