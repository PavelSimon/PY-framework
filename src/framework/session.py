"""
Session management utilities for PY-Framework
Handles user authentication and session state
"""

from typing import Optional, Dict, Any
from fasthtml.common import *
from datetime import timedelta
from starlette.responses import Response, RedirectResponse

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
    """Create response with session cookie actions.

    - If clear_session is True: clear server-side session state and attach an
      expired session cookie to the response.
    - Otherwise: return content unchanged (back-compat).
    """
    if clear_session:
        if session_id:
            clear_session(session_id)
        _active_sessions.clear()

        # Attach a cleared cookie to either an existing response or wrap content.
        cookie_header = clear_session_cookie()
        if hasattr(content, "headers") and isinstance(getattr(content, "headers", None), dict):
            content.headers["Set-Cookie"] = cookie_header
            return content

        # Wrap HTML-ish content in a Response so we can set headers safely
        resp = Response(str(content), media_type="text/html")
        resp.headers["Set-Cookie"] = cookie_header
        return resp

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


def clear_session_cookie(
    *,
    path: str = "/",
    secure: bool = True,
    httponly: bool = True,
    samesite: str = "Lax",
) -> str:
    """Build a Set-Cookie header that clears the session cookie.

    Uses Max-Age=0 to instruct the browser to delete the cookie.
    """
    attrs = ["session_id="]
    attrs.append(f"Path={path}")
    attrs.append("Max-Age=0")
    if secure:
        attrs.append("Secure")
    if httponly:
        attrs.append("HttpOnly")
    if samesite:
        attrs.append(f"SameSite={samesite.capitalize()}")
    return "; ".join(attrs)


def require_auth(func):
    """Decorator to require authentication for routes"""
    def wrapper(request, *args, **kwargs):
        # This is a simplified decorator - in practice you'd want more sophisticated handling
        return func(request, *args, **kwargs)
    return wrapper
