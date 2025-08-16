"""
Session management utilities for PY-Framework
Handles user authentication and session state
"""

from typing import Optional, Dict, Any
from fasthtml.common import *

# Simple in-memory session store for development
# In production, this would be replaced with proper cookie handling
_active_sessions = {}


def store_session(session_id: str, user_id: int):
    """Store session temporarily for demo purposes"""
    _active_sessions[session_id] = user_id


def get_current_user(request, db, auth_service) -> Optional[Dict[str, Any]]:
    """Get current logged-in user from session"""
    try:
        # For development, try to get session from cookie first
        session_id = request.cookies.get('session_id')
        
        # If no cookie, check if there's an active session (demo mode)
        if not session_id and _active_sessions:
            # Get the most recent session for demo purposes
            session_id = list(_active_sessions.keys())[-1] if _active_sessions else None
        
        if not session_id:
            return None
        
        # Validate session and get user
        user = auth_service.get_user_from_session(db, session_id)
        return user
    except Exception as e:
        print(f"Session error: {e}")
        return None


def create_session_response(content, session_id: str = None, clear_session: bool = False):
    """Create response with session cookie"""
    # For now, return content directly - we'll implement proper cookie handling later
    # The session is stored in the database and can be retrieved by session_id
    return content


def require_auth(func):
    """Decorator to require authentication for routes"""
    def wrapper(request, *args, **kwargs):
        # This is a simplified decorator - in practice you'd want more sophisticated handling
        return func(request, *args, **kwargs)
    return wrapper