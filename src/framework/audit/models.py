from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime


class AuditEventType(Enum):
    """Audit event types for comprehensive logging"""
    
    # Authentication Events
    USER_LOGIN_SUCCESS = "user_login_success"
    USER_LOGIN_FAILED = "user_login_failed"
    USER_LOGOUT = "user_logout"
    USER_REGISTRATION = "user_registration"
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_COMPLETE = "password_reset_complete"
    PASSWORD_CHANGE = "password_change"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    
    # OAuth Events
    OAUTH_LOGIN_SUCCESS = "oauth_login_success"
    OAUTH_LOGIN_FAILED = "oauth_login_failed"
    OAUTH_ACCOUNT_LINKED = "oauth_account_linked"
    OAUTH_STATE_VALIDATION_FAILED = "oauth_state_validation_failed"
    
    # Two-Factor Authentication Events
    TWO_FA_ENABLED = "two_fa_enabled"
    TWO_FA_DISABLED = "two_fa_disabled"
    TWO_FA_VERIFICATION_SUCCESS = "two_fa_verification_success"
    TWO_FA_VERIFICATION_FAILED = "two_fa_verification_failed"
    TWO_FA_BACKUP_CODE_USED = "two_fa_backup_code_used"
    TWO_FA_BACKUP_CODES_REGENERATED = "two_fa_backup_codes_regenerated"
    
    # Session Events
    SESSION_CREATED = "session_created"
    SESSION_INVALIDATED = "session_invalidated"
    SESSION_EXPIRED = "session_expired"
    SESSION_CLEANUP = "session_cleanup"
    
    # Profile Events
    PROFILE_UPDATED = "profile_updated"
    USER_ROLE_CHANGED = "user_role_changed"
    USER_STATUS_CHANGED = "user_status_changed"
    USER_DELETED = "user_deleted"
    
    # Security Events
    CSRF_TOKEN_VALIDATION_FAILED = "csrf_token_validation_failed"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_SESSION_ACCESS = "invalid_session_access"
    UNAUTHORIZED_ACCESS_ATTEMPT = "unauthorized_access_attempt"
    SUSPICIOUS_LOGIN_ACTIVITY = "suspicious_login_activity"
    
    # Admin Events
    ADMIN_USER_MANAGEMENT = "admin_user_management"
    ADMIN_ROLE_ASSIGNMENT = "admin_role_assignment"
    ADMIN_SESSION_MONITORING = "admin_session_monitoring"
    ADMIN_USER_DELETION = "admin_user_deletion"
    
    # System Events
    EMAIL_SENT = "email_sent"
    EMAIL_FAILED = "email_failed"
    DATABASE_ERROR = "database_error"
    SYSTEM_ERROR = "system_error"


class AuditEvent:
    """Audit event model for structured logging"""
    
    def __init__(
        self,
        event_type: AuditEventType,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        timestamp: Optional[datetime] = None
    ):
        self.event_type = event_type
        self.user_id = user_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.session_id = session_id
        self.details = details or {}
        self.success = success
        self.timestamp = timestamp or datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary for storage"""
        return {
            'event_type': self.event_type.value,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'session_id': self.session_id,
            'details': self.details,
            'success': self.success,
            'timestamp': self.timestamp
        }
    
    def __str__(self) -> str:
        """String representation of audit event"""
        user_info = f"user_id={self.user_id}" if self.user_id else "anonymous"
        ip_info = f"ip={self.ip_address}" if self.ip_address else ""
        status = "SUCCESS" if self.success else "FAILED"
        
        return f"[{self.timestamp.isoformat()}] {self.event_type.value.upper()} {status} {user_info} {ip_info}".strip()