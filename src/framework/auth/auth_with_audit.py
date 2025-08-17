from typing import Optional
from .auth import AuthenticationService as BaseAuthService
from ..audit import get_audit_service, AuditEventType
from ..database.database import Database


class AuthenticationServiceWithAudit(BaseAuthService):
    """Enhanced authentication service with integrated audit logging"""
    
    def __init__(self, secret_key: str, database: Database):
        super().__init__(secret_key)
        self.database = database
        self._audit_service = None
    
    @property
    def audit_service(self):
        """Lazy initialization of audit service"""
        if self._audit_service is None:
            self._audit_service = get_audit_service(self.database)
        return self._audit_service
    
    def log_authentication_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[int] = None,
        email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        success: bool = True,
        details: Optional[dict] = None
    ):
        """Log authentication event with audit service"""
        try:
            self.audit_service.log_authentication_event(
                event_type=event_type,
                user_id=user_id,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=session_id,
                success=success,
                details=details
            )
        except Exception as e:
            # Don't let audit logging failures break authentication
            print(f"Audit logging failed: {e}")
    
    def register_user_with_audit(
        self,
        email: str,
        password: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> dict:
        """Register user with audit logging"""
        try:
            # Hash password
            password_hash = self.hash_password(password)
            
            # Create user in database
            user_id = self.database.create_user(email, password_hash, first_name, last_name)
            
            # Log successful registration
            self.log_authentication_event(
                event_type=AuditEventType.USER_REGISTRATION,
                user_id=user_id,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True,
                details={'first_name': first_name, 'last_name': last_name}
            )
            
            return {
                'success': True,
                'user_id': user_id,
                'message': 'User registered successfully'
            }
            
        except Exception as e:
            # Log failed registration
            self.log_authentication_event(
                event_type=AuditEventType.USER_REGISTRATION,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                details={'error': str(e)}
            )
            
            return {
                'success': False,
                'error': str(e)
            }
    
    def authenticate_user_with_audit(
        self,
        email: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> dict:
        """Authenticate user with audit logging"""
        user = self.database.get_user_by_email(email)
        
        if not user:
            # Log failed login - user not found
            self.log_authentication_event(
                event_type=AuditEventType.USER_LOGIN_FAILED,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                details={'reason': 'user_not_found'}
            )
            
            return {
                'success': False,
                'error': 'Invalid email or password'
            }
        
        # Check if account is active
        if not user.get('is_active', True):
            self.log_authentication_event(
                event_type=AuditEventType.USER_LOGIN_FAILED,
                user_id=user['id'],
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                details={'reason': 'account_inactive'}
            )
            
            return {
                'success': False,
                'error': 'Account is deactivated'
            }
        
        # Check if account is locked
        if user.get('locked_until') and user['locked_until'] > datetime.now():
            self.log_authentication_event(
                event_type=AuditEventType.USER_LOGIN_FAILED,
                user_id=user['id'],
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                details={'reason': 'account_locked', 'locked_until': user['locked_until'].isoformat()}
            )
            
            return {
                'success': False,
                'error': f'Account is locked until {user["locked_until"]}'
            }
        
        # Verify password
        if not self.verify_password(password, user['password_hash']):
            # Increment failed attempts
            failed_attempts = self.database.increment_failed_login(user['id'])
            
            # Log failed login
            self.log_authentication_event(
                event_type=AuditEventType.USER_LOGIN_FAILED,
                user_id=user['id'],
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                details={
                    'reason': 'invalid_password',
                    'failed_attempts': failed_attempts
                }
            )
            
            # Check if account should be locked
            if failed_attempts >= 5:
                self.log_authentication_event(
                    event_type=AuditEventType.ACCOUNT_LOCKED,
                    user_id=user['id'],
                    email=email,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=True,
                    details={'failed_attempts': failed_attempts}
                )
            
            return {
                'success': False,
                'error': 'Invalid email or password'
            }
        
        # Successful authentication
        self.database.update_user_login(user['id'], reset_failed_attempts=True)
        
        # Log successful login
        self.log_authentication_event(
            event_type=AuditEventType.USER_LOGIN_SUCCESS,
            user_id=user['id'],
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={'login_method': 'password'}
        )
        
        return {
            'success': True,
            'user': user,
            'message': 'Authentication successful'
        }
    
    def verify_email_with_audit(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """Verify user email with audit logging"""
        try:
            self.database.verify_user_email(user_id)
            
            # Get user for logging
            user = self.database.get_user_by_id(user_id)
            
            self.log_authentication_event(
                event_type=AuditEventType.EMAIL_VERIFICATION,
                user_id=user_id,
                email=user['email'] if user else None,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True
            )
            
            return True
            
        except Exception as e:
            self.log_authentication_event(
                event_type=AuditEventType.EMAIL_VERIFICATION,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                details={'error': str(e)}
            )
            return False
    
    def log_password_reset_request(
        self,
        email: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """Log password reset request"""
        user = self.database.get_user_by_email(email)
        
        self.log_authentication_event(
            event_type=AuditEventType.PASSWORD_RESET_REQUEST,
            user_id=user['id'] if user else None,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )
    
    def log_password_reset_complete(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """Log password reset completion"""
        user = self.database.get_user_by_id(user_id)
        
        self.log_authentication_event(
            event_type=AuditEventType.PASSWORD_RESET_COMPLETE,
            user_id=user_id,
            email=user['email'] if user else None,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )
    
    def log_password_change(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """Log password change"""
        user = self.database.get_user_by_id(user_id)
        
        self.log_authentication_event(
            event_type=AuditEventType.PASSWORD_CHANGE,
            user_id=user_id,
            email=user['email'] if user else None,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            success=True
        )
    
    def log_logout(
        self,
        user_id: int,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """Log user logout"""
        user = self.database.get_user_by_id(user_id)
        
        self.log_authentication_event(
            event_type=AuditEventType.USER_LOGOUT,
            user_id=user_id,
            email=user['email'] if user else None,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )