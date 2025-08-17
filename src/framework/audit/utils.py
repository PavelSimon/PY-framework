from typing import Optional, Dict, Any
from fasthtml.common import Request
from .models import AuditEventType
from .audit_manager import get_audit_service


def extract_request_info(request: Request) -> Dict[str, Optional[str]]:
    """Extract audit-relevant information from FastHTML request"""
    return {
        'ip_address': get_client_ip(request),
        'user_agent': request.headers.get('user-agent'),
        'method': request.method,
        'path': str(request.url.path) if hasattr(request.url, 'path') else None,
        'query_params': str(request.url.query) if hasattr(request.url, 'query') else None
    }


def get_client_ip(request: Request) -> Optional[str]:
    """Get client IP address from request, considering proxies"""
    # Check for forwarded headers first (proxy/load balancer scenarios)
    forwarded_for = request.headers.get('x-forwarded-for')
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(',')[0].strip()
    
    forwarded = request.headers.get('x-forwarded')
    if forwarded:
        return forwarded.split(',')[0].strip()
    
    real_ip = request.headers.get('x-real-ip')
    if real_ip:
        return real_ip
    
    # Fall back to remote address
    if hasattr(request, 'client') and request.client:
        return getattr(request.client, 'host', None)
    
    return None


def audit_decorator(event_type: AuditEventType, success: bool = True):
    """Decorator for automatic audit logging of function calls"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                
                # Try to extract user and request info from arguments
                user_id = kwargs.get('user_id')
                request = kwargs.get('request')
                
                audit_details = {
                    'function': func.__name__,
                    'args_count': len(args),
                    'kwargs_keys': list(kwargs.keys())
                }
                
                request_info = {}
                if request:
                    request_info = extract_request_info(request)
                
                # Get audit service (requires database to be available)
                try:
                    audit_service = get_audit_service()
                    audit_service.log_authentication_event(
                        event_type=event_type,
                        user_id=user_id,
                        ip_address=request_info.get('ip_address'),
                        user_agent=request_info.get('user_agent'),
                        success=success,
                        details=audit_details
                    )
                except Exception as e:
                    # Don't let audit failures break the function
                    print(f"Audit logging failed in decorator: {e}")
                
                return result
                
            except Exception as e:
                # Log the failure
                try:
                    audit_service = get_audit_service()
                    audit_service.log_authentication_event(
                        event_type=event_type,
                        user_id=kwargs.get('user_id'),
                        success=False,
                        details={'error': str(e), 'function': func.__name__}
                    )
                except Exception:
                    # Ignore audit failures
                    pass
                
                # Re-raise the original exception
                raise e
        
        return wrapper
    return decorator


def log_security_event(
    event_type: AuditEventType,
    request: Optional[Request] = None,
    user_id: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None
):
    """Utility function to log security events with request context"""
    try:
        audit_service = get_audit_service()
        
        request_info = {}
        if request:
            request_info = extract_request_info(request)
        
        audit_service.log_security_event(
            event_type=event_type,
            ip_address=request_info.get('ip_address'),
            user_agent=request_info.get('user_agent'),
            user_id=user_id,
            details={
                **(details or {}),
                **{k: v for k, v in request_info.items() if k not in ['ip_address', 'user_agent']}
            }
        )
    except Exception as e:
        print(f"Security event logging failed: {e}")


def log_admin_action(
    event_type: AuditEventType,
    admin_user_id: int,
    request: Optional[Request] = None,
    target_user_id: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None
):
    """Utility function to log admin actions with full context"""
    try:
        audit_service = get_audit_service()
        
        request_info = {}
        if request:
            request_info = extract_request_info(request)
        
        audit_service.log_admin_event(
            event_type=event_type,
            admin_user_id=admin_user_id,
            target_user_id=target_user_id,
            ip_address=request_info.get('ip_address'),
            user_agent=request_info.get('user_agent'),
            session_id=session_id,
            details={
                **(details or {}),
                **{k: v for k, v in request_info.items() if k not in ['ip_address', 'user_agent']}
            }
        )
    except Exception as e:
        print(f"Admin action logging failed: {e}")


def log_oauth_event(
    event_type: AuditEventType,
    provider: str,
    request: Optional[Request] = None,
    user_id: Optional[int] = None,
    success: bool = True,
    details: Optional[Dict[str, Any]] = None
):
    """Utility function to log OAuth events"""
    try:
        audit_service = get_audit_service()
        
        request_info = {}
        if request:
            request_info = extract_request_info(request)
        
        oauth_details = {
            'provider': provider,
            **(details or {})
        }
        
        audit_service.log_authentication_event(
            event_type=event_type,
            user_id=user_id,
            ip_address=request_info.get('ip_address'),
            user_agent=request_info.get('user_agent'),
            success=success,
            details=oauth_details
        )
    except Exception as e:
        print(f"OAuth event logging failed: {e}")


def log_2fa_event(
    event_type: AuditEventType,
    user_id: int,
    request: Optional[Request] = None,
    success: bool = True,
    details: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None
):
    """Utility function to log 2FA events"""
    try:
        audit_service = get_audit_service()
        
        request_info = {}
        if request:
            request_info = extract_request_info(request)
        
        audit_service.log_authentication_event(
            event_type=event_type,
            user_id=user_id,
            ip_address=request_info.get('ip_address'),
            user_agent=request_info.get('user_agent'),
            session_id=session_id,
            success=success,
            details=details
        )
    except Exception as e:
        print(f"2FA event logging failed: {e}")