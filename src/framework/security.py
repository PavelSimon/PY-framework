"""
Enhanced Security Middleware and Headers for PY-Framework
Provides comprehensive security features, rate limiting, and protection mechanisms
"""

import time
import hashlib
from typing import Dict, Any, Tuple, Optional
from datetime import datetime, timedelta
from collections import deque
from fasthtml.common import *
from .utils.rate_limit import RequestRateLimiter


 


class SecurityConfig:
    """Security configuration settings"""
    
    def __init__(self, 
                 enable_rate_limiting: bool = True,
                 rate_limit_requests: int = 100,
                 rate_limit_window: int = 3600,
                 enable_strict_csp: bool = True,
                 enable_hsts: bool = True,
                 hsts_max_age: int = 31536000,  # 1 year
                 enable_security_headers: bool = True):
        self.enable_rate_limiting = enable_rate_limiting
        self.rate_limit_requests = rate_limit_requests
        self.rate_limit_window = rate_limit_window
        self.enable_strict_csp = enable_strict_csp
        self.enable_hsts = enable_hsts
        self.hsts_max_age = hsts_max_age
        self.enable_security_headers = enable_security_headers


class SecurityMiddleware:
    """Comprehensive security middleware"""
    
    def __init__(self, config: SecurityConfig = None):
        self.config = config or SecurityConfig()
        self.rate_limiter = RequestRateLimiter(
            max_requests=self.config.rate_limit_requests,
            window_seconds=self.config.rate_limit_window
        ) if self.config.enable_rate_limiting else None
        
    def get_client_ip(self, request) -> str:
        """Extract client IP from request, considering proxies"""
        # Check common proxy headers
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip.strip()
        
        # Fallback to direct client IP
        if hasattr(request, 'client') and request.client:
            return request.client.host
        
        return 'unknown'
    
    def get_security_headers(self, request) -> Dict[str, str]:
        """Generate comprehensive security headers"""
        headers = {}
        
        if not self.config.enable_security_headers:
            return headers
        
        # Basic security headers
        headers.update({
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # Prevent clickjacking
            "X-Frame-Options": "DENY",
            
            # XSS protection (legacy browsers)
            "X-XSS-Protection": "1; mode=block",
            
            # Control referrer information
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Prevent caching of sensitive pages
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
            
            # Security policy reporting
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
        })
        
        # HSTS (HTTP Strict Transport Security)
        if self.config.enable_hsts:
            headers["Strict-Transport-Security"] = f"max-age={self.config.hsts_max_age}; includeSubDomains; preload"
        
        # Content Security Policy
        if self.config.enable_strict_csp:
            # Generate per-request nonce for inline scripts/styles
            import secrets
            nonce = secrets.token_urlsafe(16)
            # Expose nonce for templates/AJAX if needed
            headers["X-CSP-Nonce"] = nonce
            # Strict CSP for production with nonces
            csp_policy = (
                "default-src 'self'; "
                f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
                f"style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data: https:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "upgrade-insecure-requests"
            )
        else:
            # Relaxed CSP for development
            csp_policy = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'"
            )
        
        headers["Content-Security-Policy"] = csp_policy
        
        # Permissions Policy (formerly Feature Policy)
        headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "speaker=(), "
            "vibrate=(), "
            "fullscreen=(self), "
            "sync-xhr=()"
        )
        
        return headers
    
    async def __call__(self, request, call_next):
        """Security middleware handler"""
        client_ip = self.get_client_ip(request)
        
        # Rate limiting check
        if self.rate_limiter:
            allowed, rate_info = self.rate_limiter.is_allowed(client_ip)
            
            if not allowed:
                # Rate limit exceeded
                headers = {
                    "X-RateLimit-Limit": str(rate_info['limit']),
                    "X-RateLimit-Remaining": str(rate_info['remaining']),
                    "X-RateLimit-Reset": str(rate_info['reset']),
                    "Retry-After": str(rate_info['retry_after'])
                }
                
                return Response(
                    content="Rate limit exceeded. Please try again later.",
                    status_code=429,
                    headers=headers
                )
        
        # Process the request
        response = await call_next(request)
        
        # Add security headers
        security_headers = self.get_security_headers(request)
        for header, value in security_headers.items():
            response.headers[header] = value
        
        # Add rate limiting headers if enabled
        if self.rate_limiter:
            allowed, rate_info = self.rate_limiter.is_allowed(client_ip)
            response.headers["X-RateLimit-Limit"] = str(rate_info['limit'])
            response.headers["X-RateLimit-Remaining"] = str(rate_info['remaining'])
            response.headers["X-RateLimit-Reset"] = str(rate_info['reset'])
        
        return response


def add_security_middleware(app, config: SecurityConfig = None):
    """Add comprehensive security middleware to FastHTML app"""
    security_middleware = SecurityMiddleware(config)
    
    @app.middleware("http")
    async def security_handler(request, call_next):
        return await security_middleware(request, call_next)


def create_security_config(is_production: bool = False) -> SecurityConfig:
    """Create security configuration based on environment"""
    if is_production:
        return SecurityConfig(
            enable_rate_limiting=True,
            rate_limit_requests=100,  # 100 requests per hour
            rate_limit_window=3600,
            enable_strict_csp=True,
            enable_hsts=True,
            hsts_max_age=31536000,  # 1 year
            enable_security_headers=True
        )
    else:
        return SecurityConfig(
            enable_rate_limiting=False,  # Disabled for development
            rate_limit_requests=1000,
            rate_limit_window=3600,
            enable_strict_csp=False,  # Relaxed for development
            enable_hsts=False,  # No HSTS in development
            enable_security_headers=True
        )


class SecurityReporter:
    """Security event reporting and logging"""
    
    def __init__(self):
        self.events = deque(maxlen=1000)  # Keep last 1000 events
    
    def log_security_event(self, event_type: str, client_ip: str, details: Dict[str, Any]):
        """Log security-related events"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'client_ip': client_ip,
            'details': details
        }
        
        self.events.append(event)
        
        # In production, you might want to send this to a logging service
        print(f"SECURITY EVENT [{event_type}] from {client_ip}: {details}")
    
    def get_recent_events(self, limit: int = 100) -> list:
        """Get recent security events"""
        return list(self.events)[-limit:]


# Global security reporter instance
security_reporter = SecurityReporter()


def report_security_event(event_type: str, client_ip: str, details: Dict[str, Any]):
    """Report a security event"""
    security_reporter.log_security_event(event_type, client_ip, details)

# Backwards compatibility for tests importing RateLimiter from this module
RateLimiter = RequestRateLimiter
