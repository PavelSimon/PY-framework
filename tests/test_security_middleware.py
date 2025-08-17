"""
Test security middleware functionality
"""

import pytest
import time
from unittest.mock import Mock, AsyncMock
from src.framework.security import (
    RateLimiter, 
    SecurityConfig, 
    SecurityMiddleware, 
    create_security_config,
    security_reporter
)


class TestRateLimiter:
    def test_rate_limiter_initialization(self):
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        assert limiter.max_requests == 10
        assert limiter.window_seconds == 60
        assert len(limiter.requests) == 0
    
    def test_rate_limiter_allows_requests_under_limit(self):
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        
        # First few requests should be allowed
        for i in range(5):
            allowed, info = limiter.is_allowed("192.168.1.1")
            assert allowed == True
            assert info['remaining'] == 4 - i
            assert info['limit'] == 5
    
    def test_rate_limiter_blocks_requests_over_limit(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        
        # Fill up the limit
        for i in range(3):
            allowed, info = limiter.is_allowed("192.168.1.1")
            assert allowed == True
        
        # Next request should be blocked
        allowed, info = limiter.is_allowed("192.168.1.1")
        assert allowed == False
        assert info['remaining'] == 0
        assert info['retry_after'] > 0
    
    def test_rate_limiter_different_ips_separate_limits(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        
        # Fill limit for first IP
        for i in range(2):
            allowed, info = limiter.is_allowed("192.168.1.1")
            assert allowed == True
        
        # First IP should be blocked
        allowed, info = limiter.is_allowed("192.168.1.1")
        assert allowed == False
        
        # Second IP should still be allowed
        allowed, info = limiter.is_allowed("192.168.1.2")
        assert allowed == True


class TestSecurityConfig:
    def test_default_security_config(self):
        config = SecurityConfig()
        assert config.enable_rate_limiting == True
        assert config.rate_limit_requests == 100
        assert config.rate_limit_window == 3600
        assert config.enable_strict_csp == True
        assert config.enable_hsts == True
        assert config.enable_security_headers == True
    
    def test_custom_security_config(self):
        config = SecurityConfig(
            enable_rate_limiting=False,
            rate_limit_requests=50,
            enable_strict_csp=False
        )
        assert config.enable_rate_limiting == False
        assert config.rate_limit_requests == 50
        assert config.enable_strict_csp == False
    
    def test_create_production_config(self):
        config = create_security_config(is_production=True)
        assert config.enable_rate_limiting == True
        assert config.enable_strict_csp == True
        assert config.enable_hsts == True
        assert config.rate_limit_requests == 100
    
    def test_create_development_config(self):
        config = create_security_config(is_production=False)
        assert config.enable_rate_limiting == False
        assert config.enable_strict_csp == False
        assert config.enable_hsts == False
        assert config.rate_limit_requests == 1000


class TestSecurityMiddleware:
    def test_security_middleware_initialization(self):
        config = SecurityConfig(enable_rate_limiting=True)
        middleware = SecurityMiddleware(config)
        assert middleware.config == config
        assert middleware.rate_limiter is not None
    
    def test_security_middleware_no_rate_limiting(self):
        config = SecurityConfig(enable_rate_limiting=False)
        middleware = SecurityMiddleware(config)
        assert middleware.rate_limiter is None
    
    def test_get_client_ip_forwarded_for(self):
        middleware = SecurityMiddleware()
        
        # Mock request with X-Forwarded-For header
        request = Mock()
        request.headers = {'X-Forwarded-For': '192.168.1.1, 10.0.0.1'}
        request.client = None
        
        ip = middleware.get_client_ip(request)
        assert ip == '192.168.1.1'
    
    def test_get_client_ip_real_ip(self):
        middleware = SecurityMiddleware()
        
        # Mock request with X-Real-IP header
        request = Mock()
        request.headers = {'X-Real-IP': '192.168.1.2'}
        request.client = None
        
        ip = middleware.get_client_ip(request)
        assert ip == '192.168.1.2'
    
    def test_get_client_ip_direct(self):
        middleware = SecurityMiddleware()
        
        # Mock request with direct client IP
        request = Mock()
        request.headers = {}
        request.client = Mock()
        request.client.host = '192.168.1.3'
        
        ip = middleware.get_client_ip(request)
        assert ip == '192.168.1.3'
    
    def test_get_client_ip_unknown(self):
        middleware = SecurityMiddleware()
        
        # Mock request with no IP information
        request = Mock()
        request.headers = {}
        request.client = None
        
        ip = middleware.get_client_ip(request)
        assert ip == 'unknown'
    
    def test_get_security_headers_basic(self):
        config = SecurityConfig(enable_security_headers=True)
        middleware = SecurityMiddleware(config)
        request = Mock()
        
        headers = middleware.get_security_headers(request)
        
        # Check for essential security headers
        assert headers['X-Content-Type-Options'] == 'nosniff'
        assert headers['X-Frame-Options'] == 'DENY'
        assert headers['X-XSS-Protection'] == '1; mode=block'
        assert headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
        assert 'Content-Security-Policy' in headers
        assert 'Permissions-Policy' in headers
    
    def test_get_security_headers_with_hsts(self):
        config = SecurityConfig(enable_hsts=True, hsts_max_age=31536000)
        middleware = SecurityMiddleware(config)
        request = Mock()
        
        headers = middleware.get_security_headers(request)
        
        assert 'Strict-Transport-Security' in headers
        assert 'max-age=31536000' in headers['Strict-Transport-Security']
        assert 'includeSubDomains' in headers['Strict-Transport-Security']
    
    def test_get_security_headers_strict_csp(self):
        config = SecurityConfig(enable_strict_csp=True)
        middleware = SecurityMiddleware(config)
        request = Mock()
        
        headers = middleware.get_security_headers(request)
        
        csp = headers['Content-Security-Policy']
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "upgrade-insecure-requests" in csp
    
    def test_get_security_headers_relaxed_csp(self):
        config = SecurityConfig(enable_strict_csp=False)
        middleware = SecurityMiddleware(config)
        request = Mock()
        
        headers = middleware.get_security_headers(request)
        
        csp = headers['Content-Security-Policy']
        assert "default-src 'self'" in csp
        assert "'unsafe-eval'" in csp  # Relaxed for development
        assert "frame-ancestors 'none'" not in csp
    
    def test_get_security_headers_disabled(self):
        config = SecurityConfig(enable_security_headers=False)
        middleware = SecurityMiddleware(config)
        request = Mock()
        
        headers = middleware.get_security_headers(request)
        
        assert len(headers) == 0
    
    @pytest.mark.asyncio
    async def test_middleware_call_no_rate_limiting(self):
        config = SecurityConfig(enable_rate_limiting=False)
        middleware = SecurityMiddleware(config)
        
        # Mock request and response
        request = Mock()
        request.headers = {}
        request.client = Mock()
        request.client.host = '192.168.1.1'
        
        response = Mock()
        response.headers = {}
        
        call_next = AsyncMock(return_value=response)
        
        # Call middleware
        result = await middleware(request, call_next)
        
        # Should call next middleware
        call_next.assert_called_once_with(request)
        
        # Should add security headers
        assert 'X-Content-Type-Options' in response.headers
        assert result == response
    
    @pytest.mark.asyncio
    async def test_middleware_call_with_rate_limiting_allowed(self):
        config = SecurityConfig(enable_rate_limiting=True, rate_limit_requests=10)
        middleware = SecurityMiddleware(config)
        
        # Mock request and response
        request = Mock()
        request.headers = {}
        request.client = Mock()
        request.client.host = '192.168.1.1'
        
        response = Mock()
        response.headers = {}
        
        call_next = AsyncMock(return_value=response)
        
        # Call middleware
        result = await middleware(request, call_next)
        
        # Should call next middleware
        call_next.assert_called_once_with(request)
        
        # Should add rate limit headers
        assert 'X-RateLimit-Limit' in response.headers
        assert 'X-RateLimit-Remaining' in response.headers
        assert result == response
    
    @pytest.mark.asyncio
    async def test_middleware_call_with_rate_limiting_blocked(self):
        config = SecurityConfig(enable_rate_limiting=True, rate_limit_requests=1)
        middleware = SecurityMiddleware(config)
        
        # Mock request
        request = Mock()
        request.headers = {}
        request.client = Mock()
        request.client.host = '192.168.1.1'
        
        call_next = AsyncMock()
        
        # Fill rate limit
        await middleware(request, call_next)
        
        # Second request should be blocked
        result = await middleware(request, call_next)
        
        # Should return 429 response
        assert result.status_code == 429
        assert 'X-RateLimit-Limit' in result.headers
        assert 'Retry-After' in result.headers
        
        # Should not call next middleware for blocked request
        assert call_next.call_count == 1


class TestSecurityReporter:
    def test_security_reporter_log_event(self):
        # Clear any existing events
        security_reporter.events.clear()
        
        # Log a security event
        security_reporter.log_security_event(
            'rate_limit_exceeded',
            '192.168.1.1',
            {'requests': 101, 'limit': 100}
        )
        
        # Check event was logged
        events = security_reporter.get_recent_events()
        assert len(events) == 1
        
        event = events[0]
        assert event['type'] == 'rate_limit_exceeded'
        assert event['client_ip'] == '192.168.1.1'
        assert event['details']['requests'] == 101
        assert 'timestamp' in event
    
    def test_security_reporter_max_events(self):
        # Clear any existing events
        security_reporter.events.clear()
        
        # Log more than max events (1000)
        for i in range(1005):
            security_reporter.log_security_event(
                'test_event',
                f'192.168.1.{i % 255}',
                {'sequence': i}
            )
        
        # Should only keep last 1000 events
        events = security_reporter.get_recent_events()
        assert len(events) <= 1000
        
        # Should keep the most recent events
        last_event = events[-1]
        assert last_event['details']['sequence'] == 1004
    
    def test_security_reporter_get_recent_events_limited(self):
        # Clear any existing events
        security_reporter.events.clear()
        
        # Log 50 events
        for i in range(50):
            security_reporter.log_security_event(
                'test_event',
                '192.168.1.1',
                {'sequence': i}
            )
        
        # Get limited number of events
        events = security_reporter.get_recent_events(limit=10)
        assert len(events) == 10
        
        # Should get the most recent events
        assert events[-1]['details']['sequence'] == 49
        assert events[0]['details']['sequence'] == 40


if __name__ == "__main__":
    pytest.main([__file__])