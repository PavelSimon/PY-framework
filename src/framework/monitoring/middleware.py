"""
Monitoring Middleware for PY-Framework
Integrates metrics collection and health monitoring into FastHTML applications
"""

import time
import threading
from typing import Callable, Any, Dict
import asyncio
from fasthtml.common import Request, Response
from .metrics_collector import get_metrics_collector
from .health_checker import get_health_checker
from .alerting import get_alert_manager


class MonitoringMiddleware:
    """Middleware for automatic monitoring integration"""
    
    def __init__(self, app: Any):
        self.app = app
        self.metrics = get_metrics_collector()
        self.health = get_health_checker()
        self.alerts = get_alert_manager()
        
        # Request tracking
        self._active_requests = 0
        self._request_lock = threading.Lock()
    
    def __call__(self, request: Request) -> Response:
        """Process request with monitoring"""
        start_time = time.time()
        
        # Track active request count
        with self._request_lock:
            self._active_requests += 1
            self.metrics.set_gauge('http_requests_active', self._active_requests)
        
        try:
            # Process the request
            # Support async apps as well
            if asyncio.iscoroutinefunction(self.app):
                response = asyncio.get_event_loop().run_until_complete(self.app(request))
            else:
                response = self.app(request)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Extract request info
            method = getattr(request, 'method', 'GET')
            path = getattr(request, 'url', {}).get('path', '/')
            status_code = getattr(response, 'status_code', 200)
            
            # Track metrics
            self.metrics.track_request(method, path, status_code, duration)
            
            # Update connection metrics if this is a database-related request
            if 'api' in path or 'admin' in path:
                try:
                    from ..database import Database
                    # This would require database connection tracking
                    # self.metrics.update_active_connections(db.get_connection_count())
                except:
                    pass
            
            return response
            
        except Exception as e:
            # Track error
            duration = time.time() - start_time
            method = getattr(request, 'method', 'GET')
            path = getattr(request, 'url', {}).get('path', '/')
            
            self.metrics.track_request(method, path, 500, duration)
            
            # Re-raise the exception
            raise
            
        finally:
            # Decrease active request count
            with self._request_lock:
                self._active_requests -= 1
                self.metrics.set_gauge('http_requests_active', self._active_requests)


def add_monitoring_middleware(app: Any) -> Any:
    """Add monitoring middleware to FastHTML application"""
    
    # Initialize monitoring components
    metrics = get_metrics_collector()
    health = get_health_checker()
    alerts = get_alert_manager()
    
    print("✅ Monitoring middleware initialized")
    print(f"  - Metrics collector: {len(metrics._metrics)} metrics registered")
    print(f"  - Health checker: {len(health._checks)} checks registered") 
    print(f"  - Alert manager: {len(alerts._rules)} alert rules registered")
    
    # Wrap the app with monitoring middleware
    return MonitoringMiddleware(app)


class AsyncMonitoringMiddleware:
    """Async-aware monitoring middleware compatible with FastHTML/Starlette style."""

    def __init__(self, app: Any):
        self.app = app
        self.metrics = get_metrics_collector()
        self.health = get_health_checker()
        self.alerts = get_alert_manager()
        self._active_requests = 0
        self._request_lock = threading.Lock()

    async def __call__(self, request, call_next):
        start_time = time.time()
        with self._request_lock:
            self._active_requests += 1
            self.metrics.set_gauge('http_requests_active', self._active_requests)

        try:
            response = await call_next(request)
            duration = time.time() - start_time
            method = getattr(request, 'method', 'GET')
            path = getattr(getattr(request, 'url', None), 'path', '/') if hasattr(request, 'url') else '/'
            status_code = getattr(response, 'status_code', 200)
            self.metrics.track_request(method, path, status_code, duration)
            return response
        except Exception:
            duration = time.time() - start_time
            method = getattr(request, 'method', 'GET')
            path = getattr(getattr(request, 'url', None), 'path', '/') if hasattr(request, 'url') else '/'
            self.metrics.track_request(method, path, 500, duration)
            raise
        finally:
            with self._request_lock:
                self._active_requests -= 1
                self.metrics.set_gauge('http_requests_active', self._active_requests)


def add_async_monitoring_middleware(app: Any) -> None:
    """Attach async monitoring middleware via app.middleware('http')."""
    middleware = AsyncMonitoringMiddleware(app)

    @app.middleware("http")
    async def _monitoring(request, call_next):
        return await middleware(request, call_next)


def monitor_database_operation(operation_name: str):
    """Decorator for monitoring database operations"""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            start_time = time.time()
            metrics = get_metrics_collector()
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                metrics.track_database_query(operation_name, duration, success=True)
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                metrics.track_database_query(operation_name, duration, success=False)
                raise
        
        return wrapper
    return decorator


def monitor_cache_operation(operation_name: str):
    """Decorator for monitoring cache operations"""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            metrics = get_metrics_collector()
            
            try:
                result = func(*args, **kwargs)
                # Determine if this was a hit or miss based on result
                hit = result is not None
                metrics.track_cache_operation(operation_name, hit)
                return result
                
            except Exception as e:
                metrics.track_cache_operation(operation_name, hit=False)
                raise
        
        return wrapper
    return decorator


def monitor_user_action(action_type: str):
    """Decorator for monitoring user actions"""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            metrics = get_metrics_collector()
            alerts = get_alert_manager()
            
            try:
                result = func(*args, **kwargs)
                
                # Track specific user actions
                if action_type == "login":
                    # Determine success from result or exception
                    success = result is not None and not isinstance(result, Exception)
                    metrics.track_user_login(success)
                    
                elif action_type == "audit_event":
                    # Extract event type from kwargs or result
                    event_type = kwargs.get('event_type', 'unknown')
                    metrics.track_audit_event(event_type)
                
                return result
                
            except Exception as e:
                if action_type == "login":
                    metrics.track_user_login(success=False)
                raise
        
        return wrapper
    return decorator
