"""
Performance configuration and initialization for PY-Framework
Integrates performance optimizations with existing configuration
"""

import os
import threading
import atexit
from typing import Optional, Dict, Any
from .config import Settings
from .performance import (
    PerformanceCache,
    QueryOptimizer,
    SessionCache,
    ConnectionPool,
    get_performance_cache,
    get_query_optimizer,
    get_session_cache,
    get_connection_pool
)


class PerformanceConfig:
    """Performance configuration manager"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.cache_enabled = True
        self.query_optimization_enabled = True
        self.session_cache_enabled = True
        self.connection_pool_enabled = True
        
        # Performance settings with defaults
        self.cache_default_ttl = int(os.getenv('CACHE_DEFAULT_TTL', '300'))  # 5 minutes
        self.cache_max_size = int(os.getenv('CACHE_MAX_SIZE', '1000'))
        
        self.session_cache_max_sessions = int(os.getenv('SESSION_CACHE_MAX_SESSIONS', '1000'))
        self.session_cache_cleanup_interval = int(os.getenv('SESSION_CACHE_CLEANUP_INTERVAL', '3600'))  # 1 hour
        
        self.connection_pool_max_connections = int(os.getenv('CONNECTION_POOL_MAX_CONNECTIONS', '10'))
        
        self.query_slow_threshold_ms = float(os.getenv('QUERY_SLOW_THRESHOLD_MS', '100.0'))
        
        # Initialize performance components
        self._init_components()
        
        # Start background tasks
        self._start_background_tasks()
        
        # Register cleanup
        atexit.register(self.cleanup)
    
    def _init_components(self):
        """Initialize performance components"""
        if self.cache_enabled:
            cache = get_performance_cache()
            cache.default_ttl = self.cache_default_ttl
        
        if self.query_optimization_enabled:
            get_query_optimizer()
        
        if self.session_cache_enabled:
            session_cache = get_session_cache()
            session_cache.max_sessions = self.session_cache_max_sessions
        
        if self.connection_pool_enabled:
            get_connection_pool(self.settings.database_url)
    
    def _start_background_tasks(self):
        """Start background cleanup tasks"""
        if self.cache_enabled or self.session_cache_enabled:
            cleanup_thread = threading.Thread(target=self._background_cleanup, daemon=True)
            cleanup_thread.start()
    
    def _background_cleanup(self):
        """Background task for cleaning up expired cache entries"""
        import time
        
        while True:
            try:
                if self.cache_enabled:
                    cache = get_performance_cache()
                    expired_count = cache.cleanup_expired()
                    if expired_count > 0:
                        print(f"Cleaned up {expired_count} expired cache entries")
                
                if self.session_cache_enabled:
                    session_cache = get_session_cache()
                    expired_sessions = session_cache.cleanup_expired(self.settings.session_expire_hours)
                    if expired_sessions > 0:
                        print(f"Cleaned up {expired_sessions} expired session cache entries")
                
                time.sleep(self.session_cache_cleanup_interval)
                
            except Exception as e:
                print(f"Background cleanup error: {e}")
                time.sleep(60)  # Wait a minute before retrying
    
    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        from .performance import get_performance_stats
        return get_performance_stats()
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            from .performance import global_connection_pool
            if global_connection_pool:
                global_connection_pool.close_all()
        except Exception as e:
            print(f"Error during performance cleanup: {e}")
    
    def is_enabled(self, component: str) -> bool:
        """Check if a performance component is enabled"""
        return getattr(self, f"{component}_enabled", False)


# Global performance config instance
_performance_config: Optional[PerformanceConfig] = None


def init_performance(settings: Settings) -> PerformanceConfig:
    """Initialize performance configuration"""
    global _performance_config
    
    if _performance_config is None:
        _performance_config = PerformanceConfig(settings)
        print("Performance optimization initialized:")
        print(f"  - Cache: {'enabled' if _performance_config.cache_enabled else 'disabled'}")
        print(f"  - Query optimization: {'enabled' if _performance_config.query_optimization_enabled else 'disabled'}")
        print(f"  - Session cache: {'enabled' if _performance_config.session_cache_enabled else 'disabled'}")
        print(f"  - Connection pool: {'enabled' if _performance_config.connection_pool_enabled else 'disabled'}")
    
    return _performance_config


def get_performance_config() -> Optional[PerformanceConfig]:
    """Get current performance configuration"""
    return _performance_config


def performance_middleware():
    """FastHTML middleware for performance monitoring"""
    import time
    from fasthtml.common import Request, Response
    
    def middleware(request: Request, call_next):
        start_time = time.time()
        
        # Process request
        response = call_next(request)
        
        # Track timing
        processing_time = time.time() - start_time
        
        # Add performance headers in debug mode
        config = get_performance_config()
        if config and config.settings.debug:
            if hasattr(response, 'headers'):
                response.headers['X-Processing-Time'] = f"{processing_time:.3f}s"
        
        # Track slow requests
        if processing_time > 1.0:  # Requests over 1 second
            print(f"Slow request: {request.url.path} took {processing_time:.3f}s")
        
        return response
    
    return middleware