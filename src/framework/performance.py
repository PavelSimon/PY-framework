"""
Performance optimization utilities for PY-Framework
Provides caching, connection pooling, and query optimization features
"""

import time
import asyncio
import threading
from typing import Any, Dict, Optional, Callable, List, Tuple
from datetime import datetime, timedelta
from functools import wraps, lru_cache
from collections import defaultdict
import weakref
import duckdb
import os


class PerformanceCache:
    """Thread-safe in-memory cache with TTL support"""
    
    def __init__(self, default_ttl: int = 300):  # 5 minutes default TTL
        self.cache: Dict[str, Tuple[Any, datetime]] = {}
        self.default_ttl = default_ttl
        self._lock = threading.RLock()
        self._stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'deletes': 0,
            'evictions': 0
        }
        
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired"""
        with self._lock:
            if key in self.cache:
                value, expires_at = self.cache[key]
                if datetime.now() < expires_at:
                    self._stats['hits'] += 1
                    return value
                else:
                    # Expired, remove it
                    del self.cache[key]
                    self._stats['evictions'] += 1
            
            self._stats['misses'] += 1
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache with TTL"""
        with self._lock:
            ttl = ttl or self.default_ttl
            expires_at = datetime.now() + timedelta(seconds=ttl)
            self.cache[key] = (value, expires_at)
            self._stats['sets'] += 1
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        with self._lock:
            if key in self.cache:
                del self.cache[key]
                self._stats['deletes'] += 1
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self.cache.clear()
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count removed"""
        with self._lock:
            now = datetime.now()
            expired_keys = [
                key for key, (_, expires_at) in self.cache.items()
                if now >= expires_at
            ]
            
            for key in expired_keys:
                del self.cache[key]
                self._stats['evictions'] += 1
            
            return len(expired_keys)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total_requests = self._stats['hits'] + self._stats['misses']
            hit_rate = (self._stats['hits'] / total_requests * 100) if total_requests > 0 else 0
            
            return {
                **self._stats,
                'size': len(self.cache),
                'hit_rate_percent': round(hit_rate, 2),
                'total_requests': total_requests
            }


class ConnectionPool:
    """Database connection pool for DuckDB"""
    
    def __init__(self, db_path: str, max_connections: int = 10):
        self.db_path = db_path
        self.max_connections = max_connections
        self.connections: List[duckdb.DuckDBPyConnection] = []
        self.in_use: set = set()
        self._lock = threading.Lock()
        self._created_count = 0
        
    def get_connection(self) -> duckdb.DuckDBPyConnection:
        """Get a connection from the pool"""
        with self._lock:
            # Try to reuse an existing connection
            for conn in self.connections:
                if id(conn) not in self.in_use:
                    self.in_use.add(id(conn))
                    return conn
            
            # Create new connection if under limit
            if self._created_count < self.max_connections:
                conn = duckdb.connect(self.db_path)
                self.connections.append(conn)
                self.in_use.add(id(conn))
                self._created_count += 1
                return conn
            
            # If we're at the limit, wait and try again
            # In a real implementation, you might want to implement a proper queue
            raise Exception("Connection pool exhausted")
    
    def return_connection(self, conn: duckdb.DuckDBPyConnection) -> None:
        """Return a connection to the pool"""
        with self._lock:
            self.in_use.discard(id(conn))
    
    def close_all(self) -> None:
        """Close all connections in the pool"""
        with self._lock:
            for conn in self.connections:
                try:
                    conn.close()
                except:
                    pass
            self.connections.clear()
            self.in_use.clear()
            self._created_count = 0


class QueryOptimizer:
    """Query performance tracking and optimization suggestions"""
    
    def __init__(self):
        self.query_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'count': 0,
            'total_time': 0.0,
            'avg_time': 0.0,
            'max_time': 0.0,
            'min_time': float('inf')
        })
        self._lock = threading.Lock()
    
    def track_query(self, query: str, execution_time: float) -> None:
        """Track query execution time"""
        # Normalize query for tracking (remove dynamic values)
        normalized_query = self._normalize_query(query)
        
        with self._lock:
            stats = self.query_stats[normalized_query]
            stats['count'] += 1
            stats['total_time'] += execution_time
            stats['avg_time'] = stats['total_time'] / stats['count']
            stats['max_time'] = max(stats['max_time'], execution_time)
            stats['min_time'] = min(stats['min_time'], execution_time)
    
    def _normalize_query(self, query: str) -> str:
        """Normalize query by removing dynamic values"""
        # Simple normalization - in production you'd want more sophisticated parsing
        import re
        
        # Remove string literals
        query = re.sub(r"'[^']*'", "'?'", query)
        # Remove numbers
        query = re.sub(r'\b\d+\b', '?', query)
        # Normalize whitespace
        query = ' '.join(query.split())
        
        return query.lower()
    
    def get_slow_queries(self, threshold_ms: float = 100.0) -> List[Tuple[str, Dict[str, Any]]]:
        """Get queries slower than threshold"""
        with self._lock:
            slow_queries = [
                (query, stats) for query, stats in self.query_stats.items()
                if stats['avg_time'] * 1000 > threshold_ms
            ]
            
            return sorted(slow_queries, key=lambda x: x[1]['avg_time'], reverse=True)
    
    def get_frequent_queries(self, min_count: int = 10) -> List[Tuple[str, Dict[str, Any]]]:
        """Get most frequently executed queries"""
        with self._lock:
            frequent_queries = [
                (query, stats) for query, stats in self.query_stats.items()
                if stats['count'] >= min_count
            ]
            
            return sorted(frequent_queries, key=lambda x: x[1]['count'], reverse=True)
    
    def get_stats_summary(self) -> Dict[str, Any]:
        """Get overall query statistics"""
        with self._lock:
            total_queries = sum(stats['count'] for stats in self.query_stats.values())
            total_time = sum(stats['total_time'] for stats in self.query_stats.values())
            
            if total_queries == 0:
                return {'total_queries': 0, 'total_time': 0, 'avg_time': 0}
            
            return {
                'total_queries': total_queries,
                'total_time_seconds': round(total_time, 3),
                'avg_time_ms': round((total_time / total_queries) * 1000, 3),
                'unique_query_patterns': len(self.query_stats)
            }


def cached_query(cache: PerformanceCache, ttl: int = 300):
    """Decorator for caching database query results"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            cache_key = f"{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
            
            # Try to get from cache first
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            return result
        
        return wrapper
    return decorator


def timed_query(optimizer: QueryOptimizer):
    """Decorator for tracking query execution time"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                execution_time = time.time() - start_time
                # Try to extract query from args/kwargs
                query = "unknown"
                if len(args) > 1 and isinstance(args[1], str):
                    query = args[1]
                elif 'query' in kwargs:
                    query = kwargs['query']
                
                optimizer.track_query(query, execution_time)
        
        return wrapper
    return decorator


class SessionCache:
    """Specialized cache for user sessions"""
    
    def __init__(self, max_sessions: int = 1000):
        self.max_sessions = max_sessions
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.access_times: Dict[str, datetime] = {}
        self._lock = threading.RLock()
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        with self._lock:
            if session_id in self.sessions:
                self.access_times[session_id] = datetime.now()
                return self.sessions[session_id].copy()
            return None
    
    def set_session(self, session_id: str, session_data: Dict[str, Any]) -> None:
        """Set session data with LRU eviction"""
        with self._lock:
            # Evict oldest sessions if at capacity
            if len(self.sessions) >= self.max_sessions and session_id not in self.sessions:
                oldest_session = min(self.access_times.items(), key=lambda x: x[1])[0]
                self.remove_session(oldest_session)
            
            self.sessions[session_id] = session_data.copy()
            self.access_times[session_id] = datetime.now()
    
    def remove_session(self, session_id: str) -> bool:
        """Remove session from cache"""
        with self._lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                del self.access_times[session_id]
                return True
            return False
    
    def cleanup_expired(self, expire_hours: int = 24) -> int:
        """Remove expired sessions"""
        with self._lock:
            cutoff_time = datetime.now() - timedelta(hours=expire_hours)
            expired_sessions = [
                session_id for session_id, access_time in self.access_times.items()
                if access_time < cutoff_time
            ]
            
            for session_id in expired_sessions:
                self.remove_session(session_id)
            
            return len(expired_sessions)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get session cache statistics"""
        with self._lock:
            return {
                'total_sessions': len(self.sessions),
                'max_sessions': self.max_sessions,
                'utilization_percent': round(len(self.sessions) / self.max_sessions * 100, 2)
            }


# Global performance instances - initialized in performance_config.py
global_cache: Optional[PerformanceCache] = None
global_query_optimizer: Optional[QueryOptimizer] = None
global_session_cache: Optional[SessionCache] = None
global_connection_pool: Optional[ConnectionPool] = None


def get_performance_cache() -> PerformanceCache:
    """Get or create global performance cache"""
    global global_cache
    if global_cache is None:
        global_cache = PerformanceCache(default_ttl=300)  # 5 minutes
    return global_cache


def get_query_optimizer() -> QueryOptimizer:
    """Get or create global query optimizer"""
    global global_query_optimizer
    if global_query_optimizer is None:
        global_query_optimizer = QueryOptimizer()
    return global_query_optimizer


def get_session_cache() -> SessionCache:
    """Get or create global session cache"""
    global global_session_cache
    if global_session_cache is None:
        global_session_cache = SessionCache(max_sessions=1000)
    return global_session_cache


def get_connection_pool(db_path: str = "app.db") -> ConnectionPool:
    """Get or create global connection pool"""
    global global_connection_pool
    if global_connection_pool is None:
        global_connection_pool = ConnectionPool(db_path, max_connections=10)
    return global_connection_pool


@lru_cache(maxsize=100)
def get_user_permissions(user_id: int, role_id: int) -> Dict[str, bool]:
    """Cached user permissions lookup"""
    # This would be expanded with actual permission logic
    if role_id == 0:  # Admin
        return {
            'can_manage_users': True,
            'can_view_audit': True,
            'can_manage_settings': True,
            'can_export_data': True
        }
    else:  # Regular user
        return {
            'can_manage_users': False,
            'can_view_audit': False,
            'can_manage_settings': False,
            'can_export_data': False
        }


def clear_user_cache(user_id: int) -> None:
    """Clear cached data for a specific user"""
    cache = get_performance_cache()
    
    # Clear user-specific cache entries
    keys_to_clear = []
    for key in cache.cache.keys():
        if f"user_{user_id}" in key or f":{user_id}:" in key:
            keys_to_clear.append(key)
    
    for key in keys_to_clear:
        cache.delete(key)
    
    # Clear LRU cache for user permissions
    get_user_permissions.cache_clear()


def get_performance_stats() -> Dict[str, Any]:
    """Get comprehensive performance statistics"""
    cache = get_performance_cache()
    optimizer = get_query_optimizer()
    session_cache = get_session_cache()
    
    return {
        'cache': cache.get_stats(),
        'queries': optimizer.get_stats_summary(),
        'sessions': session_cache.get_stats(),
        'slow_queries': [
            {
                'query': query[:100] + '...' if len(query) > 100 else query,
                'avg_time_ms': round(stats['avg_time'] * 1000, 2),
                'count': stats['count']
            }
            for query, stats in optimizer.get_slow_queries(50.0)[:5]  # Top 5 slow queries
        ]
    }