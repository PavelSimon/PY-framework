"""
Performance-optimized database wrapper for PY-Framework
Integrates caching, connection pooling, and query optimization
"""

import time
import threading
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import secrets
from contextlib import contextmanager
from ..performance import (
    cached_query,
    timed_query,
    get_performance_cache,
    get_query_optimizer,
    get_session_cache,
    get_connection_pool,
    clear_user_cache
)
from .database import Database


class OptimizedDatabase(Database):
    """Performance-optimized database wrapper"""
    
    def __init__(self, db_path: str = "app.db", use_connection_pool: bool = True):
        self.use_connection_pool = use_connection_pool
        self.cache = get_performance_cache()
        self.optimizer = get_query_optimizer()
        self.session_cache = get_session_cache()
        
        if use_connection_pool:
            self.pool = get_connection_pool(db_path)
            super().__init__(db_path)
        else:
            super().__init__(db_path)
            self.pool = None
    
    @contextmanager
    def get_connection(self):
        """Get database connection (from pool if enabled)"""
        if self.use_connection_pool and self.pool:
            conn = self.pool.get_connection()
            try:
                yield conn
            finally:
                self.pool.return_connection(conn)
        else:
            yield self.conn
    
    def execute_query(self, query: str, params: Optional[List] = None, fetch_one: bool = False, fetch_all: bool = True):
        """Execute query with performance tracking"""
        start_time = time.time()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(query, params or [])
                
                if fetch_one:
                    result = cursor.fetchone()
                elif fetch_all:
                    result = cursor.fetchall()
                else:
                    result = cursor
                
                return result
        finally:
            execution_time = time.time() - start_time
            self.optimizer.track_query(query, execution_time)
    
    @cached_query(cache=get_performance_cache(), ttl=300)  # 5 minutes cache
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email with caching"""
        cursor = self.execute_query("""
            SELECT id, email, password_hash, first_name, last_name, 
                   role_id, is_active, is_verified, created_at, updated_at, 
                   last_login, failed_login_attempts, locked_until
            FROM users
            WHERE email = ?
        """, [email], fetch_one=True, fetch_all=False)
        
        if cursor:
            return {
                "id": cursor[0], "email": cursor[1], "password_hash": cursor[2],
                "first_name": cursor[3], "last_name": cursor[4], "role_id": cursor[5],
                "is_active": cursor[6], "is_verified": cursor[7], "created_at": cursor[8],
                "updated_at": cursor[9], "last_login": cursor[10],
                "failed_login_attempts": cursor[11], "locked_until": cursor[12]
            }
        return None
    
    @cached_query(cache=get_performance_cache(), ttl=600)  # 10 minutes cache
    def get_user_with_role(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user with role information with caching"""
        row = self.execute_query("""
            SELECT u.id, u.email, u.first_name, u.last_name, u.role_id,
                   u.is_active, u.is_verified, u.created_at, u.updated_at, u.last_login,
                   r.name as role_name, r.description as role_description
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.id = ?
        """, [user_id], fetch_one=True, fetch_all=False)
        
        if row:
            return {
                "id": row[0], "email": row[1], "first_name": row[2], "last_name": row[3],
                "role_id": row[4], "is_active": row[5], "is_verified": row[6],
                "created_at": row[7], "updated_at": row[8], "last_login": row[9],
                "role_name": row[10], "role_description": row[11]
            }
        return None

    @cached_query(cache=get_performance_cache(), ttl=300)
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID with caching"""
        row = self.execute_query(
            """
            SELECT id, email, password_hash, first_name, last_name,
                   is_active, is_verified, created_at, updated_at,
                   last_login, failed_login_attempts, locked_until
            FROM users WHERE id = ?
            """,
            [user_id],
            fetch_one=True,
            fetch_all=False,
        )
        if row:
            return {
                "id": row[0],
                "email": row[1],
                "password_hash": row[2],
                "first_name": row[3],
                "last_name": row[4],
                "is_active": row[5],
                "is_verified": row[6],
                "created_at": row[7],
                "updated_at": row[8],
                "last_login": row[9],
                "failed_login_attempts": row[10],
                "locked_until": row[11],
            }
        return None
    
    def get_session_cached(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session with in-memory caching"""
        # Try session cache first
        session_data = self.session_cache.get_session(session_id)
        if session_data:
            return session_data
        
        # Fall back to database
        session_data = self.get_session(session_id)
        if session_data:
            # Cache for future requests
            self.session_cache.set_session(session_id, session_data)
        
        return session_data
    
    def create_session_cached(self, user_id: int, ip_address: str = None, user_agent: str = None) -> str:
        """Create session with caching"""
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=24)
        self.create_session(session_id, user_id, expires_at, ip_address, user_agent)
        
        # Cache the new session
        session_data = {
            'id': session_id,
            'user_id': user_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'created_at': datetime.now(),
            'is_active': True
        }
        self.session_cache.set_session(session_id, session_data)
        
        return session_id
    
    def delete_session_cached(self, session_id: str) -> bool:
        """Delete session with cache invalidation"""
        # Remove from cache
        self.session_cache.remove_session(session_id)
        
        # Remove from database
        return self.delete_session(session_id)
    
    @cached_query(cache=get_performance_cache(), ttl=900)  # 15 minutes cache
    def get_all_users_with_roles(self) -> List[Dict[str, Any]]:
        """Get all users with role information with caching"""
        rows = self.execute_query("""
            SELECT u.id, u.email, u.first_name, u.last_name, u.role_id,
                   u.is_active, u.is_verified, u.created_at, u.updated_at, u.last_login,
                   r.name as role_name, r.description as role_description
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            ORDER BY u.created_at DESC
        """)
        
        users = []
        for row in rows:
            users.append({
                "id": row[0], "email": row[1], "first_name": row[2], "last_name": row[3],
                "role_id": row[4], "is_active": row[5], "is_verified": row[6],
                "created_at": row[7], "updated_at": row[8], "last_login": row[9],
                "role_name": row[10], "role_description": row[11]
            })
        
        return users
    
    @cached_query(cache=get_performance_cache(), ttl=1800)  # 30 minutes cache
    def get_user_count_by_role(self) -> Dict[str, int]:
        """Get user count by role with caching"""
        rows = self.execute_query("""
            SELECT r.name, COUNT(u.id) as user_count
            FROM roles r
            LEFT JOIN users u ON r.id = u.role_id
            GROUP BY r.id, r.name
        """)
        
        counts = {}
        for row in rows:
            counts[row[0]] = row[1]
        
        return counts
    
    def update_user_role_cached(self, user_id: int, role_id: int) -> bool:
        """Update user role with cache invalidation"""
        success = self.update_user_role(user_id, role_id)
        
        if success:
            # Clear user-specific cache entries
            clear_user_cache(user_id)
            
            # Clear related cached queries
            cache_keys_to_clear = [
                f"get_all_users_with_roles:",
                f"get_user_count_by_role:",
                f"get_user_with_role:({user_id}",
            ]
            
            for cache_key in cache_keys_to_clear:
                # Find and clear matching cache entries
                for key in list(self.cache.cache.keys()):
                    if any(pattern in key for pattern in cache_keys_to_clear):
                        self.cache.delete(key)
        
        return success
    
    def update_user_active_status_cached(self, user_id: int, is_active: bool) -> bool:
        """Update user active status with cache invalidation"""
        success = self.update_user_active_status(user_id, is_active)
        
        if success:
            # Clear user-specific cache entries
            clear_user_cache(user_id)
            
            # If deactivating user, clear all their sessions
            if not is_active:
                self.delete_user_sessions(user_id)
                # Clear session cache entries for this user
                sessions_to_remove = []
                for session_id in self.session_cache.sessions.keys():
                    session_data = self.session_cache.sessions.get(session_id)
                    if session_data and session_data.get('user_id') == user_id:
                        sessions_to_remove.append(session_id)
                
                for session_id in sessions_to_remove:
                    self.session_cache.remove_session(session_id)
        
        return success
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get database performance metrics"""
        query_stats = self.optimizer.get_stats_summary()
        cache_stats = self.cache.get_stats()
        session_stats = self.session_cache.get_stats()
        
        # Get slow queries
        slow_queries = self.optimizer.get_slow_queries(100.0)  # > 100ms
        frequent_queries = self.optimizer.get_frequent_queries(10)  # > 10 executions
        
        return {
            'query_performance': query_stats,
            'cache_performance': cache_stats,
            'session_cache': session_stats,
            'slow_queries': [
                {
                    'query': query[:150] + '...' if len(query) > 150 else query,
                    'avg_time_ms': round(stats['avg_time'] * 1000, 2),
                    'max_time_ms': round(stats['max_time'] * 1000, 2),
                    'count': stats['count']
                }
                for query, stats in slow_queries[:10]
            ],
            'frequent_queries': [
                {
                    'query': query[:150] + '...' if len(query) > 150 else query,
                    'count': stats['count'],
                    'avg_time_ms': round(stats['avg_time'] * 1000, 2)
                }
                for query, stats in frequent_queries[:10]
            ]
        }
    
    def optimize_database(self) -> Dict[str, Any]:
        """Run database optimization tasks"""
        optimizations = []
        
        try:
            # Clean up expired sessions
            expired_sessions = self.cleanup_expired_sessions()
            if expired_sessions > 0:
                optimizations.append(f"Cleaned up {expired_sessions} expired sessions")
            
            # Clean up expired tokens
            with self.get_connection() as conn:
                # Email verification tokens
                cursor = conn.execute("""
                    DELETE FROM email_verification_tokens 
                    WHERE expires_at < CURRENT_TIMESTAMP
                """)
                email_tokens_cleaned = cursor.rowcount if hasattr(cursor, 'rowcount') else 0
                
                # Password reset tokens
                cursor = conn.execute("""
                    DELETE FROM password_reset_tokens 
                    WHERE expires_at < CURRENT_TIMESTAMP
                """)
                password_tokens_cleaned = cursor.rowcount if hasattr(cursor, 'rowcount') else 0
                
                if email_tokens_cleaned > 0:
                    optimizations.append(f"Cleaned up {email_tokens_cleaned} expired email verification tokens")
                
                if password_tokens_cleaned > 0:
                    optimizations.append(f"Cleaned up {password_tokens_cleaned} expired password reset tokens")
            
            # Clean up cache
            cache_cleaned = self.cache.cleanup_expired()
            if cache_cleaned > 0:
                optimizations.append(f"Cleaned up {cache_cleaned} expired cache entries")
            
            # Clean up session cache
            session_cache_cleaned = self.session_cache.cleanup_expired()
            if session_cache_cleaned > 0:
                optimizations.append(f"Cleaned up {session_cache_cleaned} expired session cache entries")
            
            return {
                'success': True,
                'optimizations': optimizations,
                'total_cleanups': len(optimizations)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'optimizations': optimizations
            }
