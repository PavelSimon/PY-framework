"""
Performance and stress tests for PY-Framework
Tests system behavior under load and performance benchmarks
"""

import pytest
import tempfile
import os
import time
import threading
import concurrent.futures
from datetime import datetime, timedelta
from unittest.mock import Mock

from src.framework.database import Database
from src.framework.auth import AuthenticationService
from src.framework.csrf import CSRFProtection
from src.framework.audit import get_audit_service, AuditEventType


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    import uuid
    db_path = f"test_perf_{uuid.uuid4().hex}.db"
    
    db = Database(db_path)
    yield db
    
    # Cleanup
    if hasattr(db, '_conn') and db._conn:
        db._conn.close()
    try:
        os.unlink(db_path)
    except:
        pass


@pytest.fixture
def perf_services(temp_db):
    """Initialize services for performance testing"""
    auth_service = AuthenticationService("test-secret-key-32-characters-long")
    csrf_protection = CSRFProtection("test-secret-key-32-characters-long")
    audit_service = get_audit_service(temp_db)
    
    return {
        'db': temp_db,
        'auth': auth_service,
        'csrf': csrf_protection,
        'audit': audit_service
    }


@pytest.mark.performance
@pytest.mark.slow
class TestDatabasePerformance:
    """Test database operation performance"""
    
    def test_user_creation_performance(self, perf_services):
        """Test performance of creating many users"""
        db = perf_services['db']
        auth_service = perf_services['auth']
        
        # Benchmark user creation
        start_time = time.time()
        user_ids = []
        
        for i in range(100):
            user_id = db.create_user(
                email=f'perf_user_{i}@example.com',
                password_hash=auth_service.hash_password('TestPass123!'),
                first_name=f'User{i}',
                last_name='Performance'
            )
            user_ids.append(user_id)
        
        creation_time = time.time() - start_time
        avg_time_per_user = creation_time / 100
        
        print(f"Created 100 users in {creation_time:.3f}s (avg: {avg_time_per_user*1000:.1f}ms per user)")
        
        # Performance assertion: should create users reasonably fast
        assert avg_time_per_user < 0.1  # Less than 100ms per user
        assert creation_time < 10.0  # Total time under 10 seconds
        
        # Test bulk query performance
        start_time = time.time()
        all_users = db.get_all_users_with_roles()
        query_time = time.time() - start_time
        
        print(f"Queried {len(all_users)} users in {query_time:.3f}s")
        
        assert len(all_users) >= 100
        assert query_time < 1.0  # Should query all users in under 1 second
        
        # Cleanup
        for user_id in user_ids:
            db.delete_user(user_id)
    
    def test_session_performance(self, perf_services):
        """Test session creation and validation performance"""
        db = perf_services['db']
        auth_service = perf_services['auth']
        
        # Create test user
        user_id = db.create_user(
            email='session_perf@example.com',
            password_hash=auth_service.hash_password('SessionPass123!'),
            first_name='Session',
            last_name='Test'
        )
        
        # Benchmark session creation
        start_time = time.time()
        session_ids = []
        
        for i in range(50):
            session_id = auth_service.create_session(
                user_id, f'127.0.0.{i%255}', f'Agent-{i}'
            )
            session_ids.append(session_id)
        
        session_creation_time = time.time() - start_time
        avg_session_time = session_creation_time / 50
        
        print(f"Created 50 sessions in {session_creation_time:.3f}s (avg: {avg_session_time*1000:.1f}ms per session)")
        
        assert avg_session_time < 0.05  # Less than 50ms per session
        
        # Benchmark session validation
        start_time = time.time()
        valid_sessions = 0
        
        for session_id in session_ids:
            session_data = auth_service.validate_session(session_id)
            if session_data:
                valid_sessions += 1
        
        validation_time = time.time() - start_time
        avg_validation_time = validation_time / 50
        
        print(f"Validated 50 sessions in {validation_time:.3f}s (avg: {avg_validation_time*1000:.1f}ms per validation)")
        
        assert valid_sessions == 50  # All sessions should be valid
        assert avg_validation_time < 0.02  # Less than 20ms per validation
        
        # Cleanup
        for session_id in session_ids:
            auth_service.logout_user(session_id)
        db.delete_user(user_id)
    
    def test_audit_logging_performance(self, perf_services):
        """Test audit logging performance under load"""
        audit_service = perf_services['audit']
        db = perf_services['db']
        auth_service = perf_services['auth']
        
        # Create test user
        user_id = db.create_user(
            email='audit_perf@example.com',
            password_hash=auth_service.hash_password('AuditPass123!'),
            first_name='Audit',
            last_name='Performance'
        )
        
        # Benchmark audit logging
        start_time = time.time()
        
        for i in range(200):
            audit_service.log_event(
                event_type=AuditEventType.LOGIN_SUCCESS,
                user_id=user_id,
                ip_address=f'192.168.1.{i%255}',
                user_agent=f'TestAgent-{i}',
                details={'test_number': i, 'batch': 'performance_test'}
            )
        
        logging_time = time.time() - start_time
        avg_log_time = logging_time / 200
        
        print(f"Logged 200 audit events in {logging_time:.3f}s (avg: {avg_log_time*1000:.1f}ms per event)")
        
        assert avg_log_time < 0.05  # Less than 50ms per audit event
        
        # Test audit query performance
        start_time = time.time()
        user_events = audit_service.get_user_activity(user_id, limit=100)
        query_time = time.time() - start_time
        
        print(f"Queried 100 audit events in {query_time:.3f}s")
        
        assert len(user_events) >= 100
        assert query_time < 0.5  # Query should complete in under 500ms
        
        # Cleanup
        db.delete_user(user_id)


@pytest.mark.performance
@pytest.mark.slow
class TestConcurrencyPerformance:
    """Test system performance under concurrent load"""
    
    def test_concurrent_user_operations(self, perf_services):
        """Test concurrent user creation and authentication"""
        db = perf_services['db']
        auth_service = perf_services['auth']
        
        def create_and_auth_user(thread_id):
            """Create user and perform authentication in thread"""
            try:
                # Create user
                user_id = db.create_user(
                    email=f'concurrent_{thread_id}@example.com',
                    password_hash=auth_service.hash_password('ConcurrentPass123!'),
                    first_name=f'User{thread_id}',
                    last_name='Concurrent'
                )
                db.verify_user_email(user_id)
                
                # Perform authentication
                result = auth_service.authenticate_user(
                    f'concurrent_{thread_id}@example.com',
                    'ConcurrentPass123!',
                    f'127.0.0.{thread_id%255}',
                    f'ConcurrentAgent-{thread_id}'
                )
                
                return {
                    'thread_id': thread_id,
                    'user_id': user_id,
                    'auth_success': result['success'],
                    'session_id': result.get('session_id')
                }
            except Exception as e:
                return {
                    'thread_id': thread_id,
                    'error': str(e)
                }
        
        # Run concurrent operations
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_and_auth_user, i) for i in range(20)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        total_time = time.time() - start_time
        
        print(f"Completed 20 concurrent user operations in {total_time:.3f}s")
        
        # Analyze results
        successful_operations = [r for r in results if 'error' not in r and r['auth_success']]
        failed_operations = [r for r in results if 'error' in r or not r.get('auth_success', False)]
        
        print(f"Successful operations: {len(successful_operations)}")
        print(f"Failed operations: {len(failed_operations)}")
        
        # Performance assertions
        assert len(successful_operations) >= 18  # At least 90% success rate
        assert total_time < 15.0  # Should complete in under 15 seconds
        
        # Cleanup
        for result in successful_operations:
            if 'user_id' in result:
                try:
                    if result.get('session_id'):
                        auth_service.logout_user(result['session_id'])
                    db.delete_user(result['user_id'])
                except:
                    pass  # Ignore cleanup errors
    
    def test_concurrent_session_validation(self, perf_services):
        """Test concurrent session validation performance"""
        db = perf_services['db']
        auth_service = perf_services['auth']
        
        # Create test users and sessions
        users_and_sessions = []
        for i in range(20):
            user_id = db.create_user(
                email=f'session_test_{i}@example.com',
                password_hash=auth_service.hash_password('SessionTest123!'),
                first_name=f'SessionUser{i}',
                last_name='Test'
            )
            
            session_id = auth_service.create_session(
                user_id, f'10.0.0.{i}', f'SessionAgent-{i}'
            )
            
            users_and_sessions.append((user_id, session_id))
        
        def validate_session(session_data):
            """Validate session in thread"""
            user_id, session_id = session_data
            try:
                validation_result = auth_service.validate_session(session_id)
                return {
                    'user_id': user_id,
                    'session_id': session_id,
                    'valid': validation_result is not None,
                    'validation_data': validation_result
                }
            except Exception as e:
                return {
                    'user_id': user_id,
                    'session_id': session_id,
                    'error': str(e)
                }
        
        # Test concurrent session validation (simulate high load)
        start_time = time.time()
        
        # Validate each session 5 times concurrently (100 total validations)
        validation_tasks = users_and_sessions * 5
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(validate_session, session_data) for session_data in validation_tasks]
            validation_results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        validation_time = time.time() - start_time
        
        print(f"Completed 100 concurrent session validations in {validation_time:.3f}s")
        
        # Analyze results
        successful_validations = [r for r in validation_results if 'error' not in r and r['valid']]
        failed_validations = [r for r in validation_results if 'error' in r or not r.get('valid', False)]
        
        print(f"Successful validations: {len(successful_validations)}")
        print(f"Failed validations: {len(failed_validations)}")
        
        # Performance assertions
        assert len(successful_validations) >= 95  # At least 95% success rate
        assert validation_time < 5.0  # Should complete in under 5 seconds
        avg_validation_time = validation_time / 100
        assert avg_validation_time < 0.05  # Less than 50ms per validation on average
        
        # Cleanup
        for user_id, session_id in users_and_sessions:
            try:
                auth_service.logout_user(session_id)
                db.delete_user(user_id)
            except:
                pass  # Ignore cleanup errors


@pytest.mark.performance
class TestMemoryAndResourceUsage:
    """Test memory and resource usage patterns"""
    
    def test_csrf_token_memory_usage(self, perf_services):
        """Test CSRF token generation doesn't leak memory"""
        csrf = perf_services['csrf']
        
        # Generate many tokens for different sessions
        session_ids = [f"session_{i}" for i in range(100)]
        tokens = []
        
        start_time = time.time()
        
        for session_id in session_ids:
            for _ in range(10):  # 10 tokens per session
                token = csrf.generate_token(session_id)
                tokens.append((token, session_id))
        
        generation_time = time.time() - start_time
        
        print(f"Generated 1000 CSRF tokens in {generation_time:.3f}s")
        
        # Test token validation performance
        start_time = time.time()
        valid_tokens = 0
        
        for token, session_id in tokens[:500]:  # Validate half the tokens
            if csrf.validate_token(token, session_id, consume=True):
                valid_tokens += 1
        
        validation_time = time.time() - start_time
        
        print(f"Validated 500 CSRF tokens in {validation_time:.3f}s")
        print(f"Valid tokens: {valid_tokens}")
        
        # Performance assertions
        assert generation_time < 2.0  # Should generate 1000 tokens in under 2 seconds
        assert validation_time < 1.0  # Should validate 500 tokens in under 1 second
        assert valid_tokens == 500  # All tokens should be valid
        
        # Test cleanup performance
        start_time = time.time()
        csrf.cleanup_expired_tokens()
        cleanup_time = time.time() - start_time
        
        print(f"CSRF cleanup completed in {cleanup_time:.3f}s")
        assert cleanup_time < 0.5  # Cleanup should be fast
    
    def test_session_cleanup_performance(self, perf_services):
        """Test session cleanup performance with many expired sessions"""
        db = perf_services['db']
        auth_service = perf_services['auth']
        
        # Create test user
        user_id = db.create_user(
            email='cleanup_test@example.com',
            password_hash=auth_service.hash_password('CleanupPass123!'),
            first_name='Cleanup',
            last_name='Test'
        )
        
        # Create many sessions and expire them
        session_ids = []
        for i in range(100):
            session_id = auth_service.create_session(
                user_id, f'172.16.0.{i%255}', f'CleanupAgent-{i}'
            )
            session_ids.append(session_id)
            
            # Manually expire the session by setting past expiry date
            db.conn.execute("""
                UPDATE sessions 
                SET expires_at = datetime('now', '-1 day') 
                WHERE id = ?
            """, [session_id])
        
        # Test cleanup performance
        start_time = time.time()
        cleaned_count = auth_service.cleanup_expired_sessions()
        cleanup_time = time.time() - start_time
        
        print(f"Cleaned up {cleaned_count} expired sessions in {cleanup_time:.3f}s")
        
        # Performance assertions
        assert cleaned_count >= 100  # Should clean up all expired sessions
        assert cleanup_time < 1.0  # Should complete cleanup in under 1 second
        
        # Verify sessions are actually cleaned up
        remaining_sessions = 0
        for session_id in session_ids:
            if auth_service.validate_session(session_id):
                remaining_sessions += 1
        
        assert remaining_sessions == 0  # All sessions should be cleaned up
        
        # Cleanup
        db.delete_user(user_id)


@pytest.mark.performance
@pytest.mark.slow
class TestStressTests:
    """Stress tests to evaluate system limits"""
    
    def test_database_connection_stress(self, perf_services):
        """Test database performance under connection stress"""
        db = perf_services['db']
        auth_service = perf_services['auth']
        
        def database_operation(operation_id):
            """Perform database operations"""
            try:
                # Create user
                user_id = db.create_user(
                    email=f'stress_{operation_id}@example.com',
                    password_hash=auth_service.hash_password('StressPass123!'),
                    first_name=f'Stress{operation_id}',
                    last_name='Test'
                )
                
                # Query user
                user = db.get_user_by_id(user_id)
                
                # Update user
                db.update_user_profile(user_id, first_name=f'Updated{operation_id}')
                
                # Create session
                session_id = auth_service.create_session(
                    user_id, f'192.168.1.{operation_id%255}', f'StressAgent-{operation_id}'
                )
                
                # Validate session
                session_data = auth_service.validate_session(session_id)
                
                # Cleanup
                auth_service.logout_user(session_id)
                db.delete_user(user_id)
                
                return {
                    'operation_id': operation_id,
                    'success': True,
                    'user_created': user_id is not None,
                    'session_valid': session_data is not None
                }
            except Exception as e:
                return {
                    'operation_id': operation_id,
                    'success': False,
                    'error': str(e)
                }
        
        # Run stress test with many concurrent operations
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(database_operation, i) for i in range(50)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        stress_time = time.time() - start_time
        
        print(f"Completed 50 stress operations in {stress_time:.3f}s")
        
        # Analyze results
        successful_ops = [r for r in results if r['success']]
        failed_ops = [r for r in results if not r['success']]
        
        print(f"Successful operations: {len(successful_ops)}")
        print(f"Failed operations: {len(failed_ops)}")
        
        if failed_ops:
            print("Failed operation errors:")
            for op in failed_ops[:5]:  # Show first 5 errors
                print(f"  Op {op['operation_id']}: {op['error']}")
        
        # Stress test assertions
        success_rate = len(successful_ops) / len(results)
        assert success_rate >= 0.9  # At least 90% success rate under stress
        assert stress_time < 30.0  # Should complete all operations in under 30 seconds


# Performance Optimization Tests
@pytest.mark.performance
class TestPerformanceOptimization:
    """Test performance optimization features"""
    
    def test_cache_performance(self):
        """Test performance cache functionality"""
        from src.framework.performance import PerformanceCache
        
        cache = PerformanceCache(default_ttl=300)
        
        # Test basic operations performance
        start_time = time.time()
        
        for i in range(1000):
            cache.set(f"key_{i}", f"value_{i}")
        
        set_time = time.time() - start_time
        
        start_time = time.time()
        
        for i in range(1000):
            value = cache.get(f"key_{i}")
            assert value == f"value_{i}"
        
        get_time = time.time() - start_time
        
        print(f"Cache set 1000 items in {set_time:.3f}s")
        print(f"Cache get 1000 items in {get_time:.3f}s")
        
        assert set_time < 1.0  # Should set 1000 items in under 1 second
        assert get_time < 0.5  # Should get 1000 items in under 0.5 seconds
        
        # Test cache stats
        stats = cache.get_stats()
        assert stats['hits'] == 1000
        assert stats['size'] == 1000
        assert stats['hit_rate_percent'] == 100.0
    
    def test_query_optimizer_performance(self):
        """Test query optimizer tracking performance"""
        from src.framework.performance import QueryOptimizer
        
        optimizer = QueryOptimizer()
        
        # Track many queries
        start_time = time.time()
        
        for i in range(1000):
            optimizer.track_query(f"SELECT * FROM table_{i % 10}", 0.001 + (i % 100) * 0.0001)
        
        tracking_time = time.time() - start_time
        
        print(f"Tracked 1000 queries in {tracking_time:.3f}s")
        
        # Get statistics
        start_time = time.time()
        stats = optimizer.get_stats_summary()
        slow_queries = optimizer.get_slow_queries(5.0)  # 5ms threshold
        frequent_queries = optimizer.get_frequent_queries(50)
        stats_time = time.time() - start_time
        
        print(f"Generated statistics in {stats_time:.3f}s")
        
        assert tracking_time < 1.0  # Should track 1000 queries in under 1 second
        assert stats_time < 0.1    # Should generate stats in under 0.1 seconds
        assert stats['total_queries'] == 1000
        assert stats['unique_query_patterns'] == 10
    
    def test_session_cache_performance(self):
        """Test session cache performance"""
        from src.framework.performance import SessionCache
        
        cache = SessionCache(max_sessions=1000)
        
        # Test session operations performance
        start_time = time.time()
        
        for i in range(1000):
            session_data = {
                'user_id': i,
                'email': f'user_{i}@example.com',
                'role': 'user',
                'created_at': time.time()
            }
            cache.set_session(f"session_{i}", session_data)
        
        set_time = time.time() - start_time
        
        start_time = time.time()
        
        for i in range(1000):
            session_data = cache.get_session(f"session_{i}")
            assert session_data['user_id'] == i
        
        get_time = time.time() - start_time
        
        print(f"Session cache set 1000 sessions in {set_time:.3f}s")
        print(f"Session cache get 1000 sessions in {get_time:.3f}s")
        
        assert set_time < 2.0  # Should set 1000 sessions in under 2 seconds
        assert get_time < 1.0  # Should get 1000 sessions in under 1 second
        
        # Test LRU eviction performance
        start_time = time.time()
        
        for i in range(1000, 1100):  # Add 100 more (should trigger eviction)
            session_data = {'user_id': i, 'email': f'user_{i}@example.com'}
            cache.set_session(f"session_{i}", session_data)
        
        eviction_time = time.time() - start_time
        
        print(f"LRU eviction for 100 sessions in {eviction_time:.3f}s")
        assert eviction_time < 1.0  # Should handle eviction in under 1 second
        assert cache.get_stats()['total_sessions'] == 1000  # Should maintain max size
    
    def test_cached_query_decorator_performance(self):
        """Test cached query decorator performance impact"""
        from src.framework.performance import cached_query, PerformanceCache
        
        cache = PerformanceCache()
        call_count = 0
        
        @cached_query(cache=cache, ttl=300)
        def expensive_operation(param):
            nonlocal call_count
            call_count += 1
            time.sleep(0.001)  # Simulate expensive operation
            return f"result_{param}"
        
        # Test first calls (cache misses)
        start_time = time.time()
        
        for i in range(100):
            result = expensive_operation(f"param_{i}")
            assert result == f"result_param_{i}"
        
        miss_time = time.time() - start_time
        
        # Test cached calls (cache hits)
        start_time = time.time()
        
        for i in range(100):
            result = expensive_operation(f"param_{i}")
            assert result == f"result_param_{i}"
        
        hit_time = time.time() - start_time
        
        print(f"100 cache misses took {miss_time:.3f}s")
        print(f"100 cache hits took {hit_time:.3f}s")
        print(f"Cache speedup: {miss_time / hit_time:.1f}x")
        
        assert call_count == 100  # Function should only be called once per unique param
        assert hit_time < miss_time / 5  # Cached calls should be at least 5x faster
        assert hit_time < 0.1  # Cached calls should be very fast


@pytest.mark.performance
class TestOptimizedDatabasePerformance:
    """Test optimized database performance"""
    
    def test_optimized_vs_regular_database_performance(self, perf_services):
        """Compare optimized database vs regular database performance"""
        from src.framework.database.optimized_database import OptimizedDatabase
        from src.framework.database import Database
        
        # Create both database instances
        regular_db = Database(":memory:")
        optimized_db = OptimizedDatabase(":memory:", use_connection_pool=False)  # Disable pool for fair comparison
        
        # Create test data
        auth_service = perf_services['auth']
        
        # Regular database performance
        start_time = time.time()
        
        regular_user_ids = []
        for i in range(100):
            user_id = regular_db.create_user(
                email=f'regular_{i}@example.com',
                password_hash=auth_service.hash_password('TestPass123!'),
                first_name=f'Regular{i}',
                last_name='User'
            )
            regular_user_ids.append(user_id)
        
        regular_create_time = time.time() - start_time
        
        start_time = time.time()
        
        for user_id in regular_user_ids:
            user = regular_db.get_user_by_id(user_id)
            assert user is not None
        
        regular_read_time = time.time() - start_time
        
        # Optimized database performance
        start_time = time.time()
        
        optimized_user_ids = []
        for i in range(100):
            user_id = optimized_db.create_user(
                email=f'optimized_{i}@example.com',
                password_hash=auth_service.hash_password('TestPass123!'),
                first_name=f'Optimized{i}',
                last_name='User'
            )
            optimized_user_ids.append(user_id)
        
        optimized_create_time = time.time() - start_time
        
        # Test cached reads (should be faster)
        start_time = time.time()
        
        for user_id in optimized_user_ids:
            user = optimized_db.get_user_by_id(user_id)  # First call - cache miss
            assert user is not None
        
        optimized_read_time_miss = time.time() - start_time
        
        start_time = time.time()
        
        for user_id in optimized_user_ids:
            user = optimized_db.get_user_by_id(user_id)  # Second call - cache hit
            assert user is not None
        
        optimized_read_time_hit = time.time() - start_time
        
        print(f"Regular DB - Create: {regular_create_time:.3f}s, Read: {regular_read_time:.3f}s")
        print(f"Optimized DB - Create: {optimized_create_time:.3f}s, Read (miss): {optimized_read_time_miss:.3f}s, Read (hit): {optimized_read_time_hit:.3f}s")
        
        # Performance assertions
        assert optimized_read_time_hit < optimized_read_time_miss / 2  # Cache hits should be much faster
        assert optimized_read_time_hit < regular_read_time / 2  # Cached reads should be faster than regular
    
    def test_optimized_database_session_caching(self, perf_services):
        """Test optimized database session caching performance"""
        from src.framework.database.optimized_database import OptimizedDatabase
        
        optimized_db = OptimizedDatabase(":memory:")
        auth_service = perf_services['auth']
        
        # Create test user
        user_id = optimized_db.create_user(
            email='session_test@example.com',
            password_hash=auth_service.hash_password('TestPass123!'),
            first_name='Session',
            last_name='Test'
        )
        
        # Create session
        session_id = optimized_db.create_session_cached(user_id, '127.0.0.1', 'TestAgent')
        
        # Test session retrieval performance
        start_time = time.time()
        
        for _ in range(100):
            session_data = optimized_db.get_session_cached(session_id)
            assert session_data is not None
            assert session_data['user_id'] == user_id
        
        cached_session_time = time.time() - start_time
        
        print(f"100 cached session retrievals in {cached_session_time:.3f}s")
        
        # Performance assertion
        assert cached_session_time < 0.5  # Should be very fast with caching
        
        # Test cache invalidation
        optimized_db.delete_session_cached(session_id)
        session_data = optimized_db.get_session_cached(session_id)
        assert session_data is None


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-m', 'performance'])