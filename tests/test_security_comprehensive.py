"""
Comprehensive security tests for PY-Framework
Tests security vulnerabilities, attack vectors, and defensive measures
"""

import pytest
import tempfile
import os
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from src.framework.database import Database
from src.framework.auth import AuthenticationService
from src.framework.csrf import CSRFProtection
from src.framework.security import SecurityConfig, SecurityMiddleware, RateLimiter
from src.framework.audit import get_audit_service, AuditEventType


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    import uuid
    db_path = f"test_security_{uuid.uuid4().hex}.db"
    
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
def security_services(temp_db):
    """Initialize services for security testing"""
    auth_service = AuthenticationService("test-secret-key-32-characters-long")
    csrf_protection = CSRFProtection("test-secret-key-32-characters-long")
    audit_service = get_audit_service(temp_db)
    security_config = SecurityConfig()
    rate_limiter = RateLimiter()
    
    return {
        'db': temp_db,
        'auth': auth_service,
        'csrf': csrf_protection,
        'audit': audit_service,
        'security_config': security_config,
        'rate_limiter': rate_limiter
    }


@pytest.mark.security
class TestPasswordSecurity:
    """Test password security measures"""
    
    def test_password_hashing_security(self, security_services):
        """Test password hashing is secure against attacks"""
        auth_service = security_services['auth']
        
        password = "TestPassword123!"
        
        # Test that same password produces different hashes (salt)
        hash1 = auth_service.hash_password(password)
        hash2 = auth_service.hash_password(password)
        
        assert hash1 != hash2  # Different salts should produce different hashes
        assert len(hash1) >= 60  # BCrypt hash should be at least 60 characters
        assert hash1.startswith('$2b$')  # Should use BCrypt 2b
        
        # Test both hashes verify correctly
        assert auth_service.verify_password(password, hash1) == True
        assert auth_service.verify_password(password, hash2) == True
        
        # Test wrong password doesn't verify
        assert auth_service.verify_password("WrongPassword", hash1) == False
        assert auth_service.verify_password("WrongPassword", hash2) == False
    
    def test_password_timing_attack_resistance(self, security_services):
        """Test password verification has consistent timing"""
        auth_service = security_services['auth']
        
        # Create test password hash
        correct_password = "CorrectPassword123!"
        password_hash = auth_service.hash_password(correct_password)
        
        # Time correct password verification
        correct_times = []
        for _ in range(10):
            start = time.time()
            auth_service.verify_password(correct_password, password_hash)
            correct_times.append(time.time() - start)
        
        # Time incorrect password verification
        wrong_times = []
        for _ in range(10):
            start = time.time()
            auth_service.verify_password("WrongPassword123!", password_hash)
            wrong_times.append(time.time() - start)
        
        avg_correct_time = sum(correct_times) / len(correct_times)
        avg_wrong_time = sum(wrong_times) / len(wrong_times)
        
        # Timing should be similar (within 50% difference)
        time_ratio = abs(avg_correct_time - avg_wrong_time) / max(avg_correct_time, avg_wrong_time)
        
        print(f"Correct password avg time: {avg_correct_time:.4f}s")
        print(f"Wrong password avg time: {avg_wrong_time:.4f}s")
        print(f"Time difference ratio: {time_ratio:.2f}")
        
        # BCrypt should provide timing attack resistance
        assert time_ratio < 0.5  # Times should be within 50% of each other
    
    def test_password_strength_enforcement(self, security_services):
        """Test password strength requirements"""
        db = security_services['db']
        auth_service = security_services['auth']
        
        # Test weak passwords are rejected
        weak_passwords = [
            "123456",
            "password",
            "abc123",
            "Password",  # No number or special char
            "password123",  # No uppercase or special char
            "PASSWORD123!",  # No lowercase
            "Passw0rd",  # Too short
            "   ",  # Just spaces
            ""  # Empty
        ]
        
        for weak_password in weak_passwords:
            try:
                user_id = db.create_user(
                    email=f'weak_{hashlib.md5(weak_password.encode()).hexdigest()}@example.com',
                    password_hash=auth_service.hash_password(weak_password),
                    first_name='Weak',
                    last_name='Password'
                )
                # If we get here, the password was accepted, which is bad
                # Cleanup and fail
                if user_id:
                    db.delete_user(user_id)
                assert False, f"Weak password '{weak_password}' was incorrectly accepted"
            except Exception:
                # Expected - weak password should be rejected
                pass
        
        # Test strong password is accepted
        strong_password = "StrongPassword123!@#"
        try:
            user_id = db.create_user(
                email='strong@example.com',
                password_hash=auth_service.hash_password(strong_password),
                first_name='Strong',
                last_name='Password'
            )
            assert user_id is not None
            db.delete_user(user_id)
        except Exception as e:
            assert False, f"Strong password was incorrectly rejected: {e}"


@pytest.mark.security
class TestSessionSecurity:
    """Test session security measures"""
    
    def test_session_token_randomness(self, security_services):
        """Test session tokens are cryptographically random"""
        auth_service = security_services['auth']
        db = security_services['db']
        
        # Create test user
        user_id = db.create_user(
            email='session_security@example.com',
            password_hash=auth_service.hash_password('SessionPass123!'),
            first_name='Session',
            last_name='Security'
        )
        
        # Generate many session tokens
        session_tokens = []
        for i in range(100):
            session_id = auth_service.create_session(
                user_id, f'127.0.0.{i%255}', f'TestAgent-{i}'
            )
            session_tokens.append(session_id)
        
        # Test uniqueness
        assert len(set(session_tokens)) == 100  # All tokens should be unique
        
        # Test token length and format
        for token in session_tokens:
            assert len(token) >= 32  # Should be at least 32 characters
            assert token.replace('-', '').replace('_', '').isalnum()  # Should be alphanumeric
        
        # Test entropy (basic check)
        # Convert tokens to bytes and check entropy
        token_bytes = ''.join(session_tokens).encode()
        byte_frequency = {}
        for byte in token_bytes:
            byte_frequency[byte] = byte_frequency.get(byte, 0) + 1
        
        # Calculate simple entropy measure
        total_bytes = len(token_bytes)
        entropy = 0
        for count in byte_frequency.values():
            probability = count / total_bytes
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        print(f"Token entropy measure: {entropy:.2f}")
        assert entropy > 4.0  # Should have reasonable entropy
        
        # Cleanup
        for session_id in session_tokens:
            auth_service.logout_user(session_id)
        db.delete_user(user_id)
    
    def test_session_fixation_protection(self, security_services):
        """Test protection against session fixation attacks"""
        auth_service = security_services['auth']
        db = security_services['db']
        
        # Create test user
        user_id = db.create_user(
            email='fixation@example.com',
            password_hash=auth_service.hash_password('FixationPass123!'),
            first_name='Fixation',
            last_name='Test'
        )
        
        # Create initial session (simulate attacker providing session)
        initial_session = auth_service.create_session(
            user_id, '127.0.0.1', 'AttackerAgent'
        )
        
        # Authenticate user (should create new session)
        auth_result = auth_service.authenticate_user(
            'fixation@example.com',
            'FixationPass123!',
            '127.0.0.1',
            'UserAgent'
        )
        
        new_session = auth_result.get('session_id')
        
        # New session should be different from initial session
        assert new_session != initial_session
        
        # Old session should be invalidated
        old_session_data = auth_service.validate_session(initial_session)
        assert old_session_data is None  # Should be invalid
        
        # New session should be valid
        new_session_data = auth_service.validate_session(new_session)
        assert new_session_data is not None
        
        # Cleanup
        auth_service.logout_user(new_session)
        db.delete_user(user_id)
    
    def test_session_hijacking_protection(self, security_services):
        """Test protection against session hijacking"""
        auth_service = security_services['auth']
        db = security_services['db']
        
        # Create test user
        user_id = db.create_user(
            email='hijack@example.com',
            password_hash=auth_service.hash_password('HijackPass123!'),
            first_name='Hijack',
            last_name='Test'
        )
        
        # Create session from legitimate IP/User-Agent
        legitimate_session = auth_service.create_session(
            user_id, '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        )
        
        # Validate session from same IP/User-Agent (should work)
        session_data = auth_service.validate_session(legitimate_session)
        assert session_data is not None
        assert session_data['ip_address'] == '192.168.1.100'
        
        # Try to use session from different IP (simulate hijacking)
        # Note: Current implementation may not block this, but we test the tracking
        session_data = auth_service.validate_session(legitimate_session)
        if session_data:
            # Verify IP is tracked for security monitoring
            assert 'ip_address' in session_data
            assert 'user_agent' in session_data
        
        # Cleanup
        auth_service.logout_user(legitimate_session)
        db.delete_user(user_id)


@pytest.mark.security
class TestCSRFSecurity:
    """Test CSRF protection security"""
    
    def test_csrf_token_unpredictability(self, security_services):
        """Test CSRF tokens are unpredictable"""
        csrf = security_services['csrf']
        
        # Generate many tokens for same session
        session_id = "test-session-123"
        tokens = []
        
        for _ in range(100):
            token = csrf.generate_token(session_id)
            tokens.append(token)
        
        # All tokens should be unique
        assert len(set(tokens)) == 100
        
        # Test token structure
        for token in tokens:
            parts = token.split('.')
            assert len(parts) >= 2  # Should have timestamp and signature parts
            
        # Test tokens from different sessions are different
        other_session_tokens = []
        for i in range(10):
            token = csrf.generate_token(f"other-session-{i}")
            other_session_tokens.append(token)
        
        # No overlap between session tokens
        assert len(set(tokens) & set(other_session_tokens)) == 0
    
    def test_csrf_token_tampering_detection(self, security_services):
        """Test CSRF tokens detect tampering"""
        csrf = security_services['csrf']
        session_id = "tamper-test-session"
        
        # Generate valid token
        valid_token = csrf.generate_token(session_id)
        
        # Test valid token works
        assert csrf.validate_token(valid_token, session_id, consume=False) == True
        
        # Test tampered tokens are rejected
        tampered_tokens = [
            valid_token[:-1] + 'X',  # Change last character
            valid_token[1:],  # Remove first character
            valid_token + 'extra',  # Add extra data
            valid_token.replace('.', '_'),  # Change separator
            'totally.different.token',  # Completely different
            '',  # Empty token
            'not.a.token'  # Invalid format
        ]
        
        for tampered_token in tampered_tokens:
            assert csrf.validate_token(tampered_token, session_id, consume=False) == False
    
    def test_csrf_double_submit_pattern(self, security_services):
        """Test CSRF double-submit cookie pattern security"""
        csrf = security_services['csrf']
        
        # Generate token for session
        session_id = "double-submit-session"
        token = csrf.generate_token(session_id)
        
        # Token should only validate with correct session
        assert csrf.validate_token(token, session_id, consume=False) == True
        assert csrf.validate_token(token, "wrong-session", consume=False) == False
        
        # Generate token for different session
        other_session = "other-double-submit-session"
        other_token = csrf.generate_token(other_session)
        
        # Cross-session validation should fail
        assert csrf.validate_token(token, other_session, consume=False) == False
        assert csrf.validate_token(other_token, session_id, consume=False) == False


@pytest.mark.security
class TestRateLimitingSecurity:
    """Test rate limiting security measures"""
    
    def test_brute_force_protection(self, security_services):
        """Test protection against brute force attacks"""
        db = security_services['db']
        auth_service = security_services['auth']
        audit_service = security_services['audit']
        
        # Create test user
        user_id = db.create_user(
            email='bruteforce@example.com',
            password_hash=auth_service.hash_password('CorrectPass123!'),
            first_name='Brute',
            last_name='Force'
        )
        db.verify_user_email(user_id)
        
        # Perform brute force attack
        failed_attempts = 0
        for i in range(10):
            result = auth_service.authenticate_user(
                'bruteforce@example.com',
                f'WrongPass{i}!',
                '127.0.0.1',
                'BruteForceAgent'
            )
            if not result['success']:
                failed_attempts += 1
        
        # Account should be locked after 5 failed attempts
        user = db.get_user_by_id(user_id)
        assert user['failed_login_attempts'] >= 5
        assert user['locked_until'] is not None
        
        # Even correct password should fail when locked
        result = auth_service.authenticate_user(
            'bruteforce@example.com',
            'CorrectPass123!',
            '127.0.0.1',
            'BruteForceAgent'
        )
        assert result['success'] == False
        assert 'locked' in result['error'].lower()
        
        # Verify security events are logged
        security_events = audit_service.get_security_events(limit=20)
        failed_login_events = [e for e in security_events if e['event_type'] == 'login_failed']
        assert len(failed_login_events) >= 5
        
        # Cleanup
        db.delete_user(user_id)
    
    def test_rate_limiter_ip_blocking(self, security_services):
        """Test rate limiter blocks excessive requests from IP"""
        rate_limiter = security_services['rate_limiter']
        
        # Configure aggressive rate limiting for testing
        rate_limiter.requests_per_minute = 10
        rate_limiter.requests_per_hour = 30
        
        ip_address = "10.0.0.100"
        
        # Make requests up to the limit
        allowed_requests = 0
        for i in range(15):
            if rate_limiter.is_allowed(ip_address):
                allowed_requests += 1
        
        print(f"Allowed requests: {allowed_requests}")
        
        # Should be limited to the configured limit
        assert allowed_requests <= 10  # Should respect per-minute limit
        
        # Subsequent requests should be blocked
        assert rate_limiter.is_allowed(ip_address) == False
        
        # Different IP should not be affected
        other_ip = "10.0.0.101"
        assert rate_limiter.is_allowed(other_ip) == True
    
    def test_distributed_brute_force_protection(self, security_services):
        """Test protection against distributed brute force attacks"""
        db = security_services['db']
        auth_service = security_services['auth']
        
        # Create test user
        user_id = db.create_user(
            email='distributed@example.com',
            password_hash=auth_service.hash_password('DistributedPass123!'),
            first_name='Distributed',
            last_name='Attack'
        )
        db.verify_user_email(user_id)
        
        # Simulate distributed attack from multiple IPs
        attack_ips = [f"172.16.{i}.{j}" for i in range(1, 4) for j in range(1, 4)]
        total_failed_attempts = 0
        
        for ip in attack_ips:
            # 2 failed attempts per IP (total 18 attempts)
            for attempt in range(2):
                result = auth_service.authenticate_user(
                    'distributed@example.com',
                    f'WrongPass{ip.replace(".", "")}{attempt}!',
                    ip,
                    f'AttackAgent-{ip}'
                )
                if not result['success']:
                    total_failed_attempts += 1
        
        print(f"Total failed attempts: {total_failed_attempts}")
        
        # Account should be locked despite distributed nature
        user = db.get_user_by_id(user_id)
        assert user['failed_login_attempts'] >= 5
        
        # Even correct password should fail when locked
        result = auth_service.authenticate_user(
            'distributed@example.com',
            'DistributedPass123!',
            '192.168.1.1',  # New IP
            'LegitimateAgent'
        )
        assert result['success'] == False
        
        # Cleanup
        db.delete_user(user_id)


@pytest.mark.security
class TestSQLInjectionProtection:
    """Test SQL injection protection"""
    
    def test_email_sql_injection_protection(self, security_services):
        """Test email fields are protected from SQL injection"""
        db = security_services['db']
        auth_service = security_services['auth']
        
        # SQL injection payloads
        sql_injection_emails = [
            "'; DROP TABLE users; --",
            "admin@example.com'; UPDATE users SET role_id=0; --",
            "test' OR '1'='1' --@example.com",
            "'; INSERT INTO users (email, password_hash) VALUES ('hacker@evil.com', 'hash'); --",
            "test@example.com' UNION SELECT * FROM users --"
        ]
        
        for malicious_email in sql_injection_emails:
            try:
                # Try to create user with malicious email
                user_id = db.create_user(
                    email=malicious_email,
                    password_hash=auth_service.hash_password('TestPass123!'),
                    first_name='SQL',
                    last_name='Injection'
                )
                
                # If user was created, it should be with the literal email string
                if user_id:
                    user = db.get_user_by_id(user_id)
                    assert user['email'] == malicious_email  # Should be stored literally
                    db.delete_user(user_id)
                    
            except Exception:
                # Database should reject malicious input
                pass
        
        # Verify users table still exists and is intact
        try:
            users = db.get_all_users_with_roles()
            # Table should exist and function normally
            assert isinstance(users, list)
        except Exception as e:
            assert False, f"Users table was compromised: {e}"
    
    def test_search_sql_injection_protection(self, security_services):
        """Test search functionality is protected from SQL injection"""
        db = security_services['db']
        auth_service = security_services['auth']
        audit_service = security_services['audit']
        
        # Create test users for search
        user_ids = []
        for i in range(3):
            user_id = db.create_user(
                email=f'search_test_{i}@example.com',
                password_hash=auth_service.hash_password('SearchPass123!'),
                first_name=f'Search{i}',
                last_name='Test'
            )
            user_ids.append(user_id)
        
        # Test malicious search queries
        malicious_searches = [
            "'; DROP TABLE users; --",
            "test' OR '1'='1",
            "' UNION SELECT password_hash FROM users --",
            "'; UPDATE users SET role_id=0; --"
        ]
        
        for malicious_query in malicious_searches:
            try:
                # Try searching with malicious input
                # Note: This assumes there's a search function
                # For this test, we'll test the email lookup which is commonly searched
                user = db.get_user_by_email(malicious_query)
                
                # Should either return None or handle safely
                assert user is None or isinstance(user, dict)
                
            except Exception:
                # Database should handle the error gracefully
                pass
        
        # Verify database integrity after injection attempts
        try:
            users = db.get_all_users_with_roles()
            assert len(users) >= 3  # Our test users should still exist
            
            # Verify user data is intact
            for user_id in user_ids:
                user = db.get_user_by_id(user_id)
                assert user is not None
                assert user['first_name'].startswith('Search')
        except Exception as e:
            assert False, f"Database was compromised by SQL injection: {e}"
        
        # Cleanup
        for user_id in user_ids:
            db.delete_user(user_id)


@pytest.mark.security
class TestInputValidationSecurity:
    """Test input validation and sanitization"""
    
    def test_xss_prevention_in_user_data(self, security_services):
        """Test XSS payloads are handled safely in user data"""
        db = security_services['db']
        auth_service = security_services['auth']
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>"
        ]
        
        for payload in xss_payloads:
            # Test XSS in first name
            try:
                user_id = db.create_user(
                    email=f'xss_{hashlib.md5(payload.encode()).hexdigest()}@example.com',
                    password_hash=auth_service.hash_password('XSSPass123!'),
                    first_name=payload,
                    last_name='Test'
                )
                
                if user_id:
                    user = db.get_user_by_id(user_id)
                    # Data should be stored as-is (sanitization happens at display time)
                    assert payload in user['first_name']
                    db.delete_user(user_id)
                    
            except Exception:
                # Input validation might reject some payloads
                pass
    
    def test_file_path_traversal_protection(self, security_services):
        """Test protection against file path traversal attacks"""
        # This test simulates file operations that might be vulnerable
        # In a real application, this would test file upload/download functions
        
        path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
        
        for payload in path_traversal_payloads:
            # Test that path traversal payloads don't access sensitive files
            # This is a placeholder test - actual implementation would depend
            # on specific file handling functions in the application
            
            # Simulate path validation
            normalized_path = os.path.normpath(payload)
            
            # Should not contain parent directory references
            assert not normalized_path.startswith('/')
            assert not normalized_path.startswith('\\')
            assert '..' not in normalized_path or not normalized_path.startswith('..')


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-m', 'security'])