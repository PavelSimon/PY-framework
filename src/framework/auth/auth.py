import secrets
import hashlib
import warnings
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, field_validator
import re

# Suppress BCrypt version warnings
warnings.filterwarnings("ignore", message=".*bcrypt.*", category=UserWarning)


class UserRegistration(BaseModel):
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class AuthenticationService:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.algorithm = "HS256"
        
        # Create BCrypt context with error suppression
        import sys
        from contextlib import redirect_stderr
        from io import StringIO
        
        stderr_buffer = StringIO()
        with redirect_stderr(stderr_buffer):
            self.pwd_context = CryptContext(
                schemes=["bcrypt"], 
                deprecated="auto",
                bcrypt__rounds=12
            )
        
        self.session_expire_hours = 24
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 30

    def hash_password(self, password: str) -> str:
        from contextlib import redirect_stderr
        from io import StringIO
        
        stderr_buffer = StringIO()
        with redirect_stderr(stderr_buffer):
            return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        from contextlib import redirect_stderr
        from io import StringIO
        
        stderr_buffer = StringIO()
        with redirect_stderr(stderr_buffer):
            return self.pwd_context.verify(plain_password, hashed_password)

    def generate_session_token(self) -> str:
        return secrets.token_urlsafe(32)

    def generate_verification_token(self) -> str:
        return secrets.token_urlsafe(32)

    def generate_csrf_token(self) -> str:
        return secrets.token_urlsafe(32)

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(hours=self.session_expire_hours)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def verify_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError:
            return None

    def authenticate_user(self, db, email: str, password: str, ip_address: str = None) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        user = db.get_user_by_email(email)
        if not user:
            return False, None, "Invalid email or password"
        
        if not user["is_active"]:
            return False, None, "Account is deactivated"
        
        if user["locked_until"] and user["locked_until"] > datetime.now():
            return False, None, f"Account is locked due to too many failed attempts. Try again later."
        
        if not self.verify_password(password, user["password_hash"]):
            failed_attempts = db.increment_failed_login(user["id"], self.lockout_duration_minutes)
            if failed_attempts >= self.max_failed_attempts:
                return False, None, f"Account locked due to {self.max_failed_attempts} failed attempts. Try again in {self.lockout_duration_minutes} minutes."
            return False, None, "Invalid email or password"
        
        db.update_user_login(user["id"], reset_failed_attempts=True)
        return True, user, "Login successful"

    def register_user(self, db, registration: UserRegistration) -> Tuple[bool, Optional[int], str]:
        existing_user = db.get_user_by_email(registration.email)
        if existing_user:
            return False, None, "Email already registered"
        
        try:
            password_hash = self.hash_password(registration.password)
            user_id = db.create_user(
                email=registration.email,
                password_hash=password_hash,
                first_name=registration.first_name,
                last_name=registration.last_name
            )
            return True, user_id, "User registered successfully"
        except Exception as e:
            return False, None, f"Registration failed: {str(e)}"

    def create_session(self, db, user_id: int, ip_address: str = None, user_agent: str = None) -> str:
        session_id = self.generate_session_token()
        expires_at = datetime.now() + timedelta(hours=self.session_expire_hours)
        
        db.create_session(
            session_id=session_id,
            user_id=user_id,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent
        )
        return session_id

    def validate_session(self, db, session_id: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        if not session_id:
            return False, None
        
        session = db.get_session(session_id)
        if not session:
            return False, None
        
        if session["expires_at"] < datetime.now():
            db.invalidate_session(session_id)
            return False, None
        
        if not session["is_active"] or not session["user_active"]:
            return False, None
        
        return True, session

    def logout_user(self, db, session_id: str):
        if session_id:
            db.invalidate_session(session_id)

    def get_user_from_session(self, db, session_id: str) -> Optional[Dict[str, Any]]:
        """Get user data from a valid session"""
        is_valid, session = self.validate_session(db, session_id)
        if not is_valid or not session:
            return None
        
        # Get full user data
        user = db.get_user_by_id(session['user_id'])
        return user

    def cleanup_expired_sessions(self, db):
        db.cleanup_expired_sessions()

    def generate_password_strength_score(self, password: str) -> Tuple[int, list]:
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters long")
        
        if len(password) >= 12:
            score += 1
        else:
            feedback.append("Consider using 12+ characters for better security")
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        common_patterns = ['password', '123456', 'qwerty', 'abc123']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 2
            feedback.append("Avoid common patterns")
        
        return max(0, score), feedback


class RateLimiter:
    def __init__(self):
        self.attempts = {}
        self.max_attempts = 5
        self.window_minutes = 15

    def is_rate_limited(self, identifier: str) -> bool:
        now = datetime.now()
        if identifier not in self.attempts:
            self.attempts[identifier] = []
        
        self.attempts[identifier] = [
            attempt for attempt in self.attempts[identifier]
            if now - attempt < timedelta(minutes=self.window_minutes)
        ]
        
        if len(self.attempts[identifier]) >= self.max_attempts:
            return True
        
        self.attempts[identifier].append(now)
        return False