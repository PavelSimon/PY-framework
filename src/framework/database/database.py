import duckdb
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pathlib import Path


class Database:
    def __init__(self, db_path: str = "app.db"):
        self.db_path = db_path
        self._conn = None
        
    @property
    def conn(self):
        """Lazy initialization of database connection"""
        if self._conn is None:
            self._conn = duckdb.connect(self.db_path)
            self._init_schema()
        return self._conn
    
    def _init_schema(self):
        # Create sequences for auto-incrementing IDs
        self._conn.execute("CREATE SEQUENCE IF NOT EXISTS user_id_seq START 1;")
        self._conn.execute("CREATE SEQUENCE IF NOT EXISTS oauth_id_seq START 1;")
        self._conn.execute("CREATE SEQUENCE IF NOT EXISTS email_token_id_seq START 1;")
        self._conn.execute("CREATE SEQUENCE IF NOT EXISTS password_token_id_seq START 1;")
        
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY DEFAULT nextval('user_id_seq'),
                email VARCHAR UNIQUE NOT NULL,
                password_hash VARCHAR NOT NULL,
                first_name VARCHAR,
                last_name VARCHAR,
                is_active BOOLEAN DEFAULT TRUE,
                is_verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        """)
        
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS oauth_accounts (
                id INTEGER PRIMARY KEY DEFAULT nextval('oauth_id_seq'),
                user_id INTEGER NOT NULL,
                provider VARCHAR NOT NULL,
                provider_user_id VARCHAR NOT NULL,
                provider_email VARCHAR,
                access_token VARCHAR,
                refresh_token VARCHAR,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(provider, provider_user_id)
            )
        """)
        
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id VARCHAR PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR,
                user_agent VARCHAR,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS email_verification_tokens (
                id INTEGER PRIMARY KEY DEFAULT nextval('email_token_id_seq'),
                user_id INTEGER NOT NULL,
                token VARCHAR UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY DEFAULT nextval('password_token_id_seq'),
                user_id INTEGER NOT NULL,
                token VARCHAR UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        """)
        
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
        """)
        
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_oauth_provider_user ON oauth_accounts(provider, provider_user_id);
        """)

    def create_user(self, email: str, password_hash: str, first_name: str = None, last_name: str = None) -> int:
        cursor = self.conn.execute("""
            INSERT INTO users (email, password_hash, first_name, last_name)
            VALUES (?, ?, ?, ?)
            RETURNING id
        """, [email, password_hash, first_name, last_name])
        return cursor.fetchone()[0]

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        cursor = self.conn.execute("""
            SELECT id, email, password_hash, first_name, last_name, 
                   is_active, is_verified, created_at, updated_at, 
                   last_login, failed_login_attempts, locked_until
            FROM users WHERE email = ?
        """, [email])
        row = cursor.fetchone()
        if row:
            return {
                "id": row[0], "email": row[1], "password_hash": row[2],
                "first_name": row[3], "last_name": row[4], "is_active": row[5],
                "is_verified": row[6], "created_at": row[7], "updated_at": row[8],
                "last_login": row[9], "failed_login_attempts": row[10], "locked_until": row[11]
            }
        return None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        cursor = self.conn.execute("""
            SELECT id, email, password_hash, first_name, last_name, 
                   is_active, is_verified, created_at, updated_at, 
                   last_login, failed_login_attempts, locked_until
            FROM users WHERE id = ?
        """, [user_id])
        row = cursor.fetchone()
        if row:
            return {
                "id": row[0], "email": row[1], "password_hash": row[2],
                "first_name": row[3], "last_name": row[4], "is_active": row[5],
                "is_verified": row[6], "created_at": row[7], "updated_at": row[8],
                "last_login": row[9], "failed_login_attempts": row[10], "locked_until": row[11]
            }
        return None

    def update_user_login(self, user_id: int, reset_failed_attempts: bool = False):
        if reset_failed_attempts:
            self.conn.execute("""
                UPDATE users 
                SET last_login = CURRENT_TIMESTAMP, failed_login_attempts = 0, 
                    locked_until = NULL, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, [user_id])
        else:
            self.conn.execute("""
                UPDATE users 
                SET last_login = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, [user_id])

    def increment_failed_login(self, user_id: int, lock_duration_minutes: int = 30):
        # First get current attempts
        cursor = self.conn.execute("""
            SELECT failed_login_attempts FROM users WHERE id = ?
        """, [user_id])
        row = cursor.fetchone()
        current_attempts = row[0] if row else 0
        
        # Calculate new attempts
        new_attempts = current_attempts + 1
        
        # Update with proper DuckDB syntax
        if new_attempts >= 5:
            # Calculate lock time using Python since DuckDB INTERVAL syntax is tricky
            from datetime import datetime, timedelta
            lock_until = datetime.now() + timedelta(minutes=lock_duration_minutes)
            cursor = self.conn.execute("""
                UPDATE users 
                SET failed_login_attempts = ?,
                    locked_until = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, [new_attempts, lock_until, user_id])
        else:
            cursor = self.conn.execute("""
                UPDATE users 
                SET failed_login_attempts = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, [new_attempts, user_id])
        
        return new_attempts

    def verify_user_email(self, user_id: int):
        self.conn.execute("""
            UPDATE users 
            SET is_verified = TRUE, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, [user_id])

    def create_session(self, session_id: str, user_id: int, expires_at: datetime, 
                      ip_address: str = None, user_agent: str = None):
        self.conn.execute("""
            INSERT INTO sessions (id, user_id, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        """, [session_id, user_id, expires_at, ip_address, user_agent])

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        cursor = self.conn.execute("""
            SELECT s.id, s.user_id, s.expires_at, s.created_at, s.ip_address, 
                   s.user_agent, s.is_active, u.email, u.is_active as user_active
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = ? AND s.is_active = TRUE
        """, [session_id])
        row = cursor.fetchone()
        if row:
            return {
                "id": row[0], "user_id": row[1], "expires_at": row[2],
                "created_at": row[3], "ip_address": row[4], "user_agent": row[5],
                "is_active": row[6], "email": row[7], "user_active": row[8]
            }
        return None

    def invalidate_session(self, session_id: str):
        self.conn.execute("""
            UPDATE sessions SET is_active = FALSE WHERE id = ?
        """, [session_id])

    def cleanup_expired_sessions(self):
        self.conn.execute("""
            UPDATE sessions 
            SET is_active = FALSE 
            WHERE expires_at < CURRENT_TIMESTAMP AND is_active = TRUE
        """)

    def create_oauth_account(self, user_id: int, provider: str, provider_user_id: str,
                           provider_email: str = None, access_token: str = None,
                           refresh_token: str = None, expires_at: datetime = None):
        self.conn.execute("""
            INSERT INTO oauth_accounts 
            (user_id, provider, provider_user_id, provider_email, 
             access_token, refresh_token, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, [user_id, provider, provider_user_id, provider_email,
              access_token, refresh_token, expires_at])

    def get_oauth_account(self, provider: str, provider_user_id: str) -> Optional[Dict[str, Any]]:
        cursor = self.conn.execute("""
            SELECT user_id, provider, provider_user_id, provider_email
            FROM oauth_accounts 
            WHERE provider = ? AND provider_user_id = ?
        """, [provider, provider_user_id])
        row = cursor.fetchone()
        if row:
            return {
                "user_id": row[0], "provider": row[1], 
                "provider_user_id": row[2], "provider_email": row[3]
            }
        return None

    def close(self):
        if self.conn:
            self.conn.close()