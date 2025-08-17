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
        self._conn.execute("CREATE SEQUENCE IF NOT EXISTS role_id_seq START 1;")
        
        # Create roles table first
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY DEFAULT nextval('role_id_seq'),
                name VARCHAR UNIQUE NOT NULL,
                description VARCHAR,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Insert default roles if they don't exist
        self._conn.execute("""
            INSERT INTO roles (id, name, description) 
            SELECT 0, 'admin', 'Administrator with full access'
            WHERE NOT EXISTS (SELECT 1 FROM roles WHERE id = 0)
        """)
        
        self._conn.execute("""
            INSERT INTO roles (id, name, description) 
            SELECT 1, 'user', 'Regular user with limited access'
            WHERE NOT EXISTS (SELECT 1 FROM roles WHERE id = 1)
        """)
        
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY DEFAULT nextval('user_id_seq'),
                email VARCHAR UNIQUE NOT NULL,
                password_hash VARCHAR NOT NULL,
                first_name VARCHAR,
                last_name VARCHAR,
                role_id INTEGER DEFAULT 1,
                is_active BOOLEAN DEFAULT TRUE,
                is_verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                FOREIGN KEY (role_id) REFERENCES roles(id)
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
            CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);
        """)
        
        # Migration: Add role_id column to existing users if not exists
        try:
            # Check if role_id column exists by trying to select it
            self._conn.execute("SELECT role_id FROM users LIMIT 1")
            print("role_id column already exists")
        except Exception as e:
            print(f"role_id column missing, attempting migration: {e}")
            try:
                # Column doesn't exist, add it
                self._conn.execute("ALTER TABLE users ADD COLUMN role_id INTEGER DEFAULT 1")
                print("✅ Successfully added role_id column to users table")
                
                # Update existing users to have the default role
                self._conn.execute("UPDATE users SET role_id = 1 WHERE role_id IS NULL")
                print("✅ Updated existing users with default role")
                
            except Exception as migration_error:
                print(f"❌ Migration failed: {migration_error}")
                print("⚠️  Database schema migration required!")
                print("To fix: Stop the server, delete app.db, and restart to recreate with correct schema")
                # Continue execution - the error will surface when trying to use role features
        
        # Ensure Pavel@pavel-simon.com is admin (role_id = 0)
        self._conn.execute("""
            UPDATE users 
            SET role_id = 0 
            WHERE email = 'Pavel@pavel-simon.com' AND role_id != 0
        """)
        
        # Ensure all other users are regular users (role_id = 1)
        self._conn.execute("""
            UPDATE users 
            SET role_id = 1 
            WHERE email != 'Pavel@pavel-simon.com' AND role_id != 1
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

    def get_user_with_role(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user information including role details"""
        try:
            cursor = self.conn.execute("""
                SELECT u.id, u.email, u.password_hash, u.first_name, u.last_name,
                       u.is_active, u.is_verified, u.created_at, u.updated_at, 
                       u.last_login, u.failed_login_attempts, u.locked_until,
                       u.role_id, r.name as role_name, r.description as role_description
                FROM users u
                LEFT JOIN roles r ON u.role_id = r.id
                WHERE u.id = ?
            """, [user_id])
            row = cursor.fetchone()
            if row:
                return {
                    "id": row[0], "email": row[1], "password_hash": row[2],
                    "first_name": row[3], "last_name": row[4], "is_active": row[5],
                    "is_verified": row[6], "created_at": row[7], "updated_at": row[8],
                    "last_login": row[9], "failed_login_attempts": row[10], 
                    "locked_until": row[11], "role_id": row[12], 
                    "role_name": row[13], "role_description": row[14]
                }
        except Exception as e:
            print(f"Error in get_user_with_role: {e}")
            # Fallback to basic user info without role
            try:
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
                        "last_login": row[9], "failed_login_attempts": row[10], 
                        "locked_until": row[11], "role_id": 1,  # Default to regular user
                        "role_name": "user", "role_description": "Regular user"
                    }
            except Exception as fallback_error:
                print(f"Fallback query also failed: {fallback_error}")
        return None

    def get_all_users_with_roles(self) -> list:
        """Get all users with their role information"""
        try:
            cursor = self.conn.execute("""
                SELECT u.id, u.email, u.first_name, u.last_name,
                       u.is_active, u.is_verified, u.created_at, u.last_login,
                       u.role_id, r.name as role_name
                FROM users u
                LEFT JOIN roles r ON u.role_id = r.id
                ORDER BY u.created_at DESC
            """)
            rows = cursor.fetchall()
            return [
                {
                    "id": row[0], "email": row[1], "first_name": row[2], 
                    "last_name": row[3], "is_active": row[4], "is_verified": row[5],
                    "created_at": row[6], "last_login": row[7], "role_id": row[8],
                    "role_name": row[9]
                }
                for row in rows
            ]
        except Exception as e:
            print(f"Error in get_all_users_with_roles: {e}")
            # Fallback to basic user info without roles
            try:
                cursor = self.conn.execute("""
                    SELECT id, email, first_name, last_name,
                           is_active, is_verified, created_at, last_login
                    FROM users
                    ORDER BY created_at DESC
                """)
                rows = cursor.fetchall()
                return [
                    {
                        "id": row[0], "email": row[1], "first_name": row[2], 
                        "last_name": row[3], "is_active": row[4], "is_verified": row[5],
                        "created_at": row[6], "last_login": row[7], "role_id": 1,
                        "role_name": "user"
                    }
                    for row in rows
                ]
            except Exception as fallback_error:
                print(f"Fallback query also failed: {fallback_error}")
                return []

    def get_role(self, role_id: int) -> Optional[Dict[str, Any]]:
        """Get role information by ID"""
        cursor = self.conn.execute("""
            SELECT id, name, description, created_at
            FROM roles
            WHERE id = ?
        """, [role_id])
        row = cursor.fetchone()
        if row:
            return {
                "id": row[0], "name": row[1], 
                "description": row[2], "created_at": row[3]
            }
        return None

    def is_admin(self, user_id: int) -> bool:
        """Check if user is an admin (role_id = 0)"""
        cursor = self.conn.execute("""
            SELECT role_id FROM users WHERE id = ?
        """, [user_id])
        row = cursor.fetchone()
        return row and row[0] == 0

    def update_user_role(self, user_id: int, role_id: int) -> bool:
        """Update user's role"""
        try:
            self.conn.execute("""
                UPDATE users 
                SET role_id = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, [role_id, user_id])
            return True
        except Exception as e:
            print(f"Error updating user role: {e}")
            return False

    def close(self):
        if self.conn:
            self.conn.close()