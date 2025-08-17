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
                print("SUCCESS: Successfully added role_id column to users table")
                
                # Update existing users to have the default role
                self._conn.execute("UPDATE users SET role_id = 1 WHERE role_id IS NULL")
                print("SUCCESS: Updated existing users with default role")
                
            except Exception as migration_error:
                print(f"ERROR: Migration failed: {migration_error}")
                print("WARNING: Database schema migration required!")
                print("To fix: Stop the server, delete app.db, and restart to recreate with correct schema")
                # Continue execution - the error will surface when trying to use role features
        
        # Note: Automatic role assignment removed due to foreign key constraints
        # Use make_admin.py script or manual database update to assign admin roles
        
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
        """)
        
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_oauth_provider_user ON oauth_accounts(provider, provider_user_id);
        """)
        
        # Two-Factor Authentication tables
        self._conn.execute("CREATE SEQUENCE IF NOT EXISTS totp_id_seq START 1;")
        self._conn.execute("CREATE SEQUENCE IF NOT EXISTS backup_code_id_seq START 1;")
        self._conn.execute("CREATE SEQUENCE IF NOT EXISTS two_factor_token_id_seq START 1;")
        self._conn.execute("CREATE SEQUENCE IF NOT EXISTS oauth_state_id_seq START 1;")
        
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS totp_secrets (
                id INTEGER PRIMARY KEY DEFAULT nextval('totp_id_seq'),
                user_id INTEGER NOT NULL,
                secret VARCHAR NOT NULL,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(user_id)
            )
        """)
        
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS backup_codes (
                id INTEGER PRIMARY KEY DEFAULT nextval('backup_code_id_seq'),
                user_id INTEGER NOT NULL,
                code_hash VARCHAR NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS two_factor_tokens (
                id INTEGER PRIMARY KEY DEFAULT nextval('two_factor_token_id_seq'),
                user_id INTEGER NOT NULL,
                token VARCHAR UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_totp_user_id ON totp_secrets(user_id);
        """)
        
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_backup_codes_user_id ON backup_codes(user_id);
        """)
        
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_two_factor_tokens_token ON two_factor_tokens(token);
        """)
        
        # OAuth state tokens table
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS oauth_state_tokens (
                id INTEGER PRIMARY KEY DEFAULT nextval('oauth_state_id_seq'),
                state_token VARCHAR UNIQUE NOT NULL,
                provider VARCHAR NOT NULL,
                session_id VARCHAR,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_oauth_state_token ON oauth_state_tokens(state_token);
        """)
        
        # Migration: Add two_factor_enabled column to users table
        try:
            # Check if two_factor_enabled column exists
            self._conn.execute("SELECT two_factor_enabled FROM users LIMIT 1")
            print("two_factor_enabled column already exists")
        except Exception as e:
            print(f"two_factor_enabled column missing, attempting migration: {e}")
            try:
                # Column doesn't exist, add it
                self._conn.execute("ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN DEFAULT FALSE")
                print("SUCCESS: Successfully added two_factor_enabled column to users table")
                
                # Update existing users to have 2FA disabled by default
                self._conn.execute("UPDATE users SET two_factor_enabled = FALSE WHERE two_factor_enabled IS NULL")
                print("SUCCESS: Updated existing users with 2FA disabled by default")
                
            except Exception as migration_error:
                print(f"ERROR: 2FA Migration failed: {migration_error}")
                print("WARNING: Database schema migration required!")
                # Continue execution - the error will surface when trying to use 2FA features

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
            # First verify the role exists
            role_check = self.conn.execute("SELECT id FROM roles WHERE id = ?", [role_id]).fetchone()
            if not role_check:
                print(f"Error: Role ID {role_id} does not exist in roles table")
                return False
            
            # Verify the user exists
            user_check = self.conn.execute("SELECT id FROM users WHERE id = ?", [user_id]).fetchone()
            if not user_check:
                print(f"Error: User ID {user_id} does not exist")
                return False
            
            print(f"Updating user {user_id} to role {role_id}")
            
            # DuckDB workaround: Temporarily disable foreign key checks for this update
            # This is safe because we're only updating role_id, not the primary key
            try:
                # Disable foreign key checks
                self.conn.execute("SET foreign_key_checks = false")
                
                # Perform the update
                self.conn.execute("""
                    UPDATE users 
                    SET role_id = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, [role_id, user_id])
                
                # Re-enable foreign key checks
                self.conn.execute("SET foreign_key_checks = true")
                
            except Exception as fk_error:
                # If the SET commands don't work, try alternative method
                print(f"Foreign key commands failed: {fk_error}, trying alternative method")
                
                # Alternative approach: Use a more complex update that DuckDB might accept
                self.conn.execute("BEGIN TRANSACTION")
                try:
                    # Get current user data
                    current_user = self.conn.execute("""
                        SELECT email, password_hash, first_name, last_name, is_active, 
                               is_verified, created_at, last_login, failed_login_attempts, 
                               locked_until, two_factor_enabled
                        FROM users WHERE id = ?
                    """, [user_id]).fetchone()
                    
                    if not current_user:
                        raise Exception(f"User {user_id} not found for role update")
                    
                    # Update with all current values plus new role_id
                    self.conn.execute("""
                        UPDATE users 
                        SET role_id = ?,
                            updated_at = CURRENT_TIMESTAMP,
                            email = ?,
                            password_hash = ?,
                            first_name = ?,
                            last_name = ?,
                            is_active = ?,
                            is_verified = ?,
                            created_at = ?,
                            last_login = ?,
                            failed_login_attempts = ?,
                            locked_until = ?,
                            two_factor_enabled = ?
                        WHERE id = ?
                    """, [
                        role_id,
                        current_user[0],  # email
                        current_user[1],  # password_hash
                        current_user[2],  # first_name
                        current_user[3],  # last_name
                        current_user[4],  # is_active
                        current_user[5],  # is_verified
                        current_user[6],  # created_at
                        current_user[7],  # last_login
                        current_user[8],  # failed_login_attempts
                        current_user[9],  # locked_until
                        current_user[10], # two_factor_enabled
                        user_id
                    ])
                    
                    self.conn.execute("COMMIT")
                    print(f"Successfully used alternative update method for user {user_id}")
                    
                except Exception as alt_error:
                    self.conn.execute("ROLLBACK")
                    print(f"Alternative method also failed: {alt_error}")
                    
                    # Last resort: Create a new table without foreign key constraints, 
                    # transfer data, drop old table, rename new table
                    print("Attempting table recreation method...")
                    
                    try:
                        # Create temporary table without foreign key constraints
                        self.conn.execute("""
                            CREATE TABLE users_temp AS SELECT * FROM users
                        """)
                        
                        # Update the role in the temporary table
                        self.conn.execute("""
                            UPDATE users_temp 
                            SET role_id = ?, updated_at = CURRENT_TIMESTAMP
                            WHERE id = ?
                        """, [role_id, user_id])
                        
                        # Drop original table
                        self.conn.execute("DROP TABLE users")
                        
                        # Recreate users table with proper structure and constraints
                        self.conn.execute("""
                            CREATE TABLE users (
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
                                two_factor_enabled BOOLEAN DEFAULT FALSE,
                                FOREIGN KEY (role_id) REFERENCES roles(id)
                            )
                        """)
                        
                        # Copy data back from temp table
                        self.conn.execute("""
                            INSERT INTO users SELECT * FROM users_temp
                        """)
                        
                        # Drop temporary table
                        self.conn.execute("DROP TABLE users_temp")
                        
                        print("Successfully updated role using table recreation method")
                        
                    except Exception as table_error:
                        print(f"Table recreation method failed: {table_error}")
                        # Try to restore from temp table if it exists
                        try:
                            # Check if temp table exists
                            temp_check = self.conn.execute("""
                                SELECT name FROM sqlite_master 
                                WHERE type='table' AND name='users_temp'
                            """).fetchone()
                            
                            if temp_check:
                                print("Attempting to restore users table from temp table...")
                                self.conn.execute("""
                                    CREATE TABLE users (
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
                                        two_factor_enabled BOOLEAN DEFAULT FALSE,
                                        FOREIGN KEY (role_id) REFERENCES roles(id)
                                    )
                                """)
                                # Restore original data 
                                self.conn.execute("INSERT INTO users SELECT * FROM users_temp")
                                self.conn.execute("DROP TABLE users_temp")
                                print("Users table restored successfully")
                            
                        except Exception as restore_error:
                            print(f"Failed to restore users table: {restore_error}")
                            print("CRITICAL ERROR: Users table may be corrupted!")
                        
                        raise table_error
            
            # Verify the update worked
            updated_user = self.conn.execute("SELECT role_id FROM users WHERE id = ?", [user_id]).fetchone()
            if updated_user and updated_user[0] == role_id:
                print(f"Successfully updated user {user_id} to role {role_id}")
                return True
            else:
                print(f"Update verification failed for user {user_id}")
                return False
                
        except Exception as e:
            print(f"Error updating user role: {e}")
            return False

    def delete_user(self, user_id: int) -> bool:
        """Permanently delete a user and all associated data"""
        try:
            # First, let's find all tables and see what's referencing this user
            print(f"=== Investigating user_id {user_id} references ===")
            
            # Get all table names
            tables_result = self.conn.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'main' AND table_type = 'BASE TABLE'
            """)
            all_tables = [row[0] for row in tables_result.fetchall()]
            print(f"Found tables: {all_tables}")
            
            # Check each table for user_id references
            for table in all_tables:
                try:
                    # Check if table has user_id column
                    columns_result = self.conn.execute(f"""
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name = '{table}' AND column_name = 'user_id'
                    """)
                    if columns_result.fetchone():
                        # Count records for this user
                        count_result = self.conn.execute(f"SELECT COUNT(*) FROM {table} WHERE user_id = ?", [user_id])
                        count = count_result.fetchone()[0]
                        if count > 0:
                            print(f"Table {table} has {count} records for user_id {user_id}")
                        else:
                            print(f"Table {table} has user_id column but no records for user {user_id}")
                except Exception as e:
                    print(f"Could not check table {table}: {e}")
            
            # Check for any foreign key constraints pointing to this user
            try:
                # Get all foreign key constraints in the database
                fk_result = self.conn.execute("""
                    SELECT 
                        tc.constraint_name,
                        tc.table_name,
                        kcu.column_name,
                        ccu.table_name AS foreign_table_name,
                        ccu.column_name AS foreign_column_name
                    FROM 
                        information_schema.table_constraints AS tc 
                        JOIN information_schema.key_column_usage AS kcu
                            ON tc.constraint_name = kcu.constraint_name
                            AND tc.table_schema = kcu.table_schema
                        JOIN information_schema.constraint_column_usage AS ccu
                            ON ccu.constraint_name = tc.constraint_name
                            AND ccu.table_schema = tc.table_schema
                    WHERE tc.constraint_type = 'FOREIGN KEY'
                    AND ccu.table_name = 'users'
                    AND ccu.column_name = 'id'
                """)
                
                foreign_keys = fk_result.fetchall()
                if foreign_keys:
                    print(f"Found {len(foreign_keys)} foreign key constraints referencing users.id:")
                    for fk in foreign_keys:
                        print(f"  {fk[1]}.{fk[2]} -> {fk[3]}.{fk[4]} (constraint: {fk[0]})")
                else:
                    print("No foreign key constraints found referencing users.id")
                    
            except Exception as e:
                print(f"Could not check foreign key constraints: {e}")
            
            # Start transaction for atomicity
            self.conn.execute("BEGIN TRANSACTION")
            
            # Delete in correct order - using explicit table list
            tables_to_clean = [
                'audit_events',  # Clean audit events first (no foreign key constraints)
                'sessions',
                'email_verification_tokens', 
                'password_reset_tokens',
                'oauth_accounts',
                'totp_secrets',
                'backup_codes', 
                'two_factor_tokens'
            ]
            
            for table in tables_to_clean:
                try:
                    # Check if table exists first
                    table_check = self.conn.execute("""
                        SELECT COUNT(*) FROM information_schema.tables 
                        WHERE table_name = ?
                    """, [table])
                    
                    if table_check.fetchone()[0] == 0:
                        print(f"Table {table} does not exist, skipping...")
                        continue
                    
                    # Count first
                    count_result = self.conn.execute(f"SELECT COUNT(*) FROM {table} WHERE user_id = ?", [user_id])
                    count = count_result.fetchone()[0]
                    
                    # Delete
                    self.conn.execute(f"DELETE FROM {table} WHERE user_id = ?", [user_id])
                    print(f"Cleaned {table}: {count} records")
                    
                except Exception as e:
                    print(f"Error cleaning {table}: {e}")
            
            # Try to delete the user
            try:
                result = self.conn.execute("DELETE FROM users WHERE id = ?", [user_id])
                print(f"User deletion attempt completed")
                
                # Commit the transaction
                self.conn.execute("COMMIT")
                return True
                
            except Exception as delete_error:
                print(f"User deletion failed: {delete_error}")
                self.conn.execute("ROLLBACK")
                return False
            
        except Exception as e:
            print(f"Error deleting user: {e}")
            # Rollback on error
            try:
                self.conn.execute("ROLLBACK")
            except Exception as rollback_error:
                print(f"Error during rollback: {rollback_error}")
            return False

    def close(self):
        if self.conn:
            self.conn.close()