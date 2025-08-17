#!/usr/bin/env python3
"""
Script to forcefully make a user an admin by handling foreign key constraints
Usage: python force_admin.py <email>
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def force_make_admin(email: str):
    try:
        from framework.database import Database
        
        # Connect to database
        db = Database()
        print("SUCCESS: Connected to database")
        
        # Check if user exists
        user = db.get_user_by_email(email)
        if not user:
            print(f"ERROR: User {email} not found")
            return False
        
        user_id = user['id']
        print(f"SUCCESS: Found user: {email} (ID: {user_id})")
        
        # Get current role information
        user_with_role = db.get_user_with_role(user_id)
        if user_with_role and user_with_role["role_id"] == 0:
            print("SUCCESS: User is already an admin!")
            return True
        
        print("Attempting to make user admin...")
        print("This will clear any existing sessions and tokens for this user.")
        
        # Method 1: Try direct update first
        try:
            success = db.update_user_role(user_id, 0)
            if success:
                print("SUCCESS: Direct role update worked!")
                return True
        except Exception as e:
            print(f"Direct update failed: {e}")
            print("Trying alternative approach...")
        
        # Method 2: Clear foreign key references and then update
        try:
            print("Clearing user sessions...")
            db.conn.execute("DELETE FROM sessions WHERE user_id = ?", [user_id])
            
            print("Clearing email verification tokens...")
            db.conn.execute("DELETE FROM email_verification_tokens WHERE user_id = ?", [user_id])
            
            print("Clearing password reset tokens...")
            db.conn.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", [user_id])
            
            print("Clearing OAuth accounts...")
            db.conn.execute("DELETE FROM oauth_accounts WHERE user_id = ?", [user_id])
            
            print("Clearing TOTP secrets...")
            db.conn.execute("DELETE FROM totp_secrets WHERE user_id = ?", [user_id])
            
            print("Clearing backup codes...")
            db.conn.execute("DELETE FROM backup_codes WHERE user_id = ?", [user_id])
            
            print("Clearing two-factor tokens...")
            db.conn.execute("DELETE FROM two_factor_tokens WHERE user_id = ?", [user_id])
            
            # Now try to update the role
            print("Attempting role update after cleanup...")
            success = db.update_user_role(user_id, 0)
            
            if success:
                print("SUCCESS: Role updated after clearing references!")
                return True
            else:
                print("ERROR: Role update still failed")
                return False
                
        except Exception as cleanup_error:
            print(f"Cleanup method failed: {cleanup_error}")
        
        # Method 3: Direct SQL update with foreign key check disabled
        try:
            print("Trying direct SQL update...")
            
            # Note: DuckDB doesn't support PRAGMA like SQLite, so we'll use a different approach
            db.conn.execute("UPDATE users SET role_id = 0 WHERE id = ?", [user_id])
            
            # Verify the update worked
            cursor = db.conn.execute("SELECT role_id FROM users WHERE id = ?", [user_id])
            row = cursor.fetchone()
            
            if row and row[0] == 0:
                print("SUCCESS: Direct SQL update worked!")
                return True
            else:
                print("ERROR: Direct SQL update failed")
                return False
                
        except Exception as sql_error:
            print(f"Direct SQL method failed: {sql_error}")
        
        print("ERROR: All methods failed")
        return False
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if 'db' in locals() and hasattr(db, '_conn') and db._conn:
            try:
                db._conn.close()
            except:
                pass

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python force_admin.py <email>")
        print("Example: python force_admin.py pavel@pavel-simon.com")
        sys.exit(1)
    
    email = sys.argv[1]
    print(f"Forcefully making {email} an admin...")
    print("WARNING: This will clear sessions and tokens for this user!")
    print("=" * 60)
    
    success = force_make_admin(email)
    
    print("=" * 60)
    if success:
        print(f"SUCCESS: {email} is now an admin!")
        print("\nNote: The user's sessions and tokens were cleared.")
        print("They will need to log in again to access admin features.")
        print("\nAdmin features:")
        print("- User management at /users")
        print("- Audit logs at /admin/audit")
    else:
        print(f"FAILED: Could not make {email} an admin")
        print("\nThis could be due to:")
        print("- Database corruption")
        print("- Missing foreign key constraints")
        print("- Database locked by another process")
    
    sys.exit(0 if success else 1)