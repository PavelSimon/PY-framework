import logging
import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from pathlib import Path

from .models import AuditEvent, AuditEventType
from ..database.database import Database


class AuditService:
    """Comprehensive audit logging service for security events and user actions"""
    
    def __init__(self, database: Database, log_file_path: Optional[str] = None):
        self.db = database
        self.logger = self._setup_logger(log_file_path)
        self._init_audit_tables()
    
    def _setup_logger(self, log_file_path: Optional[str] = None) -> logging.Logger:
        """Set up audit logger with file and console handlers"""
        logger = logging.getLogger('audit')
        logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Console handler for development
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter(
            '%(asctime)s - AUDIT - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
        
        # File handler for persistent logging
        if log_file_path:
            log_path = Path(log_file_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_path)
            file_handler.setLevel(logging.INFO)
            file_format = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_format)
            logger.addHandler(file_handler)
        
        return logger
    
    def _init_audit_tables(self):
        """Initialize audit tables in database"""
        try:
            # Create sequence for audit events
            self.db.conn.execute("CREATE SEQUENCE IF NOT EXISTS audit_event_id_seq START 1;")
            
            # Create audit_events table (no foreign key to allow user deletion)
            self.db.conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY DEFAULT nextval('audit_event_id_seq'),
                    event_type VARCHAR NOT NULL,
                    user_id INTEGER,
                    ip_address VARCHAR,
                    user_agent VARCHAR,
                    session_id VARCHAR,
                    details VARCHAR,
                    success BOOLEAN NOT NULL,
                    timestamp TIMESTAMP NOT NULL
                )
            """)
            
            # Migration: Drop foreign key constraint if it exists (for user deletion support)
            try:
                # Try to drop the foreign key constraint - this will fail silently if it doesn't exist
                self.db.conn.execute("ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_user_id_fkey")
            except Exception:
                # Ignore errors - constraint might not exist
                pass
            
            # Create indexes for performance
            self.db.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_events_user_id ON audit_events(user_id);
            """)
            
            self.db.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
            """)
            
            self.db.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);
            """)
            
            self.db.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_events_ip ON audit_events(ip_address);
            """)
            
        except Exception as e:
            self.logger.error(f"Failed to initialize audit tables: {e}")
    
    def log_event(self, event: AuditEvent):
        """Log an audit event to both database and log file"""
        try:
            # Log to database
            details_json = json.dumps(event.details) if event.details else None
            
            self.db.conn.execute("""
                INSERT INTO audit_events 
                (event_type, user_id, ip_address, user_agent, session_id, details, success, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                event.event_type.value,
                event.user_id,
                event.ip_address,
                event.user_agent,
                event.session_id,
                details_json,
                event.success,
                event.timestamp
            ])
            
            # Log to file/console
            log_level = logging.INFO if event.success else logging.WARNING
            self.logger.log(log_level, str(event))
            
            # Additional details if available
            if event.details:
                self.logger.log(log_level, f"Details: {json.dumps(event.details)}")
            
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}")
    
    def log_authentication_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[int] = None,
        email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log authentication-related events"""
        audit_details = details or {}
        if email:
            audit_details['email'] = email
        
        event = AuditEvent(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            success=success,
            details=audit_details
        )
        self.log_event(event)
    
    def log_security_event(
        self,
        event_type: AuditEventType,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log security-related events"""
        event = AuditEvent(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,  # Security events are typically failures
            details=details
        )
        self.log_event(event)
    
    def log_admin_event(
        self,
        event_type: AuditEventType,
        admin_user_id: int,
        target_user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log admin actions"""
        audit_details = details or {}
        if target_user_id:
            audit_details['target_user_id'] = target_user_id
        
        event = AuditEvent(
            event_type=event_type,
            user_id=admin_user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            details=audit_details
        )
        self.log_event(event)
    
    def get_user_activity(
        self,
        user_id: int,
        limit: int = 50,
        event_types: Optional[List[AuditEventType]] = None
    ) -> List[Dict[str, Any]]:
        """Get recent activity for a specific user"""
        try:
            query = """
                SELECT event_type, ip_address, user_agent, session_id, 
                       details, success, timestamp
                FROM audit_events
                WHERE user_id = ?
            """
            params = [user_id]
            
            if event_types:
                placeholders = ','.join('?' * len(event_types))
                query += f" AND event_type IN ({placeholders})"
                params.extend([et.value for et in event_types])
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor = self.db.conn.execute(query, params)
            rows = cursor.fetchall()
            
            return [
                {
                    'event_type': row[0],
                    'ip_address': row[1],
                    'user_agent': row[2],
                    'session_id': row[3],
                    'details': json.loads(row[4]) if row[4] else {},
                    'success': row[5],
                    'timestamp': row[6]
                }
                for row in rows
            ]
            
        except Exception as e:
            self.logger.error(f"Failed to get user activity: {e}")
            return []
    
    def get_security_events(
        self,
        hours: int = 24,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get recent security events"""
        try:
            since = datetime.now() - timedelta(hours=hours)
            
            security_events = [
                AuditEventType.CSRF_TOKEN_VALIDATION_FAILED,
                AuditEventType.RATE_LIMIT_EXCEEDED,
                AuditEventType.INVALID_SESSION_ACCESS,
                AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
                AuditEventType.SUSPICIOUS_LOGIN_ACTIVITY,
                AuditEventType.USER_LOGIN_FAILED,
                AuditEventType.OAUTH_STATE_VALIDATION_FAILED,
                AuditEventType.TWO_FA_VERIFICATION_FAILED
            ]
            
            placeholders = ','.join('?' * len(security_events))
            query = f"""
                SELECT event_type, user_id, ip_address, user_agent, 
                       details, timestamp
                FROM audit_events
                WHERE event_type IN ({placeholders})
                AND timestamp >= ?
                AND success = FALSE
                ORDER BY timestamp DESC
                LIMIT ?
            """
            
            params = [et.value for et in security_events] + [since, limit]
            cursor = self.db.conn.execute(query, params)
            rows = cursor.fetchall()
            
            return [
                {
                    'event_type': row[0],
                    'user_id': row[1],
                    'ip_address': row[2],
                    'user_agent': row[3],
                    'details': json.loads(row[4]) if row[4] else {},
                    'timestamp': row[5]
                }
                for row in rows
            ]
            
        except Exception as e:
            self.logger.error(f"Failed to get security events: {e}")
            return []
    
    def get_login_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get login statistics for the specified period"""
        try:
            since = datetime.now() - timedelta(days=days)
            
            # Total login attempts
            cursor = self.db.conn.execute("""
                SELECT COUNT(*) FROM audit_events
                WHERE event_type = ? AND timestamp >= ?
            """, [AuditEventType.USER_LOGIN_SUCCESS.value, since])
            successful_logins = cursor.fetchone()[0]
            
            cursor = self.db.conn.execute("""
                SELECT COUNT(*) FROM audit_events
                WHERE event_type = ? AND timestamp >= ?
            """, [AuditEventType.USER_LOGIN_FAILED.value, since])
            failed_logins = cursor.fetchone()[0]
            
            # Unique users (from all login attempts including OAuth)
            cursor = self.db.conn.execute("""
                SELECT COUNT(DISTINCT user_id) FROM audit_events
                WHERE event_type IN (?, ?) AND timestamp >= ? AND user_id IS NOT NULL
            """, [AuditEventType.USER_LOGIN_SUCCESS.value, AuditEventType.OAUTH_LOGIN_SUCCESS.value, since])
            unique_users = cursor.fetchone()[0]
            
            # OAuth logins
            cursor = self.db.conn.execute("""
                SELECT COUNT(*) FROM audit_events
                WHERE event_type = ? AND timestamp >= ?
            """, [AuditEventType.OAUTH_LOGIN_SUCCESS.value, since])
            oauth_logins = cursor.fetchone()[0]
            
            return {
                'period_days': days,
                'successful_logins': successful_logins,
                'failed_logins': failed_logins,
                'unique_users': unique_users,
                'oauth_logins': oauth_logins,
                'total_attempts': successful_logins + failed_logins,
                'success_rate': (successful_logins / (successful_logins + failed_logins) * 100) if (successful_logins + failed_logins) > 0 else 0
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get login statistics: {e}")
            return {}
    
    def cleanup_old_events(self, days: int = 90):
        """Clean up audit events older than specified days"""
        try:
            cutoff = datetime.now() - timedelta(days=days)
            
            # First count the records to be deleted
            cursor = self.db.conn.execute("""
                SELECT COUNT(*) FROM audit_events WHERE timestamp < ?
            """, [cutoff])
            count_to_delete = cursor.fetchone()[0]
            
            # Delete the records
            self.db.conn.execute("""
                DELETE FROM audit_events WHERE timestamp < ?
            """, [cutoff])
            
            self.logger.info(f"Cleaned up {count_to_delete} audit events older than {days} days")
            
            return count_to_delete
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old audit events: {e}")
            return 0