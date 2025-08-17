from typing import Optional
from .audit_service import AuditService
from ..database.database import Database
from ..config import settings


class AuditManager:
    """Singleton audit manager for centralized audit logging"""
    
    _instance: Optional[AuditService] = None
    
    @classmethod
    def get_instance(cls, database: Optional[Database] = None) -> AuditService:
        """Get or create audit service instance"""
        if cls._instance is None:
            if database is None:
                raise ValueError("Database instance required for first initialization")
            
            cls._instance = AuditService(
                database=database,
                log_file_path=settings.audit_log_file
            )
        
        return cls._instance
    
    @classmethod
    def reset_instance(cls):
        """Reset instance for testing"""
        cls._instance = None


# Convenience functions for common audit operations
def get_audit_service(database: Optional[Database] = None) -> AuditService:
    """Get the audit service instance"""
    return AuditManager.get_instance(database)


def log_auth_event(audit_service: AuditService, **kwargs):
    """Convenience function for logging authentication events"""
    audit_service.log_authentication_event(**kwargs)


def log_security_event(audit_service: AuditService, **kwargs):
    """Convenience function for logging security events"""
    audit_service.log_security_event(**kwargs)


def log_admin_event(audit_service: AuditService, **kwargs):
    """Convenience function for logging admin events"""
    audit_service.log_admin_event(**kwargs)