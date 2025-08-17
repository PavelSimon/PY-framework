import os
import secrets
from pydantic_settings import BaseSettings
from pydantic import EmailStr, field_validator, ConfigDict
from typing import Optional, List


class Settings(BaseSettings):
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding='utf-8'
    )
    
    app_name: str = "PY-Framework"
    debug: bool = False
    secret_key: str = secrets.token_urlsafe(32)
    
    database_url: str = "app.db"
    
    session_expire_hours: int = 24
    
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None
    google_redirect_uri: str = "http://localhost:8000/auth/oauth/google/callback"
    
    github_client_id: Optional[str] = None
    github_client_secret: Optional[str] = None
    github_redirect_uri: str = "http://localhost:8000/auth/oauth/github/callback"
    
    smtp_server: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    
    from_email: Optional[EmailStr] = None
    
    max_failed_login_attempts: int = 5
    account_lockout_duration_minutes: int = 30
    
    rate_limit_requests: int = 100
    rate_limit_window_minutes: int = 15
    
    password_reset_expire_hours: int = 1
    email_verification_expire_hours: int = 24
    
    cors_origins: str = "http://localhost:3000,http://localhost:8000"
    
    audit_log_file: Optional[str] = "logs/audit.log"
    audit_retention_days: int = 90
    
    # Performance settings
    enable_performance_optimization: bool = True
    cache_default_ttl_seconds: int = 300  # 5 minutes
    cache_max_size: int = 1000
    session_cache_max_sessions: int = 1000
    session_cache_cleanup_interval_seconds: int = 3600  # 1 hour
    connection_pool_max_connections: int = 10
    query_slow_threshold_ms: float = 100.0
    enable_query_optimization: bool = True
    enable_connection_pooling: bool = True
    
    @field_validator('secret_key')
    @classmethod
    def validate_secret_key(cls, v):
        if len(v) < 32:
            raise ValueError('Secret key must be at least 32 characters long')
        return v
    
    @field_validator('cors_origins')
    @classmethod
    def validate_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(',') if origin.strip()]
        return v
    
    def is_oauth_configured(self, provider: str) -> bool:
        """Check if OAuth provider is properly configured"""
        if provider == "google":
            return bool(self.google_client_id and self.google_client_secret)
        elif provider == "github":
            return bool(self.github_client_id and self.github_client_secret)
        return False
    
    def get_oauth_providers(self) -> List[str]:
        """Get list of configured OAuth providers"""
        providers = []
        if self.is_oauth_configured("google"):
            providers.append("google")
        if self.is_oauth_configured("github"):
            providers.append("github")
        return providers


def get_settings() -> Settings:
    return Settings()


settings = get_settings()