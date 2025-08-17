#!/usr/bin/env python3
"""
Development server for PY-Framework with hot reloading
Based on dev_no_reload.py but with reloading enabled
"""

import sys
import warnings
from pathlib import Path

# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", message=".*bcrypt.*")

sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import everything we need
from fasthtml.common import *
from src.framework.config import Settings
from src.framework.database import Database
from src.framework.auth import AuthenticationService
from src.framework.email import EmailService
from src.framework.csrf import CSRFProtection, add_csrf_middleware
from src.framework.security import add_security_middleware, create_security_config
from src.framework.routes import create_auth_routes, create_main_routes, create_dev_routes, create_2fa_routes, create_performance_routes, create_monitoring_routes
from src.framework.routes.audit_routes import create_audit_routes
from src.framework.audit import get_audit_service
from src.framework.performance_config import init_performance
from src.framework.database.optimized_database import OptimizedDatabase

def create_app():
    """Create and configure the FastHTML application"""
    settings = Settings(debug=True)
    
    # Create FastHTML app with development settings
    app = FastHTML(
        debug=True,     # Enable debug mode
        live=True,      # Enable live reload for HTML/CSS changes
        reload=False,   # Disable FastHTML's own reload (uvicorn will handle it)
        hdrs=[
            Meta(charset="utf-8"),
            Meta(name="viewport", content="width=device-width, initial-scale=1"),
            Link(rel="icon", type="image/x-icon", href="/static/favicon.ico"),
            Link(rel="stylesheet", href="/static/css/style.css"),
            Script(src="/static/js/htmx.min.js"),
        ]
    )
    
    # Initialize performance optimization
    if settings.enable_performance_optimization:
        perf_config = init_performance(settings)
        # Use optimized database if performance optimization is enabled
        db = OptimizedDatabase(settings.database_url, use_connection_pool=settings.enable_connection_pooling)
        print("SUCCESS: Performance optimization enabled")
    else:
        db = Database(settings.database_url)
        print("INFO: Performance optimization disabled")
    
    # Initialize services
    auth_service = AuthenticationService(settings.secret_key)
    email_service = EmailService()
    csrf_protection = CSRFProtection(settings.secret_key)
    
    # Add CSRF middleware
    add_csrf_middleware(app, csrf_protection)
    
    # Add enhanced security middleware (development settings)
    security_config = create_security_config(is_production=False)
    add_security_middleware(app, security_config)
    
    # Initialize audit service (creates tables if needed)
    try:
        audit_service = get_audit_service(db)
        print("SUCCESS: Audit service initialized")
    except Exception as e:
        print(f"WARNING: Audit service initialization failed: {e}")
    
    # Register route modules
    create_auth_routes(app, db, auth_service, email_service, csrf_protection)
    create_main_routes(app, db, auth_service, is_development=True, csrf_protection=csrf_protection)
    create_dev_routes(app, db, auth_service, email_service, settings, csrf_protection)
    create_2fa_routes(app, db, auth_service, csrf_protection)
    create_audit_routes(app, db, auth_service)
    
    # Register performance monitoring routes (development mode)
    if settings.enable_performance_optimization:
        create_performance_routes(app, db, auth_service, csrf_protection)
    
    # Register enhanced monitoring routes
    create_monitoring_routes(app, db, auth_service, csrf_protection)
    
    # Mount static files
    app.mount("/static", StaticFiles(directory="static"), name="static")
    
    print("Development server starting...")
    print(f"Database: {settings.database_url}")
    print("Server: http://localhost:8000")
    
    return app

# Create app instance at module level for uvicorn import
app = create_app()

if __name__ == "__main__":
    print("\n" + "="*50)
    print("PY-Framework Development Server (With Hot Reload)")
    print("="*50)
    print("Server: http://localhost:8000")
    print("Admin login: admin@admin.com / AdminPass123!")
    print("Pavel admin login: Pavel@pavel-simon.com / <your_password>")
    print("Audit dashboard: http://localhost:8000/admin/audit")
    print("Hot reloading: ENABLED")
    print("Press Ctrl+C to stop")
    print("="*50)
    print("Watching: src/ directory for changes")
    print("="*50 + "\n")
    
    # Use uvicorn with hot reloading enabled via import string
    import uvicorn
    uvicorn.run(
        "dev:app",                  # Import string - required for reload
        host="localhost", 
        port=8000, 
        reload=True,                # Enable hot reloading
        reload_dirs=["src"],        # Only watch src directory
        reload_excludes=["*.db", "*.log"],  # Exclude database and log files
        access_log=True,
        use_colors=True,
        log_level="info"
    )