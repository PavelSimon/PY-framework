#!/usr/bin/env python3
"""
Production server for PY-Framework
Optimized for production deployment with security and performance features
"""

import sys
import warnings
from pathlib import Path
from contextlib import redirect_stderr
from io import StringIO

# Suppress BCrypt version warnings and redirect stderr during imports
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", message=".*bcrypt.*")

sys.path.insert(0, str(Path(__file__).parent / "src"))

# Suppress stderr during imports to hide BCrypt version errors
stderr_buffer = StringIO()
with redirect_stderr(stderr_buffer):
    from fasthtml.common import *
    from src.framework.config import settings
    from src.framework.database import Database
    from src.framework.auth import AuthenticationService
    from src.framework.email import EmailService
    from src.framework.csrf import CSRFProtection, add_csrf_middleware
    from src.framework.security import add_security_middleware, create_security_config
    from src.framework.routes import create_auth_routes, create_main_routes, create_2fa_routes, create_performance_routes
    from src.framework.routes.audit_routes import create_audit_routes
    from src.framework.audit import get_audit_service
    from src.framework.performance_config import init_performance
    from src.framework.database.optimized_database import OptimizedDatabase

def create_production_app():
    app = FastHTML(
        debug=settings.debug,
        live=False,
        reload=False,
        hdrs=[
            Meta(charset="utf-8"),
            Meta(name="viewport", content="width=device-width, initial-scale=1"),
            Meta(name="description", content="Secure web application built with PY-Framework"),
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
        print("SUCCESS: Production performance optimization enabled")
    else:
        db = Database(settings.database_url)
        print("INFO: Production performance optimization disabled")
    
    # Initialize services
    auth_service = AuthenticationService(settings.secret_key)
    email_service = EmailService() if hasattr(settings, 'smtp_server') and settings.smtp_server else None
    csrf_protection = CSRFProtection(settings.secret_key)
    
    # Add CSRF middleware
    add_csrf_middleware(app, csrf_protection)
    
    # Add enhanced security middleware
    security_config = create_security_config(is_production=True)
    add_security_middleware(app, security_config)
    
    # Initialize audit service (creates tables if needed)
    try:
        audit_service = get_audit_service(db)
        print("SUCCESS: Audit service initialized")
    except Exception as e:
        print(f"WARNING: Audit service initialization failed: {e}")
    
    # Register route modules
    create_auth_routes(app, db, auth_service, email_service, csrf_protection)
    create_main_routes(app, db, auth_service, is_development=False, csrf_protection=csrf_protection)
    create_2fa_routes(app, db, auth_service, csrf_protection)
    create_audit_routes(app, db, auth_service)
    
    # Register performance monitoring routes (production mode)
    if settings.enable_performance_optimization:
        create_performance_routes(app, db, auth_service, csrf_protection)
    
    # Mount static files
    app.mount("/static", StaticFiles(directory="static"), name="static")
    
    return app

# Create app instance at module level for uvicorn
app = create_production_app()

if __name__ == "__main__":
    print("Production server starting...")
    print(f"Database: {settings.database_url}")
    print(f"Debug mode: {settings.debug}")
    print("Server: http://localhost:8000")
    
    serve(host="0.0.0.0", port=8000)