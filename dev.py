#!/usr/bin/env python3
"""
Development server for PY-Framework
Includes hot reloading, debug mode, and development utilities
"""

import os
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
    from src.framework.config import Settings
    from src.framework.database import Database
    from src.framework.auth import AuthenticationService
    from src.framework.email import EmailService
    from src.framework.routes import create_auth_routes, create_main_routes, create_dev_routes

def create_dev_app():
    settings = Settings(debug=True)
    
    app = FastHTML(
        debug=True,
        live=True,
        reload=True,
        hdrs=[
            Meta(charset="utf-8"),
            Meta(name="viewport", content="width=device-width, initial-scale=1"),
            Link(rel="icon", type="image/x-icon", href="/static/favicon.ico"),
            Link(rel="stylesheet", href="/static/css/style.css"),
            Script(src="/static/js/htmx.min.js"),
        ]
    )
    
    # Initialize services
    db = Database(settings.database_url)
    auth_service = AuthenticationService(settings.secret_key)
    email_service = EmailService()
    
    # Register route modules
    create_auth_routes(app, db, auth_service, email_service)
    create_main_routes(app, db, auth_service, is_development=True)
    create_dev_routes(app, db, auth_service, email_service, settings)
    
    # Mount static files
    app.mount("/static", StaticFiles(directory="static"), name="static")
    
    print("Development server starting...")
    print(f"Database: {settings.database_url}")
    print(f"Debug mode: {settings.debug}")
    print("Server: http://localhost:8000")
    
    return app

# Create app instance at module level for uvicorn
app = create_dev_app()

if __name__ == "__main__":
    serve(host="localhost", port=8000)