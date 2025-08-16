"""
Routes package for PY-Framework
Contains all route handlers organized by functionality
"""

from .auth import create_auth_routes
from .main import create_main_routes
from .dev import create_dev_routes

__all__ = [
    'create_auth_routes',
    'create_main_routes', 
    'create_dev_routes'
]