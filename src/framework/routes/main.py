"""
Main application route handlers for PY-Framework
"""

from fasthtml.common import *
from ..layout import create_app_layout, create_auth_layout, create_page_title, create_success_message
from ..session import get_current_user


def create_main_routes(app, db=None, auth_service=None, is_development=False):
    """Register main application routes with the FastHTML app"""
    
    @app.get("/")
    def home():
        if is_development:
            content = Div(
                create_page_title("🚀 PY-Framework Development Server", "Welcome to your secure FastHTML framework!"),
                Div(
                    A("Get Started", href="/dashboard", cls="btn btn-primary"),
                    A("View Documentation", href="/docs", cls="btn btn-secondary"),
                    cls="button-group"
                ),
                H2("Development Features:"),
                Ul(
                    Li("✅ Hot reloading enabled"),
                    Li("✅ Debug mode active"),
                    Li("✅ Database initialized"),
                    Li("✅ Authentication system ready"),
                    Li("✅ Email service configured"),
                    Li("✅ Navigation layout implemented"),
                ),
                H2("Test the Framework:"),
                Ul(
                    Li(A("Test Registration", href="/auth/register")),
                    Li(A("Test Login", href="/auth/login")),
                    Li(A("Test Email Service", href="/dev/test-email")),
                    Li(A("View Dashboard", href="/dashboard")),
                )
            )
            return Titled("PY-Framework Development", create_app_layout(content, current_page="home"))
        else:
            content = Div(
                create_page_title("🚀 PY-Framework", "A secure, robust web application framework"),
                P("Welcome to your production-ready FastHTML framework with enterprise-grade security and modern authentication."),
                Div(
                    A("Get Started", href="/dashboard", cls="btn btn-primary"),
                    A("Login", href="/auth/login", cls="btn btn-secondary"),
                    cls="button-group"
                ),
                H2("🚀 Production Features:"),
                Ul(
                    Li("✅ Enterprise-grade security headers"),
                    Li("✅ Production-optimized performance"),
                    Li("✅ Secure authentication system"),
                    Li("✅ Professional navigation layout"),
                    Li("✅ Email verification system"),
                    Li("✅ Session management"),
                )
            )
            return Titled("Welcome to PY-Framework", create_app_layout(content, current_page="home", show_sidebar=False))
    
    @app.get("/dashboard")
    def dashboard(request):
        # Get current user from session
        user = get_current_user(request, db, auth_service)
        
        if not user:
            # Redirect to login if not authenticated
            return RedirectResponse("/auth/login", status_code=302)
        
        content = Div(
            create_page_title("Dashboard", f"Welcome back, {user['first_name'] or user['email']}!"),
            create_success_message("You are successfully logged in to the PY-Framework!"),
            H2("👤 Your Account:"),
            Ul(
                Li(f"📧 Email: {user['email']}"),
                Li(f"👤 Name: {user['first_name'] or 'Not set'} {user['last_name'] or ''}"),
                Li(f"✅ Verified: {'Yes' if user['is_verified'] else 'No'}"),
                Li(f"📅 Member since: {user['created_at'].strftime('%Y-%m-%d') if user['created_at'] else 'Unknown'}"),
            ),
            H2("🚀 Framework Features Status:"),
            Ul(
                Li("✅ User Registration with Email Verification"),
                Li("✅ Secure Password Authentication (BCrypt, 12 rounds)"),
                Li("✅ Session Management with automatic cleanup"),
                Li("✅ Account lockout protection (5 attempts)"),
                Li("✅ Professional navigation layout"),
                Li("✅ Responsive design with sidebar"),
                Li("🔄 CSRF Protection (coming next)"),
                Li("🔄 Password Reset (coming next)"),
                Li("🔄 OAuth Integration (Google & GitHub)"),
            ),
            H2("📊 Quick Actions:"),
            Div(
                A("Edit Profile", href="/profile", cls="btn btn-primary"),
                A("Test Email", href="/dev/test-email", cls="btn btn-secondary") if is_development else None,
                A("View Users", href="/users", cls="btn btn-secondary"),
                cls="button-group"
            )
        )
        return Titled("Dashboard", create_app_layout(content, user=user, current_page="/dashboard"))
    
    @app.get("/page1")
    def page1(request):
        # Sample page for "1. stránka" menu item
        user = get_current_user(request, db, auth_service)
        
        if not user:
            # Redirect to login if not authenticated
            return RedirectResponse("/auth/login", status_code=302)
        
        content = Div(
            create_page_title("1. stránka", "This is the first page from the main menu"),
            P("This page demonstrates the navigation structure with the sidebar and top menu."),
            H3("Navigation Features:"),
            Ul(
                Li("Top navigation with favicon and main menu"),
                Li("Persona icon with dropdown for profile and logout"),
                Li("Left sidebar with app-specific submenu"),
                Li("Responsive design for mobile devices"),
            ),
            P("This is where your application-specific content would go.")
        )
        return Titled("1. stránka", create_app_layout(content, user=user, current_page="/page1"))
    
    @app.get("/profile")
    def profile(request):
        # Profile edit page
        user = get_current_user(request, db, auth_service)
        
        if not user:
            # Redirect to login if not authenticated
            return RedirectResponse("/auth/login", status_code=302)
        
        content = Div(
            create_page_title("Edit Profile", "Update your account information"),
            Form(
                Div(
                    Label("First Name:", fr="first_name"),
                    Input(type="text", id="first_name", name="first_name", value=user['first_name'] or ""),
                    cls="form-group"
                ),
                Div(
                    Label("Last Name:", fr="last_name"),
                    Input(type="text", id="last_name", name="last_name", value=user['last_name'] or ""),
                    cls="form-group"
                ),
                Div(
                    Label("Email:", fr="email"),
                    Input(type="email", id="email", name="email", value=user['email'], readonly=True),
                    Small("Email cannot be changed"),
                    cls="form-group"
                ),
                Button("Update Profile", type="submit", cls="btn btn-primary"),
                A("Change Password", href="/profile/change-password", cls="btn btn-secondary"),
                action="/profile",
                method="post",
                cls="form"
            )
        )
        return Titled("Edit Profile", create_app_layout(content, user=user, current_page="/profile"))
    
    @app.get("/health")
    def health_check():
        return {"status": "healthy", "framework": "PY-Framework", "version": "0.1.0"}