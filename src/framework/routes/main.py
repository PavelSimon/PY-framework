"""
Main application route handlers for PY-Framework
"""

from fasthtml.common import *
from ..layout import create_app_layout, create_auth_layout, create_page_title, create_success_message
from ..session import get_current_user


def create_main_routes(app, db=None, auth_service=None, is_development=False, csrf_protection=None):
    """Register main application routes with the FastHTML app"""
    
    @app.get("/")
    def home():
        if is_development:
            content = Div(
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
                    Li("✅ CSRF protection enabled"),
                    Li("✅ Profile update functionality"),
                ),
                H2("Test the Framework:"),
                Ul(
                    Li(A("Test Registration", href="/auth/register")),
                    Li(A("Test Login", href="/auth/login")),
                    Li(A("Test Email Service", href="/dev/test-email")),
                    Li(A("View Dashboard", href="/dashboard")),
                )
            )
            return Titled("PY-Framework Development", create_app_layout(
                content, 
                current_page="home",
                page_title="🚀 PY-Framework Development Server",
                page_subtitle="Welcome to your secure FastHTML framework!"
            ))
        else:
            content = Div(
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
            return Titled("Welcome to PY-Framework", create_app_layout(
                content, 
                current_page="home", 
                show_sidebar=False,
                page_title="🚀 PY-Framework",
                page_subtitle="A secure, robust web application framework"
            ))
    
    @app.get("/dashboard")
    def dashboard(request):
        # Get current user from session
        user = get_current_user(request, db, auth_service)
        
        if not user:
            # Redirect to login if not authenticated
            return RedirectResponse("/auth/login", status_code=302)
        
        content = Div(
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
                Li("✅ CSRF Protection (Cross-Site Request Forgery prevention)"),
                Li("✅ Profile Update functionality"),
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
        return Titled("Dashboard", create_app_layout(
            content, 
            user=user, 
            current_page="/dashboard",
            page_title="Dashboard",
            page_subtitle=f"Welcome back, {user['first_name'] or user['email']}!"
        ))
    
    @app.get("/page1")
    def page1(request):
        # Sample page for "1. stránka" menu item
        user = get_current_user(request, db, auth_service)
        
        if not user:
            # Redirect to login if not authenticated
            return RedirectResponse("/auth/login", status_code=302)
        
        content = Div(
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
        return Titled("1. stránka", create_app_layout(
            content, 
            user=user, 
            current_page="/page1",
            page_title="1. stránka",
            page_subtitle="This is the first page from the main menu"
        ))
    
    @app.get("/profile")
    def profile(request):
        # Profile edit page
        user = get_current_user(request, db, auth_service)
        
        if not user:
            # Redirect to login if not authenticated
            return RedirectResponse("/auth/login", status_code=302)
        
        # Create form with CSRF token if protection is enabled
        form_elements = [
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
            )
        ]
        
        # Add CSRF token if protection is enabled
        if csrf_protection:
            session_id = request.cookies.get('session_id')
            form_elements.insert(0, csrf_protection.create_csrf_input(session_id))
        
        form_elements.extend([
            Button("Update Profile", type="submit", cls="btn btn-primary"),
            A("Change Password", href="/profile/change-password", cls="btn btn-secondary")
        ])
        
        content = Div(
            Form(
                *form_elements,
                action="/profile",
                method="post",
                cls="form"
            )
        )
        return Titled("Edit Profile", create_app_layout(
            content, 
            user=user, 
            current_page="/profile",
            page_title="Edit Profile",
            page_subtitle="Update your account information"
        ))
    
    @app.post("/profile")
    def update_profile(request, first_name: str = None, last_name: str = None, csrf_token: str = None):
        # Get current user from session
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        try:
            # Validate CSRF token if protection is enabled
            if csrf_protection:
                session_id = request.cookies.get('session_id')
                if not csrf_protection.validate_token(csrf_token, session_id):
                    content = Div(
                        create_error_message("Invalid security token. Please try again."),
                        P(A("Back to Profile", href="/profile", cls="btn btn-primary"))
                    )
                    return Titled("Security Error", create_app_layout(
                        content, 
                        user=user,
                        page_title="Security Error",
                        page_subtitle="Invalid security token"
                    ))
            
            # Update user profile in database
            db.conn.execute("""
                UPDATE users 
                SET first_name = ?, last_name = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, [first_name, last_name, user['id']])
            
            content = Div(
                create_success_message("Your profile has been updated successfully."),
                P(A("Back to Profile", href="/profile", cls="btn btn-primary")),
                P(A("Go to Dashboard", href="/dashboard", cls="btn btn-secondary"))
            )
            return Titled("Profile Updated", create_app_layout(
                content, 
                user=user,
                page_title="Profile Updated! ✅",
                page_subtitle="Your changes have been saved"
            ))
            
        except Exception as e:
            content = Div(
                create_error_message(f"Failed to update profile: {str(e)}"),
                P(A("Back to Profile", href="/profile", cls="btn btn-primary"))
            )
            return Titled("Update Failed", create_app_layout(
                content, 
                user=user,
                page_title="Update Failed",
                page_subtitle="An error occurred while updating your profile"
            ))
    
    @app.get("/health")
    def health_check():
        return {"status": "healthy", "framework": "PY-Framework", "version": "0.1.0"}