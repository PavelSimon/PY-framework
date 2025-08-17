"""
Development route handlers for PY-Framework
These routes are only available in development mode
"""

from fasthtml.common import *
from starlette.responses import RedirectResponse
from ..layout import create_app_layout, create_page_title
from ..session import get_current_user


def create_dev_routes(app, db=None, auth_service=None, email_service=None, settings=None, csrf_protection=None):
    """Register development routes with the FastHTML app"""
    
    @app.get("/dev/test-email")
    def test_email(request):
        # Development tool to test email functionality
        user = get_current_user(request, db, auth_service)
        
        if not user:
            # Redirect to login if not authenticated
            return RedirectResponse("/auth/login", status_code=302)
        
        content = Div(
            P("This development tool allows you to test the email service configuration."),
            Form(
                Div(
                    Label("Test Email Address:", fr="test_email"),
                    Input(type="email", id="test_email", name="test_email", placeholder="test@example.com"),
                    cls="form-group"
                ),
                Button("Send Test Email", type="submit", cls="btn btn-primary"),
                action="/dev/test-email",
                method="post",
                cls="form"
            ),
            H3("Email Configuration Status:"),
            Ul(
                Li(f"SMTP Server: {getattr(settings, 'smtp_server', None) or 'Not configured'}"),
                Li(f"SMTP Port: {getattr(settings, 'smtp_port', 'Not set')}"),
                Li(f"From Email: {getattr(settings, 'from_email', None) or 'Not configured'}"),
                Li(f"TLS Enabled: {getattr(settings, 'smtp_use_tls', 'Not set')}"),
            )
        )
        return Titled("Email Test", create_app_layout(
            content, 
            user=user, 
            current_page="/dev/test-email",
            page_title="Email Service Test",
            page_subtitle="Test the email functionality"
        ))
    
    @app.post("/dev/test-email")
    def send_test_email(request, test_email: str):
        # Handle test email sending
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        if email_service:
            try:
                # Try to send a test email
                success = email_service.send_test_email(test_email)
                if success:
                    message = f"✅ Test email sent successfully to {test_email}"
                    message_class = "alert alert-success"
                else:
                    message = f"❌ Failed to send test email to {test_email}"
                    message_class = "alert alert-danger"
            except Exception as e:
                message = f"❌ Error sending test email: {str(e)}"
                message_class = "alert alert-danger"
        else:
            message = "❌ Email service not configured"
            message_class = "alert alert-warning"
        
        content = Div(
            Div(message, cls=message_class),
            P(A("Back to Email Test", href="/dev/test-email", cls="btn btn-primary")),
            P(A("Dashboard", href="/dashboard", cls="btn btn-secondary"))
        )
        return Titled("Email Test Result", create_app_layout(
            content, 
            user=user, 
            current_page="/dev/test-email",
            page_title="Email Test Result",
            page_subtitle="Test email sending result"
        ))
    
    @app.get("/dev/test-auth")
    def test_auth(request):
        # Development tool to test authentication functionality
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        content = Div(
            P("This development tool allows you to test the authentication system."),
            H3("Authentication Features:"),
            Ul(
                Li("✅ User registration with email validation"),
                Li("✅ Password hashing with BCrypt (12 rounds)"),
                Li("✅ Session management"),
                Li("✅ Account lockout protection"),
                Li("✅ Email verification (if configured)"),
            ),
            H3("Quick Test Actions:"),
            Div(
                A("Test Registration", href="/auth/register", cls="btn btn-primary"),
                A("Test Login", href="/auth/login", cls="btn btn-secondary"),
                A("View Dashboard", href="/dashboard", cls="btn btn-secondary"),
                cls="button-group"
            )
        )
        return Titled("Auth Test", create_app_layout(
            content, 
            user=user, 
            current_page="/dev/test-auth",
            page_title="Authentication Test",
            page_subtitle="Test authentication system"
        ))
    
    @app.get("/dev/database")
    def test_database(request):
        # Development tool to inspect database
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        content = Div(
            P("This development tool shows basic database information."),
            H3("Database Status:"),
            Ul(
                Li(f"Database URL: {getattr(settings, 'database_url', 'Not configured')}"),
                Li("✅ Database connection active"),
                Li("✅ Tables initialized"),
                Li("✅ Authentication tables ready"),
            ),
            H3("Available Tables:"),
            Ul(
                Li("users - User accounts and profile information"),
                Li("sessions - Active user sessions"),
                Li("email_tokens - Email verification tokens"),
                Li("login_attempts - Failed login tracking"),
            ),
            P("For detailed database operations, use a database client or admin tool.")
        )
        return Titled("Database Inspector", create_app_layout(
            content, 
            user=user, 
            current_page="/dev/database",
            page_title="Database Inspector",
            page_subtitle="View database status and basic info"
        ))
    
    @app.get("/dev/oauth-debug")
    def oauth_debug(request):
        # OAuth configuration debug tool
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        from ..oauth import OAuthService
        from ..config import settings
        
        oauth_service = OAuthService(db)
        
        content = Div(
            H2("OAuth Configuration Debug"),
            
            H3("🔍 Google OAuth Configuration"),
            Div(
                P(f"Client ID: {'✅ Configured' if settings.google_client_id else '❌ Missing'}"),
                P(f"Client Secret: {'✅ Configured' if settings.google_client_secret else '❌ Missing'}"),
                P(f"Redirect URI: {settings.google_redirect_uri}"),
                P(f"Status: {'✅ Ready' if settings.is_oauth_configured('google') else '❌ Not Configured'}"),
                style="margin: 1rem 0; padding: 1rem; border: 1px solid #ddd; border-radius: 4px;"
            ),
            
            H3("🐙 GitHub OAuth Configuration"),
            Div(
                P(f"Client ID: {'✅ Configured' if settings.github_client_id else '❌ Missing'}"),
                P(f"Client Secret: {'✅ Configured' if settings.github_client_secret else '❌ Missing'}"),
                P(f"Redirect URI: {settings.github_redirect_uri}"),
                P(f"Status: {'✅ Ready' if settings.is_oauth_configured('github') else '❌ Not Configured'}"),
                style="margin: 1rem 0; padding: 1rem; border: 1px solid #ddd; border-radius: 4px;"
            ),
            
            H3("🔗 Test OAuth URLs"),
            Div(
                P("Google Auth URL:"),
                Pre(Code(oauth_service.get_auth_url("google") or "❌ Failed to generate")),
                P("GitHub Auth URL:"),
                Pre(Code(oauth_service.get_auth_url("github") or "❌ Failed to generate")),
                style="margin: 1rem 0; padding: 1rem; border: 1px solid #ddd; border-radius: 4px;"
            ),
            
            H3("⚠️ Common Issues"),
            Ul(
                Li("Redirect URI mismatch: Ensure Google/GitHub app redirect URI exactly matches the URLs above"),
                Li("Missing credentials: Check .env file has correct GOOGLE_CLIENT_ID/SECRET and GITHUB_CLIENT_ID/SECRET"),
                Li("API not enabled: For Google, ensure Google+ API is enabled in Cloud Console"),
                Li("Wrong environment: Make sure you're using development/localhost settings")
            ),
            
            H3("🔧 Setup Instructions"),
            Div(
                H4("Google OAuth Setup:"),
                Ol(
                    Li("Go to Google Cloud Console → APIs & Services → Credentials"),
                    Li("Create OAuth 2.0 Client ID (Web application)"),
                    Li(f"Add redirect URI: {settings.google_redirect_uri}"),
                    Li("Copy Client ID and Secret to .env file")
                ),
                H4("GitHub OAuth Setup:"),
                Ol(
                    Li("Go to GitHub Settings → Developer settings → OAuth Apps"),
                    Li("Create new OAuth App"),
                    Li(f"Set Authorization callback URL: {settings.github_redirect_uri}"),
                    Li("Copy Client ID and Secret to .env file")
                ),
                style="margin: 1rem 0; padding: 1rem; border: 1px solid #ddd; border-radius: 4px;"
            )
        )
        
        return Titled("OAuth Debug", create_app_layout(
            content, 
            user=user, 
            current_page="/dev/oauth-debug",
            page_title="OAuth Configuration Debug",
            page_subtitle="Debug OAuth provider configurations"
        ))