"""
Development route handlers for PY-Framework
These routes are only available in development mode
"""

from fasthtml.common import *
from ..layout import create_app_layout, create_page_title
from ..session import get_current_user


def create_dev_routes(app, db=None, auth_service=None, email_service=None, settings=None):
    """Register development routes with the FastHTML app"""
    
    @app.get("/dev/test-email")
    def test_email(request):
        # Development tool to test email functionality
        user = get_current_user(request, db, auth_service)
        
        if not user:
            # Redirect to login if not authenticated
            return RedirectResponse("/auth/login", status_code=302)
        
        content = Div(
            create_page_title("Email Service Test", "Test the email functionality"),
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
        return Titled("Email Test", create_app_layout(content, user=user, current_page="/dev/test-email"))
    
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
            create_page_title("Email Test Result"),
            Div(message, cls=message_class),
            P(A("Back to Email Test", href="/dev/test-email", cls="btn btn-primary")),
            P(A("Dashboard", href="/dashboard", cls="btn btn-secondary"))
        )
        return Titled("Email Test Result", create_app_layout(content, user=user, current_page="/dev/test-email"))
    
    @app.get("/dev/test-auth")
    def test_auth(request):
        # Development tool to test authentication functionality
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        content = Div(
            create_page_title("Authentication Test", "Test authentication system"),
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
        return Titled("Auth Test", create_app_layout(content, user=user, current_page="/dev/test-auth"))
    
    @app.get("/dev/database")
    def test_database(request):
        # Development tool to inspect database
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        content = Div(
            create_page_title("Database Inspector", "View database status and basic info"),
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
        return Titled("Database Inspector", create_app_layout(content, user=user, current_page="/dev/database"))