"""
Authentication route handlers for PY-Framework
"""

from fasthtml.common import *
from ..auth import UserRegistration
from ..email import EmailService
from ..layout import create_auth_layout, create_page_title, create_success_message, create_error_message, create_warning_message
from ..session import create_session_response, store_session


def create_auth_routes(app, db, auth_service, email_service=None):
    """Register authentication routes with the FastHTML app"""
    
    @app.get("/auth/login")
    def login_page():
        content = Div(
            create_page_title("Login", "Enter your credentials to access your account"),
            Form(
                Div(
                    Label("Email:", fr="email"),
                    Input(type="email", id="email", name="email", required=True),
                    cls="form-group"
                ),
                Div(
                    Label("Password:", fr="password"),
                    Input(type="password", id="password", name="password", required=True),
                    cls="form-group"
                ),
                Button("Login", type="submit", cls="btn btn-primary"),
                action="/auth/login",
                method="post",
                cls="form"
            ),
            P(A("Don't have an account? Register here", href="/auth/register")),
            P(A("Forgot your password?", href="/auth/forgot-password"))
        )
        return Titled("Login", create_auth_layout(content))
    
    @app.get("/auth/register")
    def register_page():
        content = Div(
            create_page_title("Register", "Create your new account"),
            Form(
                Div(
                    Label("Email:", fr="email"),
                    Input(type="email", id="email", name="email", required=True),
                    cls="form-group"
                ),
                Div(
                    Label("First Name:", fr="first_name"),
                    Input(type="text", id="first_name", name="first_name"),
                    cls="form-group"
                ),
                Div(
                    Label("Last Name:", fr="last_name"),
                    Input(type="text", id="last_name", name="last_name"),
                    cls="form-group"
                ),
                Div(
                    Label("Password:", fr="password"),
                    Input(type="password", id="password", name="password", required=True),
                    Small("Minimum 8 characters with uppercase, lowercase, number, and special character"),
                    cls="form-group"
                ),
                Button("Register", type="submit", cls="btn btn-primary"),
                action="/auth/register",
                method="post",
                cls="form"
            ),
            P(A("Already have an account? Login here", href="/auth/login"))
        )
        return Titled("Register", create_auth_layout(content))
    
    @app.post("/auth/register")
    def register_user(email: str, password: str, first_name: str = None, last_name: str = None):
        try:
            # Validate registration data
            registration = UserRegistration(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )
            
            # Register the user
            success, user_id, message = auth_service.register_user(db, registration)
            
            if not success:
                content = Div(
                    create_page_title("Registration Failed"),
                    create_error_message(message),
                    P(A("Try again", href="/auth/register", cls="btn btn-primary"))
                )
                return Titled("Registration Failed", create_auth_layout(content))
            
            # Generate verification token and send email if email service is available
            if email_service:
                try:
                    token = email_service.generate_verification_token(db, user_id)
                    email_sent = email_service.send_verification_email(
                        email, token, first_name or email.split('@')[0]
                    )
                    
                    if email_sent:
                        content = Div(
                            create_page_title("Registration Successful! 🎉"),
                            create_success_message("Please check your email to verify your account."),
                            P("Check your spam folder if you don't see the email."),
                            P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                        )
                        return Titled("Registration Successful", create_auth_layout(content))
                    else:
                        content = Div(
                            create_page_title("Registration Successful! 🎉"),
                            create_warning_message("Account created but verification email could not be sent."),
                            P("Please contact support for manual verification."),
                            P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                        )
                        return Titled("Registration Successful", create_auth_layout(content))
                except Exception as e:
                    print(f"Email error: {e}")
                    error_msg = str(e)
                    
                    # Provide helpful error messages for common email issues
                    if "Application-specific password required" in error_msg:
                        helpful_msg = "Gmail requires an app-specific password. Go to Google Account → Security → 2-Step Verification → App passwords to generate one."
                    elif "Authentication failed" in error_msg or "Invalid credentials" in error_msg:
                        helpful_msg = "Email authentication failed. Please check your SMTP username and password in .env file."
                    elif "Connection refused" in error_msg or "Failed to connect" in error_msg:
                        helpful_msg = "Cannot connect to email server. Please check your SMTP server settings in .env file."
                    else:
                        helpful_msg = f"Email configuration error: {error_msg}"
                    
                    content = Div(
                        create_page_title("Registration Successful! 🎉"),
                        create_warning_message("Account created but verification email failed."),
                        P(helpful_msg),
                        P("You can still log in, but email verification is not available."),
                        P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                    )
                    return Titled("Registration Successful", create_auth_layout(content))
            else:
                # No email service configured
                content = Div(
                    create_page_title("Registration Successful! 🎉"),
                    create_success_message("Your account has been created successfully."),
                    P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("Registration Successful", create_auth_layout(content))
                
        except Exception as e:
            content = Div(
                create_page_title("Registration Failed"),
                create_error_message(f"Validation error: {str(e)}"),
                P(A("Try again", href="/auth/register", cls="btn btn-primary"))
            )
            return Titled("Registration Failed", create_auth_layout(content))
    
    @app.get("/auth/verify/{token}")
    def verify_email(token: str):
        if not email_service:
            content = Div(
                create_page_title("Email Verification Not Available"),
                create_error_message("Email verification is not configured."),
                P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
            )
            return Titled("Verification Not Available", create_auth_layout(content))
            
        success, user_id, message = email_service.verify_email_token(db, token)
        
        if success:
            content = Div(
                create_page_title("Email Verified! ✅"),
                create_success_message("Your email has been successfully verified."),
                P("You can now log in to your account."),
                P(A("Login", href="/auth/login", cls="btn btn-primary"))
            )
            return Titled("Email Verified", create_auth_layout(content))
        else:
            content = Div(
                create_page_title("Verification Failed"),
                create_error_message(message),
                P(A("Back to registration", href="/auth/register", cls="btn btn-primary"))
            )
            return Titled("Verification Failed", create_auth_layout(content))
    
    @app.post("/auth/login")
    def login_user(request, email: str, password: str):
        try:
            # Get client IP and user agent for session tracking
            client_ip = request.client.host if hasattr(request, 'client') else None
            user_agent = request.headers.get('user-agent', '')
            
            # Authenticate user
            success, user, message = auth_service.authenticate_user(db, email, password, client_ip)
            
            if not success:
                return Div(
                    H1("Login Failed"),
                    P(message, cls="alert alert-danger"),
                    P(A("Try again", href="/auth/login")),
                    P(A("Forgot password?", href="/auth/forgot-password")),
                    cls="container"
                )
            
            # Check if user is verified (only if email service is configured)
            if email_service and not user['is_verified']:
                return Div(
                    H1("Email Not Verified"),
                    P("Please verify your email before logging in.", cls="alert alert-warning"),
                    P("Check your email for the verification link."),
                    P(A("Resend verification", href="/auth/resend-verification")),
                    P(A("Back to login", href="/auth/login")),
                    cls="container"
                )
            
            # Create session
            session_id = auth_service.create_session(db, user['id'], client_ip, user_agent)
            
            # Store session temporarily for development
            store_session(session_id, user['id'])
            
            # Create response content
            content = Div(
                H1("Login Successful!"),
                P(f"Welcome back, {user['first_name'] or user['email']}!", cls="alert alert-success"),
                P(A("Go to Dashboard", href="/dashboard", cls="btn btn-primary")),
                P(A("Logout", href="/auth/logout", cls="btn btn-secondary")),
                cls="container"
            )
            
            # Return response with session cookie
            return create_session_response(content, session_id)
            
        except Exception as e:
            return Div(
                H1("Login Error"),
                P(f"An error occurred: {str(e)}", cls="alert alert-danger"),
                P(A("Try again", href="/auth/login")),
                cls="container"
            )
    
    @app.get("/auth/logout")
    def logout_user(request):
        # Get session ID and invalidate it
        session_id = request.cookies.get('session_id')
        if session_id:
            auth_service.logout_user(db, session_id)
        
        # Create logout content
        content = Div(
            H1("Logged Out"),
            P("You have been successfully logged out.", cls="alert alert-success"),
            P(A("Login again", href="/auth/login", cls="btn btn-primary")),
            cls="container"
        )
        
        # Return response with cleared session cookie
        return create_session_response(content, clear_session=True)
    
    @app.get("/auth/resend-verification")
    def resend_verification_page():
        content = Div(
            create_page_title("Resend Email Verification", "Enter your email to resend verification"),
            P("If you didn't receive the verification email, you can request a new one here."),
            Form(
                Div(
                    Label("Email:", fr="email"),
                    Input(type="email", id="email", name="email", required=True, placeholder="your-email@example.com"),
                    cls="form-group"
                ),
                Button("Resend Verification Email", type="submit", cls="btn btn-primary"),
                action="/auth/resend-verification",
                method="post",
                cls="form"
            ),
            P(A("Back to Login", href="/auth/login")),
            P(A("Register New Account", href="/auth/register"))
        )
        return Titled("Resend Verification", create_auth_layout(content))
    
    @app.post("/auth/resend-verification")
    def resend_verification_email(email: str):
        try:
            # Check if user exists and is not verified
            user = db.get_user_by_email(email)
            if not user:
                content = Div(
                    create_page_title("Email Not Found"),
                    create_error_message("No account found with this email address."),
                    P(A("Register Account", href="/auth/register", cls="btn btn-primary")),
                    P(A("Try Different Email", href="/auth/resend-verification", cls="btn btn-secondary"))
                )
                return Titled("Email Not Found", create_auth_layout(content))
            
            if user['is_verified']:
                content = Div(
                    create_page_title("Already Verified"),
                    create_success_message("Your email is already verified. You can log in normally."),
                    P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("Already Verified", create_auth_layout(content))
            
            # Send verification email if email service is available
            if email_service:
                try:
                    # Generate new verification token
                    token = email_service.generate_verification_token(db, user['id'])
                    email_sent = email_service.send_verification_email(
                        email, token, user['first_name'] or email.split('@')[0]
                    )
                    
                    if email_sent:
                        content = Div(
                            create_page_title("Verification Email Sent! 📧"),
                            create_success_message("A new verification email has been sent to your address."),
                            P("Please check your email and spam folder."),
                            P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                        )
                        return Titled("Email Sent", create_auth_layout(content))
                    else:
                        content = Div(
                            create_page_title("Email Send Failed"),
                            create_error_message("Failed to send verification email. Please try again later."),
                            P(A("Try Again", href="/auth/resend-verification", cls="btn btn-primary")),
                            P(A("Contact Support", href="/contact", cls="btn btn-secondary"))
                        )
                        return Titled("Send Failed", create_auth_layout(content))
                        
                except Exception as e:
                    error_msg = str(e)
                    
                    # Provide helpful error messages for common email issues
                    if "Application-specific password required" in error_msg:
                        helpful_msg = "Gmail requires an app-specific password. Please configure email settings properly."
                    elif "Authentication failed" in error_msg:
                        helpful_msg = "Email server authentication failed. Please check SMTP configuration."
                    else:
                        helpful_msg = f"Email error: {error_msg}"
                    
                    content = Div(
                        create_page_title("Email Configuration Error"),
                        create_error_message("Unable to send verification email due to configuration issues."),
                        P(helpful_msg),
                        P(A("Try Again Later", href="/auth/resend-verification", cls="btn btn-primary")),
                        P(A("Contact Support", href="/contact", cls="btn btn-secondary"))
                    )
                    return Titled("Configuration Error", create_auth_layout(content))
            else:
                content = Div(
                    create_page_title("Email Service Not Available"),
                    create_warning_message("Email verification service is not configured."),
                    P("Please contact an administrator to verify your account manually."),
                    P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("Service Unavailable", create_auth_layout(content))
                
        except Exception as e:
            content = Div(
                create_page_title("Resend Failed"),
                create_error_message(f"An error occurred: {str(e)}"),
                P(A("Try again", href="/auth/resend-verification", cls="btn btn-primary"))
            )
            return Titled("Resend Failed", create_auth_layout(content))