"""
Authentication route handlers for PY-Framework
"""

from fasthtml.common import *
from starlette.responses import RedirectResponse
from ..auth import UserRegistration
from ..email import EmailService
from ..layout import create_auth_layout, create_page_title, create_success_message, create_error_message, create_warning_message
from ..session import create_session_response, store_session, clear_session
from ..csrf import csrf_protect


def create_auth_routes(app, db, auth_service, email_service=None, csrf_protection=None):
    """Register authentication routes with the FastHTML app"""
    
    @app.get("/auth/login")
    def login_page(request):
        # Create form with CSRF token if protection is enabled
        form_elements = [
            Div(
                Label("Email:", fr="email"),
                Input(type="email", id="email", name="email", required=True),
                cls="form-group"
            ),
            Div(
                Label("Password:", fr="password"),
                Input(type="password", id="password", name="password", required=True),
                cls="form-group"
            )
        ]
        
        # Add CSRF token if protection is enabled
        if csrf_protection:
            session_id = request.cookies.get('session_id')
            form_elements.insert(0, csrf_protection.create_csrf_input(session_id))
        
        form_elements.append(Button("Login", type="submit", cls="btn btn-primary"))
        
        content = Div(
            Form(
                *form_elements,
                action="/auth/login",
                method="post",
                cls="form"
            ),
            # OAuth login options
            Div(
                Hr(),
                P("Or sign in with:", style="text-align: center; margin: 1rem 0 0.5rem 0; color: #666;"),
                Div(
                    A("🔍 Sign in with Google", href="/auth/google", cls="btn btn-google", style="display: inline-block; margin-right: 0.5rem; padding: 0.5rem 1rem; background-color: #4285f4; color: white; text-decoration: none; border-radius: 4px;"),
                    A("🐙 Sign in with GitHub", href="/auth/github", cls="btn btn-github", style="display: inline-block; padding: 0.5rem 1rem; background-color: #333; color: white; text-decoration: none; border-radius: 4px;"),
                    style="text-align: center; margin-bottom: 1rem;"
                ),
                Hr(),
                style="margin: 1.5rem 0;"
            ),
            P(A("Don't have an account? Register here", href="/auth/register")),
            P(A("Forgot your password?", href="/auth/forgot-password"))
        )
        return Titled("Login", create_auth_layout(
            content,
            page_title="Login",
            page_subtitle="Enter your credentials to access your account"
        ))
    
    @app.get("/auth/register")
    def register_page(request):
        # Create form with CSRF token if protection is enabled
        form_elements = [
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
            )
        ]
        
        # Add CSRF token if protection is enabled
        if csrf_protection:
            session_id = request.cookies.get('session_id')
            form_elements.insert(0, csrf_protection.create_csrf_input(session_id))
        
        form_elements.append(Button("Register", type="submit", cls="btn btn-primary"))
        
        content = Div(
            Form(
                *form_elements,
                action="/auth/register",
                method="post",
                cls="form"
            ),
            P(A("Already have an account? Login here", href="/auth/login"))
        )
        return Titled("Register", create_auth_layout(
            content,
            page_title="Register",
            page_subtitle="Create your new account"
        ))
    
    @app.post("/auth/register")
    def register_user(request, email: str, password: str, first_name: str = None, last_name: str = None, csrf_token: str = None):
        try:
            # Validate CSRF token if protection is enabled
            if csrf_protection:
                session_id = request.cookies.get('session_id')
                if not csrf_protection.validate_token(csrf_token, session_id):
                    content = Div(
                        create_error_message("Invalid security token. Please try again."),
                        P(A("Back to Registration", href="/auth/register", cls="btn btn-primary"))
                    )
                    return Titled("Security Error", create_auth_layout(
                        content,
                        page_title="Security Error",
                        page_subtitle="Invalid security token"
                    ))
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
                    create_error_message(message),
                    P(A("Try again", href="/auth/register", cls="btn btn-primary"))
                )
                return Titled("Registration Failed", create_auth_layout(
                    content,
                    page_title="Registration Failed",
                    page_subtitle="Unable to create your account"
                ))
            
            # Generate verification token and send email if email service is available
            if email_service:
                try:
                    token = email_service.generate_verification_token(db, user_id)
                    email_sent = email_service.send_verification_email(
                        email, token, first_name or email.split('@')[0]
                    )
                    
                    if email_sent:
                        content = Div(
                            create_success_message("Please check your email to verify your account."),
                            P("Check your spam folder if you don't see the email."),
                            P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                        )
                        return Titled("Registration Successful", create_auth_layout(
                            content,
                            page_title="Registration Successful! 🎉",
                            page_subtitle="Welcome to PY-Framework"
                        ))
                    else:
                        content = Div(
                            create_warning_message("Account created but verification email could not be sent."),
                            P("Please contact support for manual verification."),
                            P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                        )
                        return Titled("Registration Successful", create_auth_layout(
                            content,
                            page_title="Registration Successful! 🎉",
                            page_subtitle="Account created but email verification failed"
                        ))
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
                        create_warning_message("Account created but verification email failed."),
                        P(helpful_msg),
                        P("You can still log in, but email verification is not available."),
                        P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                    )
                    return Titled("Registration Successful", create_auth_layout(
                        content,
                        page_title="Registration Successful! 🎉",
                        page_subtitle="Account created but email service error"
                    ))
            else:
                # No email service configured
                content = Div(
                    create_success_message("Your account has been created successfully."),
                    P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("Registration Successful", create_auth_layout(
                    content,
                    page_title="Registration Successful! 🎉",
                    page_subtitle="Welcome to PY-Framework"
                ))
                
        except Exception as e:
            content = Div(
                create_error_message(f"Validation error: {str(e)}"),
                P(A("Try again", href="/auth/register", cls="btn btn-primary"))
            )
            return Titled("Registration Failed", create_auth_layout(
                content,
                page_title="Registration Failed",
                page_subtitle="Validation error occurred"
            ))
    
    @app.get("/auth/verify/{token}")
    def verify_email(token: str):
        if not email_service:
            content = Div(
                create_error_message("Email verification is not configured."),
                P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
            )
            return Titled("Verification Not Available", create_auth_layout(
                content,
                page_title="Email Verification Not Available",
                page_subtitle="Service not configured"
            ))
            
        success, user_id, message = email_service.verify_email_token(db, token)
        
        if success:
            content = Div(
                create_success_message("Your email has been successfully verified."),
                P("You can now log in to your account."),
                P(A("Login", href="/auth/login", cls="btn btn-primary"))
            )
            return Titled("Email Verified", create_auth_layout(
                content,
                page_title="Email Verified! ✅",
                page_subtitle="Your account is now active"
            ))
        else:
            content = Div(
                create_error_message(message),
                P(A("Back to registration", href="/auth/register", cls="btn btn-primary"))
            )
            return Titled("Verification Failed", create_auth_layout(
                content,
                page_title="Verification Failed",
                page_subtitle="Unable to verify your email"
            ))
    
    @app.post("/auth/login")
    def login_user(request, email: str, password: str, csrf_token: str = None):
        try:
            # Validate CSRF token if protection is enabled
            if csrf_protection:
                session_id = request.cookies.get('session_id')
                if not csrf_protection.validate_token(csrf_token, session_id):
                    return Div(
                        H1("Security Error"),
                        P("Invalid security token. Please try again.", cls="alert alert-danger"),
                        P(A("Back to Login", href="/auth/login")),
                        cls="container"
                    )
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
            
            # Redirect directly to dashboard after successful login
            return RedirectResponse("/dashboard", status_code=302)
            
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
            # Invalidate session in database
            auth_service.logout_user(db, session_id)
            # Clear session from temporary store
            clear_session(session_id)
        
        # Create logout content
        content = Div(
            H1("Logged Out"),
            P("You have been successfully logged out.", cls="alert alert-success"),
            P(A("Login again", href="/auth/login", cls="btn btn-primary")),
            cls="container"
        )
        
        # Return response with cleared session cookie
        return create_session_response(content, session_id=session_id, clear_session=True)
    
    @app.get("/auth/resend-verification")
    def resend_verification_page(request):
        # Create form with CSRF token if protection is enabled
        form_elements = [
            Div(
                Label("Email:", fr="email"),
                Input(type="email", id="email", name="email", required=True, placeholder="your-email@example.com"),
                cls="form-group"
            )
        ]
        
        # Add CSRF token if protection is enabled
        if csrf_protection:
            session_id = request.cookies.get('session_id')
            form_elements.insert(0, csrf_protection.create_csrf_input(session_id))
        
        form_elements.append(Button("Resend Verification Email", type="submit", cls="btn btn-primary"))
        
        content = Div(
            P("If you didn't receive the verification email, you can request a new one here."),
            Form(
                *form_elements,
                action="/auth/resend-verification",
                method="post",
                cls="form"
            ),
            P(A("Back to Login", href="/auth/login")),
            P(A("Register New Account", href="/auth/register"))
        )
        return Titled("Resend Verification", create_auth_layout(
            content,
            page_title="Resend Email Verification",
            page_subtitle="Enter your email to resend verification"
        ))
    
    @app.post("/auth/resend-verification")
    def resend_verification_email(request, email: str, csrf_token: str = None):
        try:
            # Validate CSRF token if protection is enabled
            if csrf_protection:
                session_id = request.cookies.get('session_id')
                if not csrf_protection.validate_token(csrf_token, session_id):
                    content = Div(
                        create_error_message("Invalid security token. Please try again."),
                        P(A("Back to Resend Verification", href="/auth/resend-verification", cls="btn btn-primary"))
                    )
                    return Titled("Security Error", create_auth_layout(
                        content,
                        page_title="Security Error",
                        page_subtitle="Invalid security token"
                    ))
            # Check if user exists and is not verified
            user = db.get_user_by_email(email)
            if not user:
                content = Div(
                    create_error_message("No account found with this email address."),
                    P(A("Register Account", href="/auth/register", cls="btn btn-primary")),
                    P(A("Try Different Email", href="/auth/resend-verification", cls="btn btn-secondary"))
                )
                return Titled("Email Not Found", create_auth_layout(
                    content,
                    page_title="Email Not Found",
                    page_subtitle="No account with this email"
                ))
            
            if user['is_verified']:
                content = Div(
                    create_success_message("Your email is already verified. You can log in normally."),
                    P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("Already Verified", create_auth_layout(
                    content,
                    page_title="Already Verified",
                    page_subtitle="Your email is already verified"
                ))
            
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
                            create_success_message("A new verification email has been sent to your address."),
                            P("Please check your email and spam folder."),
                            P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                        )
                        return Titled("Email Sent", create_auth_layout(
                            content,
                            page_title="Verification Email Sent! 📧",
                            page_subtitle="Check your email inbox"
                        ))
                    else:
                        content = Div(
                            create_error_message("Failed to send verification email. Please try again later."),
                            P(A("Try Again", href="/auth/resend-verification", cls="btn btn-primary")),
                            P(A("Contact Support", href="/contact", cls="btn btn-secondary"))
                        )
                        return Titled("Send Failed", create_auth_layout(
                            content,
                            page_title="Email Send Failed",
                            page_subtitle="Unable to send verification email"
                        ))
                        
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
                        create_error_message("Unable to send verification email due to configuration issues."),
                        P(helpful_msg),
                        P(A("Try Again Later", href="/auth/resend-verification", cls="btn btn-primary")),
                        P(A("Contact Support", href="/contact", cls="btn btn-secondary"))
                    )
                    return Titled("Configuration Error", create_auth_layout(
                        content,
                        page_title="Email Configuration Error",
                        page_subtitle="Email service configuration issue"
                    ))
            else:
                content = Div(
                    create_warning_message("Email verification service is not configured."),
                    P("Please contact an administrator to verify your account manually."),
                    P(A("Go to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("Service Unavailable", create_auth_layout(
                    content,
                    page_title="Email Service Not Available",
                    page_subtitle="Email verification service not configured"
                ))
                
        except Exception as e:
            content = Div(
                create_error_message(f"An error occurred: {str(e)}"),
                P(A("Try again", href="/auth/resend-verification", cls="btn btn-primary"))
            )
            return Titled("Resend Failed", create_auth_layout(
                content,
                page_title="Resend Failed",
                page_subtitle="An error occurred"
            ))
    
    @app.get("/auth/forgot-password")
    def forgot_password_page(request):
        # Create form with CSRF token if protection is enabled
        form_elements = [
            Div(
                Label("Email:", fr="email"),
                Input(type="email", id="email", name="email", required=True, placeholder="your-email@example.com"),
                Small("Enter the email address associated with your account"),
                cls="form-group"
            )
        ]
        
        # Add CSRF token if protection is enabled
        if csrf_protection:
            session_id = request.cookies.get('session_id')
            form_elements.insert(0, csrf_protection.create_csrf_input(session_id))
        
        form_elements.append(Button("Send Reset Link", type="submit", cls="btn btn-primary"))
        
        content = Div(
            P("Forgot your password? No problem. Enter your email address and we'll send you a reset link."),
            Form(
                *form_elements,
                action="/auth/forgot-password",
                method="post",
                cls="form"
            ),
            P(A("Back to Login", href="/auth/login")),
            P(A("Don't have an account? Register", href="/auth/register"))
        )
        return Titled("Forgot Password", create_auth_layout(
            content,
            page_title="Forgot Password",
            page_subtitle="Reset your account password"
        ))
    
    @app.post("/auth/forgot-password")
    def send_password_reset(request, email: str, csrf_token: str = None):
        try:
            # Validate CSRF token if protection is enabled
            if csrf_protection:
                session_id = request.cookies.get('session_id')
                if not csrf_protection.validate_token(csrf_token, session_id):
                    content = Div(
                        create_error_message("Invalid security token. Please try again."),
                        P(A("Back to Reset", href="/auth/forgot-password", cls="btn btn-primary"))
                    )
                    return Titled("Security Error", create_auth_layout(
                        content,
                        page_title="Security Error",
                        page_subtitle="Invalid security token"
                    ))
            
            # Check if user exists
            user = db.get_user_by_email(email)
            
            # Always show success message to prevent email enumeration
            success_content = Div(
                create_success_message("If an account exists with this email, a password reset link has been sent."),
                P("Please check your email and spam folder."),
                P("The reset link will expire in 1 hour."),
                P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
            )
            
            # Only actually send email if user exists and email service is configured
            if user and email_service:
                try:
                    # Generate password reset token
                    token = email_service.generate_password_reset_token(db, user['id'])
                    
                    # Send password reset email
                    email_sent = email_service.send_password_reset_email(
                        email, token, user['first_name'] or email.split('@')[0]
                    )
                    
                    if not email_sent:
                        print(f"Failed to send password reset email to {email}")
                        
                except Exception as e:
                    print(f"Password reset email error: {e}")
            
            return Titled("Reset Link Sent", create_auth_layout(
                success_content,
                page_title="Reset Link Sent! 📧",
                page_subtitle="Check your email inbox"
            ))
            
        except Exception as e:
            content = Div(
                create_error_message("Unable to process password reset request. Please try again."),
                P(A("Try again", href="/auth/forgot-password", cls="btn btn-primary"))
            )
            return Titled("Reset Failed", create_auth_layout(
                content,
                page_title="Reset Failed",
                page_subtitle="An error occurred"
            ))
    
    @app.get("/auth/reset-password/{token}")
    def reset_password_page(token: str):
        if not email_service:
            content = Div(
                create_error_message("Password reset is not configured."),
                P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
            )
            return Titled("Reset Not Available", create_auth_layout(
                content,
                page_title="Password Reset Not Available",
                page_subtitle="Service not configured"
            ))
        
        # Verify the reset token
        success, user_id, message = email_service.verify_password_reset_token(db, token)
        
        if not success:
            content = Div(
                create_error_message(message),
                P("The reset link may be expired or invalid."),
                P(A("Request New Reset Link", href="/auth/forgot-password", cls="btn btn-primary")),
                P(A("Back to Login", href="/auth/login", cls="btn btn-secondary"))
            )
            return Titled("Invalid Reset Link", create_auth_layout(
                content,
                page_title="Invalid Reset Link",
                page_subtitle="Unable to reset password"
            ))
        
        # Create password reset form with CSRF token
        form_elements = [
            Input(type="hidden", name="token", value=token),
            Div(
                Label("New Password:", fr="password"),
                Input(type="password", id="password", name="password", required=True),
                Small("Minimum 8 characters with uppercase, lowercase, number, and special character"),
                cls="form-group"
            ),
            Div(
                Label("Confirm Password:", fr="confirm_password"),
                Input(type="password", id="confirm_password", name="confirm_password", required=True),
                cls="form-group"
            )
        ]
        
        # Add CSRF token if protection is enabled
        if csrf_protection:
            form_elements.insert(1, csrf_protection.create_csrf_input())
        
        form_elements.append(Button("Reset Password", type="submit", cls="btn btn-primary"))
        
        content = Div(
            P("Enter your new password below. Make sure it's strong and secure."),
            Form(
                *form_elements,
                action="/auth/reset-password",
                method="post",
                cls="form"
            )
        )
        return Titled("Reset Password", create_auth_layout(
            content,
            page_title="Reset Password",
            page_subtitle="Choose a new secure password"
        ))
    
    @app.post("/auth/reset-password")
    def process_password_reset(request, token: str, password: str, confirm_password: str, csrf_token: str = None):
        try:
            # Validate CSRF token if protection is enabled
            if csrf_protection:
                if not csrf_protection.validate_token(csrf_token):
                    content = Div(
                        create_error_message("Invalid security token. Please try again."),
                        P(A("Back to Reset", href=f"/auth/reset-password/{token}", cls="btn btn-primary"))
                    )
                    return Titled("Security Error", create_auth_layout(
                        content,
                        page_title="Security Error",
                        page_subtitle="Invalid security token"
                    ))
            
            # Verify passwords match
            if password != confirm_password:
                content = Div(
                    create_error_message("Passwords do not match. Please try again."),
                    P(A("Back to Reset", href=f"/auth/reset-password/{token}", cls="btn btn-primary"))
                )
                return Titled("Password Mismatch", create_auth_layout(
                    content,
                    page_title="Password Mismatch",
                    page_subtitle="Passwords must match"
                ))
            
            # Verify the reset token is still valid
            if not email_service:
                content = Div(
                    create_error_message("Password reset service is not available."),
                    P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("Service Unavailable", create_auth_layout(
                    content,
                    page_title="Service Unavailable",
                    page_subtitle="Password reset not configured"
                ))
            
            success, user_id, message = email_service.verify_password_reset_token(db, token)
            
            if not success:
                content = Div(
                    create_error_message(message),
                    P("The reset token may have expired or been used already."),
                    P(A("Request New Reset Link", href="/auth/forgot-password", cls="btn btn-primary"))
                )
                return Titled("Invalid Token", create_auth_layout(
                    content,
                    page_title="Invalid Reset Token",
                    page_subtitle="Unable to reset password"
                ))
            
            # Validate password requirements
            from ..auth import UserRegistration
            try:
                # Use the registration validation to check password
                temp_registration = UserRegistration(
                    email="temp@example.com",  # Dummy email for validation
                    password=password
                )
            except ValueError as ve:
                content = Div(
                    create_error_message(f"Password validation failed: {str(ve)}"),
                    P(A("Back to Reset", href=f"/auth/reset-password/{token}", cls="btn btn-primary"))
                )
                return Titled("Invalid Password", create_auth_layout(
                    content,
                    page_title="Invalid Password",
                    page_subtitle="Password does not meet requirements"
                ))
            
            # Update user password
            password_hash = auth_service.hash_password(password)
            db.conn.execute("""
                UPDATE users 
                SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, [password_hash, user_id])
            
            # Mark reset token as used
            email_service.mark_password_reset_token_used(db, token)
            
            # Invalidate all user sessions for security
            db.conn.execute("""
                UPDATE sessions 
                SET is_active = FALSE 
                WHERE user_id = ?
            """, [user_id])
            
            content = Div(
                create_success_message("Your password has been successfully reset."),
                P("All existing sessions have been logged out for security."),
                P("You can now log in with your new password."),
                P(A("Login", href="/auth/login", cls="btn btn-primary"))
            )
            return Titled("Password Reset Successful", create_auth_layout(
                content,
                page_title="Password Reset Successful! ✅",
                page_subtitle="Your password has been updated"
            ))
            
        except Exception as e:
            content = Div(
                create_error_message(f"An error occurred while resetting your password: {str(e)}"),
                P(A("Try again", href=f"/auth/reset-password/{token}", cls="btn btn-primary"))
            )
            return Titled("Reset Failed", create_auth_layout(
                content,
                page_title="Reset Failed",
                page_subtitle="An error occurred"
            ))
    
    # OAuth Routes
    @app.get("/auth/{provider}")
    def oauth_login(provider: str):
        """Initiate OAuth login flow"""
        try:
            from ..oauth import OAuthService
            oauth_service = OAuthService()
            
            # Validate provider
            if provider not in ['google', 'github']:
                content = Div(
                    create_error_message(f"OAuth provider '{provider}' is not supported."),
                    P("Supported providers: Google, GitHub"),
                    P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("Invalid Provider", create_auth_layout(
                    content,
                    page_title="Invalid OAuth Provider",
                    page_subtitle="Provider not supported"
                ))
            
            # Get authorization URL
            auth_url = oauth_service.get_auth_url(provider)
            if not auth_url:
                content = Div(
                    create_error_message(f"{provider.title()} OAuth is not configured properly."),
                    P("Possible issues:"),
                    Ul(
                        Li("Missing OAuth client credentials in .env file"),
                        Li("Invalid redirect URI configuration"),
                        Li("OAuth app not properly set up with provider")
                    ),
                    P("Please check the OAuth configuration in settings."),
                    P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("OAuth Not Configured", create_auth_layout(
                    content,
                    page_title="OAuth Not Available",
                    page_subtitle="Service not configured"
                ))
            
            # Redirect to provider authorization page
            return RedirectResponse(auth_url, status_code=302)
            
        except Exception as e:
            print(f"OAuth initiation error: {e}")
            content = Div(
                create_error_message("Failed to initiate OAuth login. Please try again."),
                P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
            )
            return Titled("OAuth Error", create_auth_layout(
                content,
                page_title="OAuth Login Failed",
                page_subtitle="An error occurred"
            ))
    
    @app.get("/auth/{provider}/callback")
    def oauth_callback(request, provider: str, code: str = None, state: str = None, error: str = None):
        """Handle OAuth callback"""
        try:
            from ..oauth import OAuthService
            oauth_service = OAuthService()
            
            # Check for OAuth errors
            if error:
                error_descriptions = {
                    'access_denied': 'You cancelled the authorization request.',
                    'invalid_request': 'The OAuth request was invalid.',
                    'unsupported_response_type': 'OAuth configuration error.',
                }
                error_msg = error_descriptions.get(error, f"OAuth error: {error}")
                
                content = Div(
                    create_error_message(error_msg),
                    P("Please try logging in again."),
                    P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("OAuth Error", create_auth_layout(
                    content,
                    page_title="OAuth Authorization Failed",
                    page_subtitle="Authorization was not granted"
                ))
            
            # Validate required parameters
            if not code or not state:
                content = Div(
                    create_error_message("Missing required OAuth parameters."),
                    P("The OAuth callback is missing required information."),
                    P(A("Try Again", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("OAuth Error", create_auth_layout(
                    content,
                    page_title="OAuth Callback Error",
                    page_subtitle="Missing parameters"
                ))
            
            # Validate state parameter (CSRF protection)
            if not oauth_service.validate_state_token(state, provider):
                content = Div(
                    create_error_message("Invalid OAuth state token."),
                    P("This may be a security issue or an expired request."),
                    P(A("Try Again", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("Security Error", create_auth_layout(
                    content,
                    page_title="OAuth Security Error",
                    page_subtitle="Invalid state token"
                ))
            
            # Get OAuth provider
            oauth_provider = oauth_service.get_provider(provider)
            if not oauth_provider:
                content = Div(
                    create_error_message(f"OAuth provider '{provider}' is not available."),
                    P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("Provider Unavailable", create_auth_layout(
                    content,
                    page_title="OAuth Provider Unavailable",
                    page_subtitle="Provider not configured"
                ))
            
            # Process OAuth callback synchronously with error handling
            try:
                import asyncio
                
                # Create new event loop for this thread if needed
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                
                return loop.run_until_complete(process_oauth_callback_async(
                    oauth_service, oauth_provider, provider, code, state, request, db, auth_service
                ))
            except Exception as async_error:
                print(f"OAuth callback async processing error: {async_error}")
                content = Div(
                    create_error_message("Failed to process OAuth login. Please try again."),
                    P(f"Error details: {str(async_error)}"),
                    P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("OAuth Error", create_auth_layout(
                    content,
                    page_title="OAuth Login Failed",
                    page_subtitle="Processing error occurred"
                ))
            
        except Exception as e:
            print(f"OAuth callback error: {e}")
            content = Div(
                create_error_message("Failed to process OAuth login. Please try again."),
                P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
            )
            return Titled("OAuth Error", create_auth_layout(
                content,
                page_title="OAuth Login Failed",
                page_subtitle="An error occurred"
            ))
    
    async def process_oauth_callback_async(oauth_service, oauth_provider, provider, code, state, request, db, auth_service):
        """Process OAuth callback asynchronously"""
        try:
            # Exchange code for token
            token_data = await oauth_provider.exchange_code_for_token(code, state)
            if not token_data:
                content = Div(
                    create_error_message("Failed to exchange OAuth code for token."),
                    P("The authorization may have expired or failed."),
                    P(A("Try Again", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("OAuth Error", create_auth_layout(
                    content,
                    page_title="OAuth Token Exchange Failed",
                    page_subtitle="Authorization failed"
                ))
            
            # Get user information from provider
            user_info = await oauth_provider.get_user_info(token_data["access_token"])
            if not user_info:
                content = Div(
                    create_error_message("Failed to get user information from OAuth provider."),
                    P("Please try again or use a different login method."),
                    P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
                )
                return Titled("OAuth Error", create_auth_layout(
                    content,
                    page_title="OAuth User Info Failed",
                    page_subtitle="Could not retrieve user information"
                ))
            
            # Check if user exists with this OAuth account
            existing_user = oauth_service.find_user_by_oauth(provider, user_info["provider_user_id"])
            
            if existing_user:
                # User exists, log them in
                if not existing_user["is_active"]:
                    content = Div(
                        create_error_message("Your account has been deactivated."),
                        P("Please contact support for assistance."),
                        P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
                    )
                    return Titled("Account Deactivated", create_auth_layout(
                        content,
                        page_title="Account Deactivated",
                        page_subtitle="Account access disabled"
                    ))
                
                # Update OAuth token information
                from datetime import datetime, timedelta
                expires_at = None
                if token_data.get("expires_in"):
                    expires_at = datetime.now() + timedelta(seconds=token_data["expires_in"])
                
                oauth_service.link_oauth_account(
                    user_id=existing_user["id"],
                    provider=provider,
                    provider_user_id=user_info["provider_user_id"],
                    provider_email=user_info["email"],
                    access_token=token_data["access_token"],
                    refresh_token=token_data.get("refresh_token"),
                    expires_at=expires_at
                )
                
                # Create session and log user in
                client_ip = request.client.host if hasattr(request, 'client') else None
                user_agent = request.headers.get('user-agent')
                
                session_id = auth_service.create_session(db, existing_user["id"], client_ip, user_agent)
                store_session(session_id, existing_user["id"])
                
                # Update login timestamp
                db.update_user_login(existing_user["id"], reset_failed_attempts=True)
                
                return RedirectResponse("/dashboard", status_code=302)
            
            else:
                # Check if user exists with same email (for account linking)
                email_user = oauth_service.find_user_by_email(user_info["email"])
                
                if email_user:
                    # Account linking flow - user exists with same email
                    if not email_user["is_active"]:
                        content = Div(
                            create_error_message("An account with this email is deactivated."),
                            P("Please contact support for assistance."),
                            P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
                        )
                        return Titled("Account Deactivated", create_auth_layout(
                            content,
                            page_title="Account Deactivated",
                            page_subtitle="Account access disabled"
                        ))
                    
                    # Link OAuth account to existing user
                    from datetime import datetime, timedelta
                    expires_at = None
                    if token_data.get("expires_in"):
                        expires_at = datetime.now() + timedelta(seconds=token_data["expires_in"])
                    
                    oauth_service.link_oauth_account(
                        user_id=email_user["id"],
                        provider=provider,
                        provider_user_id=user_info["provider_user_id"],
                        provider_email=user_info["email"],
                        access_token=token_data["access_token"],
                        refresh_token=token_data.get("refresh_token"),
                        expires_at=expires_at
                    )
                    
                    # Create session and log user in
                    client_ip = request.client.host if hasattr(request, 'client') else None
                    user_agent = request.headers.get('user-agent')
                    
                    session_id = auth_service.create_session(db, email_user["id"], client_ip, user_agent)
                    store_session(session_id, email_user["id"])
                    
                    # Update login timestamp
                    db.update_user_login(email_user["id"], reset_failed_attempts=True)
                    
                    return RedirectResponse("/dashboard", status_code=302)
                
                else:
                    # Create new user from OAuth information
                    from datetime import datetime, timedelta
                    expires_at = None
                    if token_data.get("expires_in"):
                        expires_at = datetime.now() + timedelta(seconds=token_data["expires_in"])
                    
                    user_id = oauth_service.create_user_from_oauth(
                        provider=provider,
                        user_info=user_info,
                        access_token=token_data["access_token"],
                        refresh_token=token_data.get("refresh_token"),
                        expires_at=expires_at
                    )
                    
                    if not user_id:
                        content = Div(
                            create_error_message("Failed to create user account."),
                            P("Please try again or contact support."),
                            P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
                        )
                        return Titled("Account Creation Failed", create_auth_layout(
                            content,
                            page_title="Account Creation Failed",
                            page_subtitle="Could not create account"
                        ))
                    
                    # Create session and log new user in
                    client_ip = request.client.host if hasattr(request, 'client') else None
                    user_agent = request.headers.get('user-agent')
                    
                    session_id = auth_service.create_session(db, user_id, client_ip, user_agent)
                    store_session(session_id, user_id)
                    
                    # Update login timestamp
                    db.update_user_login(user_id, reset_failed_attempts=True)
                    
                    return RedirectResponse("/dashboard", status_code=302)
        
        except Exception as e:
            print(f"OAuth callback processing error: {e}")
            content = Div(
                create_error_message("Failed to process OAuth login. Please try again."),
                P(A("Back to Login", href="/auth/login", cls="btn btn-primary"))
            )
            return Titled("OAuth Error", create_auth_layout(
                content,
                page_title="OAuth Login Failed",
                page_subtitle="An error occurred"
            ))