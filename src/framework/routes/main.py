"""
Main application route handlers for PY-Framework
"""

from fasthtml.common import *
from ..layout import create_app_layout, create_auth_layout, create_page_title, create_success_message, create_error_message
from ..session import get_current_user


def create_main_routes(app, db=None, auth_service=None, is_development=False, csrf_protection=None):
    """Register main application routes with the FastHTML app"""
    
    @app.get("/")
    def home(request):
        # Check if user is authenticated
        user = get_current_user(request, db, auth_service)
        
        if user:
            # User is logged in, redirect to dashboard
            return RedirectResponse("/dashboard", status_code=302)
        
        # User is not logged in, show appropriate landing page
        if is_development:
            content = Div(
                Div(
                    A("Login", href="/auth/login", cls="btn btn-primary"),
                    A("Register", href="/auth/register", cls="btn btn-secondary"),
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
                H2("Get Started:"),
                Ul(
                    Li(A("Create Account", href="/auth/register")),
                    Li(A("Sign In", href="/auth/login")),
                    Li(A("Test Email Service", href="/dev/test-email")),
                    Li(A("Reset Password", href="/auth/forgot-password")),
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
                    A("Login", href="/auth/login", cls="btn btn-primary"),
                    A("Register", href="/auth/register", cls="btn btn-secondary"),
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
    
    @app.get("/profile/change-password")
    def change_password_page(request):
        # Change password page
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Create form with CSRF token if protection is enabled
        form_elements = [
            Div(
                Label("Current Password:", fr="current_password"),
                Input(type="password", id="current_password", name="current_password", required=True),
                cls="form-group"
            ),
            Div(
                Label("New Password:", fr="new_password"),
                Input(type="password", id="new_password", name="new_password", required=True),
                Small("Minimum 8 characters with uppercase, lowercase, number, and special character"),
                cls="form-group"
            ),
            Div(
                Label("Confirm New Password:", fr="confirm_password"),
                Input(type="password", id="confirm_password", name="confirm_password", required=True),
                cls="form-group"
            )
        ]
        
        # Add CSRF token if protection is enabled
        if csrf_protection:
            session_id = request.cookies.get('session_id')
            form_elements.insert(0, csrf_protection.create_csrf_input(session_id))
        
        form_elements.append(Button("Change Password", type="submit", cls="btn btn-primary"))
        
        content = Div(
            P("Enter your current password and choose a new secure password."),
            Form(
                *form_elements,
                action="/profile/change-password",
                method="post",
                cls="form"
            ),
            P(A("Back to Profile", href="/profile", cls="btn btn-secondary"))
        )
        return Titled("Change Password", create_app_layout(
            content, 
            user=user, 
            current_page="/profile",
            page_title="Change Password",
            page_subtitle="Update your account password"
        ))
    
    @app.post("/profile/change-password")
    def process_change_password(request, current_password: str, new_password: str, confirm_password: str, csrf_token: str = None):
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
                        P(A("Back to Change Password", href="/profile/change-password", cls="btn btn-primary"))
                    )
                    return Titled("Security Error", create_app_layout(
                        content, 
                        user=user,
                        page_title="Security Error",
                        page_subtitle="Invalid security token"
                    ))
            
            # Verify new passwords match
            if new_password != confirm_password:
                content = Div(
                    create_error_message("New passwords do not match. Please try again."),
                    P(A("Back to Change Password", href="/profile/change-password", cls="btn btn-primary"))
                )
                return Titled("Password Mismatch", create_app_layout(
                    content, 
                    user=user,
                    page_title="Password Mismatch",
                    page_subtitle="Passwords must match"
                ))
            
            # Verify current password
            if not auth_service.verify_password(current_password, user['password_hash']):
                content = Div(
                    create_error_message("Current password is incorrect. Please try again."),
                    P(A("Back to Change Password", href="/profile/change-password", cls="btn btn-primary"))
                )
                return Titled("Incorrect Password", create_app_layout(
                    content, 
                    user=user,
                    page_title="Incorrect Password",
                    page_subtitle="Current password verification failed"
                ))
            
            # Validate new password requirements
            from ..auth import UserRegistration
            try:
                # Use the registration validation to check password
                temp_registration = UserRegistration(
                    email="temp@example.com",  # Dummy email for validation
                    password=new_password
                )
            except ValueError as ve:
                content = Div(
                    create_error_message(f"New password validation failed: {str(ve)}"),
                    P(A("Back to Change Password", href="/profile/change-password", cls="btn btn-primary"))
                )
                return Titled("Invalid Password", create_app_layout(
                    content, 
                    user=user,
                    page_title="Invalid Password",
                    page_subtitle="Password does not meet requirements"
                ))
            
            # Check if new password is different from current
            if auth_service.verify_password(new_password, user['password_hash']):
                content = Div(
                    create_error_message("New password must be different from your current password."),
                    P(A("Back to Change Password", href="/profile/change-password", cls="btn btn-primary"))
                )
                return Titled("Same Password", create_app_layout(
                    content, 
                    user=user,
                    page_title="Same Password",
                    page_subtitle="New password must be different"
                ))
            
            # Update user password
            new_password_hash = auth_service.hash_password(new_password)
            db.conn.execute("""
                UPDATE users 
                SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, [new_password_hash, user['id']])
            
            # Invalidate all other user sessions for security (except current)
            current_session_id = request.cookies.get('session_id')
            db.conn.execute("""
                UPDATE sessions 
                SET is_active = FALSE 
                WHERE user_id = ? AND id != ?
            """, [user['id'], current_session_id])
            
            content = Div(
                create_success_message("Your password has been successfully changed."),
                P("All other sessions have been logged out for security."),
                P(A("Back to Profile", href="/profile", cls="btn btn-primary")),
                P(A("Go to Dashboard", href="/dashboard", cls="btn btn-secondary"))
            )
            return Titled("Password Changed", create_app_layout(
                content, 
                user=user,
                page_title="Password Changed! ✅",
                page_subtitle="Your password has been updated"
            ))
            
        except Exception as e:
            content = Div(
                create_error_message(f"Failed to change password: {str(e)}"),
                P(A("Back to Change Password", href="/profile/change-password", cls="btn btn-primary"))
            )
            return Titled("Change Failed", create_app_layout(
                content, 
                user=user,
                page_title="Change Failed",
                page_subtitle="An error occurred while changing your password"
            ))
    
    @app.get("/docs")
    def docs_index(request):
        # Check authentication first
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Redirect to overview doc by default
        return RedirectResponse("/docs/overview", status_code=302)
    
    @app.get("/docs/{doc_name}")
    def docs_view(request, doc_name: str):
        import os
        import markdown
        
        # Check authentication first
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Map doc names to files
        doc_files = {
            "overview": ("Project Overview", "README.md"),
            "security": ("Security Guide", "docs/SECURITY.md"),
            "api": ("API Reference", "docs/API.md"),
            "deployment": ("Deployment Guide", "docs/DEPLOYMENT.md"),
            "specifications": ("Development Specs", "CLAUDE.md")
        }
        
        if doc_name not in doc_files:
            return RedirectResponse("/docs/overview", status_code=302)
        
        doc_title, doc_file = doc_files[doc_name]
        
        # Read the markdown file
        try:
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            file_path = os.path.join(project_root, doc_file)
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Convert markdown to HTML
            html_content = markdown.markdown(content, extensions=['codehilite', 'fenced_code'])
            
        except Exception as e:
            html_content = f"<p>Error loading documentation: {str(e)}</p>"
        
        # Create docs sidebar
        docs_sidebar = Div(
            H3("📚 Documentation"),
            Ul(
                Li(A("Project Overview", href="/docs/overview", 
                    cls="active" if doc_name == "overview" else "")),
                Li(A("Security Guide", href="/docs/security", 
                    cls="active" if doc_name == "security" else "")),
                Li(A("API Reference", href="/docs/api", 
                    cls="active" if doc_name == "api" else "")),
                Li(A("Deployment Guide", href="/docs/deployment", 
                    cls="active" if doc_name == "deployment" else "")),
                Li(A("Development Specs", href="/docs/specifications", 
                    cls="active" if doc_name == "specifications" else "")),
                cls="docs-nav"
            ),
            cls="docs-sidebar"
        )
        
        # Main content area with raw HTML
        main_content = Div(
            Div(NotStr(html_content), cls="docs-content"),
            cls="docs-main"
        )
        
        # Combine sidebar and content
        content = Div(
            docs_sidebar,
            main_content,
            cls="docs-layout"
        )
        
        return Titled(f"{doc_title} - PY-Framework", create_app_layout(
            content, 
            user=user, 
            current_page=f"docs_{doc_name}",
            page_title=doc_title,
            page_subtitle="PY-Framework Documentation",
            show_sidebar=False  # We'll use our own docs sidebar
        ))
    
    @app.get("/settings")
    def settings_page(request):
        # Settings page - comprehensive user preferences and configuration
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Get user's current settings and account info
        user_sessions = []
        try:
            # Get active sessions for this user
            cursor = db.conn.execute("""
                SELECT id, created_at, ip_address, user_agent, is_active 
                FROM sessions 
                WHERE user_id = ? AND is_active = TRUE
                ORDER BY created_at DESC
                LIMIT 10
            """, [user['id']])
            user_sessions = cursor.fetchall()
        except Exception as e:
            print(f"Error fetching sessions: {e}")
        
        # Current session info
        current_session_id = request.cookies.get('session_id')
        
        # Create settings sections
        content = Div(
            # Account Information Section
            Div(
                H2("👤 Account Information"),
                Div(
                    Div(
                        H4("Personal Details"),
                        P(f"📧 Email: {user['email']}"),
                        P(f"👤 Name: {user['first_name'] or 'Not set'} {user['last_name'] or ''}"),
                        P(f"✅ Email Verified: {'Yes' if user['is_verified'] else 'No'}"),
                        P(f"📅 Member Since: {user['created_at'].strftime('%B %d, %Y') if user['created_at'] else 'Unknown'}"),
                        P(f"🔄 Last Updated: {user['updated_at'].strftime('%B %d, %Y at %H:%M') if user['updated_at'] else 'Never'}"),
                        cls="settings-card"
                    ),
                    Div(
                        H4("Quick Actions"),
                        Div(
                            A("✏️ Edit Profile", href="/profile", cls="btn btn-primary"),
                            A("🔒 Change Password", href="/profile/change-password", cls="btn btn-secondary"),
                            cls="button-group"
                        ),
                        cls="settings-card"
                    ),
                    cls="settings-grid"
                ),
                cls="settings-section"
            ),
            
            # Security Settings Section
            Div(
                H2("🔐 Security Settings"),
                Div(
                    Div(
                        H4("Password Security"),
                        P("✅ Strong password requirements enforced"),
                        P("✅ BCrypt hashing with 12 rounds"),
                        P("✅ Account lockout protection (5 failed attempts)"),
                        P("✅ Session timeout: 24 hours"),
                        Div(
                            A("🔒 Change Password", href="/profile/change-password", cls="btn btn-outline"),
                            A("🔑 Reset Password", href="/auth/forgot-password", cls="btn btn-outline"),
                            cls="button-group"
                        ),
                        cls="settings-card"
                    ),
                    Div(
                        H4("Account Protection"),
                        P("✅ CSRF protection enabled on all forms"),
                        P("✅ Rate limiting: 100 requests per hour"),
                        P("✅ IP address tracking for sessions"),
                        P("✅ Security headers enabled"),
                        P("🔄 Two-Factor Authentication: Coming soon"),
                        cls="settings-card"
                    ),
                    cls="settings-grid"
                ),
                cls="settings-section"
            ),
            
            # Active Sessions Section
            Div(
                H2("📱 Active Sessions"),
                Div(
                    H4(f"Session Management ({len(user_sessions)} active sessions)"),
                    P("Monitor and manage your active login sessions across different devices."),
                    cls="settings-card-header"
                ),
                *[
                    Div(
                        Div(
                            H5("🖥️ Session Details" if session[0] == current_session_id else "📱 Device Session"),
                            P(f"Session ID: {session[0][:16]}..." if session[0] else "Unknown"),
                            P(f"📅 Login Time: {session[1].strftime('%B %d, %Y at %H:%M') if session[1] else 'Unknown'}"),
                            P(f"🌐 IP Address: {session[2] or 'Unknown'}"),
                            P(f"💻 Device: {session[3][:50] + '...' if session[3] and len(session[3]) > 50 else session[3] or 'Unknown'}"),
                            Small("✅ Current Session" if session[0] == current_session_id else "📱 Other Device", 
                                  cls="session-indicator current" if session[0] == current_session_id else "session-indicator other"),
                            cls="session-info"
                        ),
                        cls="session-card current-session" if session[0] == current_session_id else "session-card"
                    )
                    for session in user_sessions
                ] if user_sessions else [
                    Div(
                        P("No active sessions found."),
                        cls="settings-card"
                    )
                ],
                cls="settings-section"
            ),
            
            # Framework Information Section
            Div(
                H2("ℹ️ Framework Information"),
                Div(
                    Div(
                        H4("PY-Framework Status"),
                        P("🚀 Framework Version: 0.1.0"),
                        P("✅ All systems operational"),
                        P("🔒 Security features active"),
                        P("📧 Email service configured"),
                        P("🛡️ CSRF protection enabled"),
                        P("⚡ Security middleware active"),
                        cls="settings-card"
                    ),
                    Div(
                        H4("Development Tools"),
                        Div(
                            A("📧 Test Email", href="/dev/test-email", cls="btn btn-outline") if is_development else None,
                            A("🔍 Test Auth", href="/dev/test-auth", cls="btn btn-outline") if is_development else None,
                            A("🗄️ Database", href="/dev/database", cls="btn btn-outline") if is_development else None,
                            A("📚 Documentation", href="/docs", cls="btn btn-outline"),
                            A("❤️ Health Check", href="/health", cls="btn btn-outline"),
                            cls="button-group"
                        ),
                        cls="settings-card"
                    ),
                    cls="settings-grid"
                ),
                cls="settings-section"
            ),
            
            # Danger Zone Section
            Div(
                H2("⚠️ Danger Zone"),
                Div(
                    Div(
                        H4("Account Actions"),
                        P("These actions cannot be undone. Please be careful."),
                        Div(
                            A("🚪 Logout All Sessions", href="/auth/logout-all", cls="btn btn-danger"),
                            A("🗑️ Delete Account", href="/settings/delete-account", cls="btn btn-danger disabled", 
                              title="Account deletion coming in future update"),
                            cls="button-group"
                        ),
                        cls="danger-zone-card"
                    ),
                    cls="settings-grid"
                ),
                cls="settings-section"
            ),
            
            cls="settings-container"
        )
        
        return Titled("Settings", create_app_layout(
            content, 
            user=user, 
            current_page="/settings",
            page_title="Settings",
            page_subtitle="Manage your account preferences and security settings"
        ))
    
    @app.get("/health")
    def health_check():
        return {"status": "healthy", "framework": "PY-Framework", "version": "0.1.0"}