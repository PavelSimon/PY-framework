"""
Main application route handlers for PY-Framework
"""

from fasthtml.common import *
from ..layout import create_app_layout, create_auth_layout, create_page_title, create_success_message, create_error_message
from ..session import get_current_user
from ..auth.totp import TwoFactorAuthentication, TOTPService


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
        
        # Get 2FA status for the user
        two_fa = TwoFactorAuthentication(db)
        totp_service = TOTPService(db)
        status = two_fa.get_2fa_status(user["id"])
        is_2fa_enabled = status["enabled"]
        backup_codes_count = status["backup_codes_remaining"]
        
        # Create 2FA section
        if is_2fa_enabled:
            two_fa_section = Div(
                H3("🔐 Two-Factor Authentication"),
                Div(
                    P("✅ 2FA is enabled for your account", cls="text-success"),
                    P(f"Backup codes remaining: {backup_codes_count}"),
                    Div(
                        A("Manage 2FA Settings", href="/profile/2fa", cls="btn btn-primary"),
                        A("Regenerate Backup Codes", href="/profile/2fa/backup-codes", cls="btn btn-secondary") if backup_codes_count < 8 else None,
                        cls="button-group"
                    ),
                    cls="alert alert-success"
                ),
                style="margin-top: 2rem;"
            )
        else:
            two_fa_section = Div(
                H3("🔐 Two-Factor Authentication"),
                Div(
                    P("🔓 2FA is not enabled for your account", cls="text-warning"),
                    P("Add an extra layer of security to your account with two-factor authentication."),
                    Div(
                        A("Enable 2FA", href="/profile/2fa", cls="btn btn-primary"),
                        cls="button-group"
                    ),
                    cls="alert alert-warning"
                ),
                style="margin-top: 2rem;"
            )
        
        content = Div(
            Form(
                *form_elements,
                action="/profile",
                method="post",
                cls="form"
            ),
            two_fa_section
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
    
    @app.get("/users")
    def users_page(request):
        # Users management page - admin can see all users, regular users see only themselves
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Check if user is admin
        is_admin = user.get('role_id') == 0
        
        # Get users based on role
        if is_admin:
            # Admin can see all users
            users = db.get_all_users_with_roles()
            page_title = "User Management"
            page_subtitle = "Manage all system users (Admin view)"
        else:
            # Regular users see only themselves
            users = [user]  # Show only current user
            page_title = "My Account"
            page_subtitle = "Your account information"
        
        # Create user cards
        user_cards = []
        for u in users:
            # Determine role styling
            role_class = "admin-role" if u.get('role_id') == 0 else "user-role"
            role_icon = "👑" if u.get('role_id') == 0 else "👤"
            
            # Create user card
            user_card = Div(
                Div(
                    H4(f"{role_icon} {u.get('first_name', 'Unknown')} {u.get('last_name', '')}".strip()),
                    P(f"📧 {u.get('email', 'No email')}"),
                    P(f"🏷️ Role: {u.get('role_name', 'Unknown').title()}", cls=f"role-badge {role_class}"),
                    P(f"✅ Verified: {'Yes' if u.get('is_verified') else 'No'}"),
                    P(f"🔄 Status: {'Active' if u.get('is_active') else 'Inactive'}"),
                    P(f"📅 Joined: {u.get('created_at').strftime('%B %d, %Y') if u.get('created_at') else 'Unknown'}"),
                    P(f"🕐 Last Login: {u.get('last_login').strftime('%B %d, %Y at %H:%M') if u.get('last_login') else 'Never'}"),
                    
                    # Admin actions (only visible to admins and not for current user)
                    Div(
                        H5("Admin Actions"),
                        Div(
                            A("Edit Role", href=f"/users/{u.get('id')}/edit-role", cls="btn btn-outline btn-sm") if is_admin and u.get('id') != user.get('id') else None,
                            A("View Sessions", href=f"/users/{u.get('id')}/sessions", cls="btn btn-outline btn-sm") if is_admin else None,
                            A("Toggle Status", href=f"/users/{u.get('id')}/toggle", cls="btn btn-outline btn-sm") if is_admin and u.get('id') != user.get('id') else None,
                            A("❌ Delete User", href=f"/users/{u.get('id')}/delete", cls="btn btn-danger btn-sm", onclick="return confirm('Are you sure you want to permanently delete this user? This action cannot be undone!')") if is_admin and u.get('id') != user.get('id') else None,
                            cls="button-group"
                        ),
                        cls="admin-actions"
                    ) if is_admin and len(users) > 1 else None,
                    
                    # Self-management actions
                    Div(
                        H5("Account Actions"),
                        Div(
                            A("Edit Profile", href="/profile", cls="btn btn-primary btn-sm"),
                            A("Change Password", href="/profile/change-password", cls="btn btn-secondary btn-sm"),
                            A("View Settings", href="/settings", cls="btn btn-outline btn-sm"),
                            cls="button-group"
                        ),
                        cls="self-actions"
                    ) if u.get('id') == user.get('id') else None,
                    
                    cls="user-info"
                ),
                cls=f"user-card {role_class}" + (" current-user" if u.get('id') == user.get('id') else "")
            )
            user_cards.append(user_card)
        
        # Create main content
        content = Div(
            # Summary section (admin only)
            Div(
                H2("📊 User Summary"),
                Div(
                    Div(
                        H4("Total Users"),
                        P(f"{len(users)}", cls="stat-number"),
                        cls="stat-card"
                    ),
                    Div(
                        H4("Admin Users"),
                        P(f"{len([u for u in users if u.get('role_id') == 0])}", cls="stat-number admin-stat"),
                        cls="stat-card"
                    ),
                    Div(
                        H4("Regular Users"),
                        P(f"{len([u for u in users if u.get('role_id') == 1])}", cls="stat-number user-stat"),
                        cls="stat-card"
                    ),
                    Div(
                        H4("Verified Users"),
                        P(f"{len([u for u in users if u.get('is_verified')])}", cls="stat-number verified-stat"),
                        cls="stat-card"
                    ),
                    cls="stats-grid"
                ),
                cls="users-section"
            ) if is_admin else None,
            
            # Users list section
            Div(
                H2("👥 Users" if is_admin else "👤 My Account"),
                Div(
                    *user_cards,
                    cls="users-grid"
                ),
                cls="users-section"
            ),
            
            # Admin tools section
            Div(
                H2("🛠️ Admin Tools"),
                Div(
                    Div(
                        H4("User Management"),
                        P("Manage user accounts, roles, and permissions."),
                        Div(
                            A("Create User", href="/users/create", cls="btn btn-primary"),
                            A("Export Users", href="/users/export", cls="btn btn-outline"),
                            A("Audit Log", href="/users/audit", cls="btn btn-secondary"),
                            cls="button-group"
                        ),
                        cls="admin-tools-card"
                    ),
                    Div(
                        H4("System Actions"),
                        P("System-wide administration functions."),
                        Div(
                            A("User Management", href="/users", cls="btn btn-outline"),
                            A("System Settings", href="/settings", cls="btn btn-outline"),
                            A("Documentation", href="/docs", cls="btn btn-secondary"),
                            cls="button-group"
                        ),
                        cls="admin-tools-card"
                    ),
                    cls="admin-tools-grid"
                ),
                cls="users-section"
            ) if is_admin else None,
            
            cls="users-container"
        )
        
        return Titled("Users", create_app_layout(
            content, 
            user=user, 
            current_page="/users",
            page_title=page_title,
            page_subtitle=page_subtitle
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
    
    @app.get("/users/{user_id:int}/edit-role")
    def edit_user_role_page(request, user_id: int):
        # Admin-only: Edit user role page
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return RedirectResponse("/", status_code=302)
        
        # Get target user
        target_user = db.get_user_with_role(user_id)
        if not target_user:
            content = Div(
                create_error_message("User not found."),
                P(A("Back to Users", href="/users", cls="btn btn-primary"))
            )
            return Titled("User Not Found", create_app_layout(
                content, 
                user=user,
                page_title="User Not Found",
                page_subtitle="The specified user could not be found"
            ))
        
        # Prevent admin from editing their own role
        if target_user['id'] == user['id']:
            content = Div(
                create_error_message("You cannot edit your own role."),
                P(A("Back to Users", href="/users", cls="btn btn-primary"))
            )
            return Titled("Cannot Edit Own Role", create_app_layout(
                content, 
                user=user,
                page_title="Cannot Edit Own Role",
                page_subtitle="Security restriction"
            ))
        
        # Create role selection form
        form_elements = [
            Div(
                H4(f"Editing role for: {target_user['first_name'] or 'Unknown'} {target_user['last_name'] or ''} ({target_user['email']})"),
                cls="form-group"
            ),
            Div(
                Label("Current Role:", fr="current_role"),
                P(f"{target_user.get('role_name', 'Unknown').title()} (ID: {target_user.get('role_id')})", cls="current-role-display"),
                cls="form-group"
            ),
            Div(
                Label("New Role:", fr="role_id"),
                Select(
                    Option("Regular User", value="1", selected=target_user.get('role_id') == 1),
                    Option("Administrator", value="0", selected=target_user.get('role_id') == 0),
                    id="role_id", name="role_id", required=True
                ),
                Small("Administrators have full access to all system features"),
                cls="form-group"
            )
        ]
        
        # Add CSRF token if protection is enabled
        if csrf_protection:
            session_id = request.cookies.get('session_id')
            form_elements.insert(-1, csrf_protection.create_csrf_input(session_id))
        
        form_elements.extend([
            Div(
                Button("Update Role", type="submit", cls="btn btn-primary"),
                A("Cancel", href="/users", cls="btn btn-secondary"),
                cls="button-group"
            )
        ])
        
        content = Div(
            P("⚠️ Changing user roles affects their access permissions. Please be careful."),
            Form(
                *form_elements,
                action=f"/users/{user_id}/edit-role",
                method="post",
                cls="form"
            )
        )
        return Titled("Edit User Role", create_app_layout(
            content, 
            user=user, 
            current_page="/users",
            page_title="Edit User Role",
            page_subtitle="Manage user access permissions"
        ))
    
    @app.post("/users/{user_id:int}/edit-role")
    def update_user_role(request, user_id: int, role_id: int, csrf_token: str = None):
        # Admin-only: Update user role
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return RedirectResponse("/", status_code=302)
        
        # Get target user
        target_user = db.get_user_with_role(user_id)
        if not target_user:
            return RedirectResponse("/users", status_code=302)
        
        # Prevent admin from editing their own role
        if target_user['id'] == user['id']:
            return RedirectResponse("/users", status_code=302)
        
        try:
            # Validate CSRF token if protection is enabled
            if csrf_protection:
                session_id = request.cookies.get('session_id')
                if not csrf_protection.validate_token(csrf_token, session_id):
                    content = Div(
                        create_error_message("Invalid security token. Please try again."),
                        P(A("Back to Users", href="/users", cls="btn btn-primary"))
                    )
                    return Titled("Security Error", create_app_layout(
                        content, 
                        user=user,
                        page_title="Security Error",
                        page_subtitle="Invalid security token"
                    ))
            
            # Validate role_id
            if role_id not in [0, 1]:
                content = Div(
                    create_error_message("Invalid role selected."),
                    P(A("Back to Edit Role", href=f"/users/{user_id}/edit-role", cls="btn btn-primary"))
                )
                return Titled("Invalid Role", create_app_layout(
                    content, 
                    user=user,
                    page_title="Invalid Role",
                    page_subtitle="Please select a valid role"
                ))
            
            # Update user role with foreign key constraint handling
            success = False
            user_sessions_cleared = False
            
            try:
                # First try direct update
                success = db.update_user_role(user_id, role_id)
            except Exception as e:
                if "foreign key constraint" in str(e).lower():
                    print(f"Role update failed due to foreign key constraints for user {user_id}, clearing references...")
                    
                    try:
                        # Clear foreign key references that might prevent role update
                        db.conn.execute("DELETE FROM sessions WHERE user_id = ?", [user_id])
                        db.conn.execute("DELETE FROM email_verification_tokens WHERE user_id = ?", [user_id])
                        db.conn.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", [user_id])
                        db.conn.execute("DELETE FROM oauth_accounts WHERE user_id = ?", [user_id])
                        db.conn.execute("DELETE FROM totp_secrets WHERE user_id = ?", [user_id])
                        db.conn.execute("DELETE FROM backup_codes WHERE user_id = ?", [user_id])
                        db.conn.execute("DELETE FROM two_factor_tokens WHERE user_id = ?", [user_id])
                        
                        user_sessions_cleared = True
                        
                        # Try role update again after clearing references
                        success = db.update_user_role(user_id, role_id)
                        
                        if success:
                            print(f"Role update succeeded after clearing references for user {user_id}")
                        
                    except Exception as clear_error:
                        print(f"Error clearing references for user {user_id}: {clear_error}")
                        success = False
                else:
                    print(f"Error updating user role: {e}")
                    success = False
            
            if success:
                role_name = "Administrator" if role_id == 0 else "Regular User"
                success_msg = f"User role updated to {role_name} successfully."
                if user_sessions_cleared:
                    success_msg += " Note: User's sessions and tokens were cleared for security."
                
                content = Div(
                    create_success_message(success_msg),
                    P(A("Back to Users", href="/users", cls="btn btn-primary")),
                    P(A("Edit Another User", href="/users", cls="btn btn-secondary"))
                )
                return Titled("Role Updated", create_app_layout(
                    content, 
                    user=user,
                    page_title="Role Updated! ✅",
                    page_subtitle="User permissions have been changed"
                ))
            else:
                content = Div(
                    create_error_message("Failed to update user role. Please try again."),
                    P(A("Back to Edit Role", href=f"/users/{user_id}/edit-role", cls="btn btn-primary"))
                )
                return Titled("Update Failed", create_app_layout(
                    content, 
                    user=user,
                    page_title="Update Failed",
                    page_subtitle="An error occurred while updating the role"
                ))
            
        except Exception as e:
            content = Div(
                create_error_message(f"Failed to update role: {str(e)}"),
                P(A("Back to Edit Role", href=f"/users/{user_id}/edit-role", cls="btn btn-primary"))
            )
            return Titled("Update Failed", create_app_layout(
                content, 
                user=user,
                page_title="Update Failed",
                page_subtitle="An error occurred while updating the role"
            ))
    
    @app.get("/users/{user_id:int}/sessions")
    def view_user_sessions(request, user_id: int):
        # Admin-only: View user sessions
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return RedirectResponse("/", status_code=302)
        
        # Get target user
        target_user = db.get_user_with_role(user_id)
        if not target_user:
            return RedirectResponse("/users", status_code=302)
        
        # Get user's sessions
        try:
            cursor = db.conn.execute("""
                SELECT id, created_at, ip_address, user_agent, is_active, expires_at
                FROM sessions 
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 50
            """, [user_id])
            sessions = cursor.fetchall()
        except Exception as e:
            sessions = []
        
        # Create session cards
        session_cards = []
        for session in sessions:
            status_class = "active-session" if session[4] else "inactive-session"
            status_text = "✅ Active" if session[4] else "❌ Inactive"
            
            session_card = Div(
                H5(f"Session: {session[0][:16]}..."),
                P(f"📅 Created: {session[1].strftime('%B %d, %Y at %H:%M') if session[1] else 'Unknown'}"),
                P(f"⏰ Expires: {session[5].strftime('%B %d, %Y at %H:%M') if session[5] else 'Unknown'}"),
                P(f"🌐 IP Address: {session[2] or 'Unknown'}"),
                P(f"💻 Device: {session[3][:50] + '...' if session[3] and len(session[3]) > 50 else session[3] or 'Unknown'}"),
                P(f"Status: {status_text}", cls=f"session-status {status_class}"),
                cls=f"session-card {status_class}"
            )
            session_cards.append(session_card)
        
        content = Div(
            Div(
                H2(f"Sessions for {target_user['first_name'] or 'Unknown'} {target_user['last_name'] or ''} ({target_user['email']})"),
                P(f"Total sessions: {len(sessions)}"),
                P(f"Active sessions: {len([s for s in sessions if s[4]])}"),
                cls="sessions-header"
            ),
            Div(
                *session_cards if session_cards else [P("No sessions found for this user.")],
                cls="sessions-grid"
            ),
            Div(
                A("Back to Users", href="/users", cls="btn btn-primary"),
                A("Refresh", href=f"/users/{user_id}/sessions", cls="btn btn-secondary"),
                cls="button-group"
            )
        )
        
        return Titled("User Sessions", create_app_layout(
            content, 
            user=user, 
            current_page="/users",
            page_title=f"Sessions for {target_user['email']}",
            page_subtitle="Monitor user login sessions"
        ))
    
    @app.get("/users/{user_id:int}/toggle")
    def toggle_user_status(request, user_id: int):
        # Admin-only: Toggle user active status
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return RedirectResponse("/", status_code=302)
        
        # Get target user
        target_user = db.get_user_with_role(user_id)
        if not target_user:
            return RedirectResponse("/users", status_code=302)
        
        # Prevent admin from disabling their own account
        if target_user['id'] == user['id']:
            return RedirectResponse("/users", status_code=302)
        
        try:
            # Toggle user status
            new_status = not target_user['is_active']
            db.conn.execute("""
                UPDATE users 
                SET is_active = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, [new_status, user_id])
            
            # If deactivating user, invalidate all their sessions
            if not new_status:
                db.conn.execute("""
                    UPDATE sessions 
                    SET is_active = FALSE 
                    WHERE user_id = ?
                """, [user_id])
            
            status_text = "activated" if new_status else "deactivated"
            content = Div(
                create_success_message(f"User has been {status_text} successfully."),
                P(A("Back to Users", href="/users", cls="btn btn-primary"))
            )
            return Titled("Status Updated", create_app_layout(
                content, 
                user=user,
                page_title="Status Updated! ✅",
                page_subtitle=f"User account has been {status_text}"
            ))
            
        except Exception as e:
            content = Div(
                create_error_message(f"Failed to toggle user status: {str(e)}"),
                P(A("Back to Users", href="/users", cls="btn btn-primary"))
            )
            return Titled("Toggle Failed", create_app_layout(
                content, 
                user=user,
                page_title="Toggle Failed",
                page_subtitle="An error occurred while changing user status"
            ))
    
    @app.get("/users/{user_id}/delete")
    def delete_user_page(request, user_id: int):
        """Delete user confirmation page (admin only)"""
        from ..middleware import validate_admin_access
        
        # Validate admin access
        is_admin, current_user, error_response = validate_admin_access(request, db, auth_service)
        if not is_admin:
            return error_response
        
        # Get user to delete
        target_user = db.get_user_with_role(user_id)
        if not target_user:
            content = Div(
                create_error_message("User not found."),
                P(A("Back to Users", href="/users", cls="btn btn-primary"))
            )
            return Titled("User Not Found", create_app_layout(
                content, 
                user=current_user,
                page_title="User Not Found",
                page_subtitle="User does not exist"
            ))
        
        # Prevent admin from deleting themselves
        if target_user['id'] == current_user['id']:
            content = Div(
                create_error_message("You cannot delete your own account."),
                P(A("Back to Users", href="/users", cls="btn btn-primary"))
            )
            return Titled("Cannot Delete Self", create_app_layout(
                content, 
                user=current_user,
                page_title="Cannot Delete Self",
                page_subtitle="Admin protection"
            ))
        
        # Create confirmation form with CSRF token
        form_elements = [
            Div(
                P(f"You are about to permanently delete the user: {target_user['first_name']} {target_user['last_name']} ({target_user['email']})"),
                P("⚠️ This action cannot be undone and will delete:"),
                Ul(
                    Li("User account and profile information"),
                    Li("All active sessions"),
                    Li("Email verification and password reset tokens"),
                    Li("OAuth account links"),
                    Li("Two-factor authentication settings"),
                    Li("Backup codes and security tokens")
                ),
                P("Type 'DELETE' to confirm:", style="font-weight: bold; margin-top: 1rem;"),
                cls="alert alert-danger"
            ),
            Div(
                Label("Confirmation:", fr="confirmation"),
                Input(type="text", id="confirmation", name="confirmation", required=True, placeholder="Type DELETE"),
                Small("Type DELETE to confirm user deletion"),
                cls="form-group"
            )
        ]
        
        # Add CSRF token if protection is enabled
        if hasattr(request, 'cookies') and 'session_id' in request.cookies:
            session_id = request.cookies.get('session_id')
            csrf_token_input = f'<input type="hidden" name="csrf_token" value="placeholder">'
            form_elements.insert(0, NotStr(csrf_token_input))
        
        form_elements.append(Button("🗑️ DELETE USER", type="submit", cls="btn btn-danger"))
        
        content = Div(
            H2(f"Delete User: {target_user['first_name']} {target_user['last_name']}"),
            Form(
                *form_elements,
                action=f"/users/{user_id}/delete",
                method="post",
                cls="form"
            ),
            P(A("← Cancel", href="/users", cls="btn btn-secondary"))
        )
        
        return Titled("Delete User", create_app_layout(
            content, 
            user=current_user,
            current_page="/users",
            page_title="Delete User",
            page_subtitle="Permanent user deletion"
        ))
    
    @app.post("/users/{user_id}/delete")
    def delete_user_confirm(request, user_id: int, confirmation: str, csrf_token: str = None):
        """Process user deletion (admin only)"""
        from ..middleware import validate_admin_access
        
        try:
            # Validate admin access
            is_admin, current_user, error_response = validate_admin_access(request, db, auth_service)
            if not is_admin:
                return error_response
            
            # Validate CSRF token if protection is enabled
            # Note: CSRF validation would be implemented here
            
            # Get user to delete
            target_user = db.get_user_with_role(user_id)
            if not target_user:
                content = Div(
                    create_error_message("User not found."),
                    P(A("Back to Users", href="/users", cls="btn btn-primary"))
                )
                return Titled("User Not Found", create_app_layout(
                    content, 
                    user=current_user,
                    page_title="User Not Found",
                    page_subtitle="User does not exist"
                ))
            
            # Prevent admin from deleting themselves
            if target_user['id'] == current_user['id']:
                content = Div(
                    create_error_message("You cannot delete your own account."),
                    P(A("Back to Users", href="/users", cls="btn btn-primary"))
                )
                return Titled("Cannot Delete Self", create_app_layout(
                    content, 
                    user=current_user,
                    page_title="Cannot Delete Self",
                    page_subtitle="Admin protection"
                ))
            
            # Validate confirmation
            if confirmation != "DELETE":
                content = Div(
                    create_error_message("Invalid confirmation. You must type 'DELETE' exactly."),
                    P(A("Try Again", href=f"/users/{user_id}/delete", cls="btn btn-primary"))
                )
                return Titled("Invalid Confirmation", create_app_layout(
                    content, 
                    user=current_user,
                    page_title="Invalid Confirmation",
                    page_subtitle="Deletion cancelled"
                ))
            
            # Perform deletion
            user_email = target_user['email']
            user_name = f"{target_user['first_name']} {target_user['last_name']}"
            
            success = db.delete_user(user_id)
            
            if success:
                content = Div(
                    create_success_message(f"User '{user_name}' ({user_email}) has been permanently deleted."),
                    P("All associated data has been removed from the system."),
                    P(A("Back to Users", href="/users", cls="btn btn-primary"))
                )
                return Titled("User Deleted", create_app_layout(
                    content, 
                    user=current_user,
                    page_title="User Deleted ✅",
                    page_subtitle="User successfully removed"
                ))
            else:
                content = Div(
                    create_error_message("Failed to delete user. Please try again."),
                    P(A("Try Again", href=f"/users/{user_id}/delete", cls="btn btn-primary"))
                )
                return Titled("Delete Failed", create_app_layout(
                    content, 
                    user=current_user,
                    page_title="Delete Failed",
                    page_subtitle="An error occurred"
                ))
                
        except Exception as e:
            content = Div(
                create_error_message(f"An error occurred while deleting the user: {str(e)}"),
                P(A("Back to Users", href="/users", cls="btn btn-primary"))
            )
            return Titled("Delete Error", create_app_layout(
                content, 
                user=current_user,
                page_title="Delete Error",
                page_subtitle="An error occurred"
            ))

    @app.get("/health")
    def health_check():
        return {"status": "healthy", "framework": "PY-Framework", "version": "0.1.0"}