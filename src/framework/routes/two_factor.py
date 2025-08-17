"""
Two-Factor Authentication route handlers for PY-Framework
"""

from fasthtml.common import *
from starlette.responses import RedirectResponse, Response
import base64

from ..layout import create_app_layout, create_success_message, create_error_message, create_warning_message
from ..session import get_current_user
from ..csrf import csrf_protect
from ..auth.totp import TwoFactorAuthentication, TOTPService


def create_2fa_routes(app, db, auth_service, csrf_protection=None):
    """Register 2FA routes with the FastHTML app"""
    
    @app.get("/profile/2fa")
    def two_factor_settings(request):
        """2FA settings and management page"""
        user = get_current_user(request, db, auth_service)
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        two_fa = TwoFactorAuthentication(db)
        totp_service = TOTPService(db)
        
        # Get 2FA status
        status = two_fa.get_2fa_status(user["id"])
        is_enabled = status["enabled"]
        backup_codes_count = status["backup_codes_remaining"]
        
        if is_enabled:
            # Show 2FA management interface
            content = Div(
                H2("Two-Factor Authentication"),
                
                Div(
                    H3("✅ 2FA is Enabled"),
                    P("Your account is protected with two-factor authentication."),
                    P(f"Backup codes remaining: {backup_codes_count}"),
                    cls="alert alert-success"
                ),
                
                Div(
                    H4("Actions"),
                    Div(
                        A("🔄 Regenerate Backup Codes", 
                          href="/profile/2fa/backup-codes", 
                          cls="btn btn-secondary",
                          style="margin-right: 0.5rem;"),
                        A("❌ Disable 2FA", 
                          href="/profile/2fa/disable", 
                          cls="btn btn-danger",
                          onclick="return confirm('Are you sure you want to disable 2FA? This will make your account less secure.')"),
                    ),
                    style="margin: 1rem 0;"
                ),
                
                Div(
                    H4("⚠️ Important Security Information"),
                    Ul(
                        Li("Keep your authenticator app secure and backed up"),
                        Li("Store backup codes in a secure location"),
                        Li("If you lose access to your authenticator, use a backup code"),
                        Li("Contact support if you lose both your authenticator and backup codes")
                    ),
                    style="margin: 1rem 0; padding: 1rem; border: 1px solid #ffc107; border-radius: 4px; background-color: #fff3cd;"
                )
            )
        else:
            # Show 2FA setup interface
            content = Div(
                H2("Two-Factor Authentication"),
                
                Div(
                    H3("🔒 Secure Your Account"),
                    P("Two-factor authentication adds an extra layer of security to your account by requiring a verification code from your phone in addition to your password."),
                    cls="alert alert-info"
                ),
                
                Div(
                    H4("Benefits of 2FA:"),
                    Ul(
                        Li("🛡️ Protects against unauthorized access"),
                        Li("🔐 Secures your account even if password is compromised"),
                        Li("📱 Works with popular authenticator apps"),
                        Li("🆘 Includes backup codes for recovery")
                    ),
                    style="margin: 1rem 0;"
                ),
                
                Div(
                    H4("Setup Process:"),
                    Ol(
                        Li("Download an authenticator app (Google Authenticator, Authy, etc.)"),
                        Li("Scan the QR code with your authenticator app"),
                        Li("Enter the verification code to confirm setup"),
                        Li("Save your backup codes in a secure location")
                    ),
                    style="margin: 1rem 0;"
                ),
                
                Div(
                    A("🚀 Enable Two-Factor Authentication", 
                      href="/profile/2fa/setup", 
                      cls="btn btn-primary btn-lg"),
                    style="margin: 2rem 0; text-align: center;"
                )
            )
        
        return Titled("Two-Factor Authentication", create_app_layout(
            content,
            user=user,
            current_page="/profile/2fa",
            page_title="Two-Factor Authentication",
            page_subtitle="Secure your account with 2FA"
        ))
    
    @app.get("/profile/2fa/setup")
    def setup_2fa_page(request):
        """2FA setup page with QR code"""
        user = get_current_user(request, db, auth_service)
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Check if 2FA is already enabled
        totp_service = TOTPService(db)
        if totp_service.is_2fa_enabled(user["id"]):
            return RedirectResponse("/profile/2fa", status_code=302)
        
        # Generate QR code for setup
        two_fa = TwoFactorAuthentication(db)
        secret, totp_uri, qr_code = two_fa.setup_2fa(user["id"], user["email"])
        
        # Note: Secret is passed through the form as a hidden field for verification
        # This is secure since the form is CSRF protected and the secret is only used once
        
        # Convert QR code to base64 for display
        qr_code_b64 = base64.b64encode(qr_code).decode('utf-8')
        
        # Create form with CSRF token
        form_elements = [
            Input(type="hidden", name="secret", value=secret),
            Div(
                Label("Verification Code:", fr="verification_code"),
                Input(type="text", id="verification_code", name="verification_code", 
                      required=True, maxlength="6", pattern=r"\d{6}",
                      placeholder="123456"),
                Small("Enter the 6-digit code from your authenticator app"),
                cls="form-group"
            )
        ]
        
        # Add CSRF token if protection is enabled
        if csrf_protection:
            session_id = request.cookies.get('session_id')
            form_elements.insert(0, csrf_protection.create_csrf_input(session_id))
        
        form_elements.append(Button("Enable 2FA", type="submit", cls="btn btn-primary"))
        
        content = Div(
            H2("Setup Two-Factor Authentication"),
            
            Div(
                H3("Step 1: Install Authenticator App"),
                P("Download one of these authenticator apps on your phone:"),
                Ul(
                    Li("📱 Google Authenticator (iOS/Android)"),
                    Li("🔐 Authy (iOS/Android/Desktop)"),
                    Li("🛡️ Microsoft Authenticator (iOS/Android)"),
                    Li("🔒 1Password (Premium)")
                ),
                cls="setup-step"
            ),
            
            Div(
                H3("Step 2: Scan QR Code"),
                P("Open your authenticator app and scan this QR code:"),
                Div(
                    Img(src=f"data:image/png;base64,{qr_code_b64}", 
                        alt="2FA QR Code",
                        style="max-width: 256px; border: 1px solid #ddd; padding: 10px; background: white;"),
                    style="text-align: center; margin: 1rem 0;"
                ),
                Details(
                    Summary("Can't scan? Enter manually"),
                    P(f"Secret key: {secret}"),
                    P(f"Account: {user['email']}"),
                    P("Issuer: PY-Framework"),
                    style="margin: 1rem 0; padding: 1rem; border: 1px solid #ddd; border-radius: 4px;"
                ),
                cls="setup-step"
            ),
            
            Div(
                H3("Step 3: Verify Setup"),
                P("Enter the 6-digit code shown in your authenticator app:"),
                Form(
                    *form_elements,
                    action="/profile/2fa/setup",
                    method="post",
                    cls="form"
                ),
                cls="setup-step"
            ),
            
            P(A("← Back to Security Settings", href="/profile/2fa", cls="btn btn-secondary"))
        )
        
        return Titled("Setup 2FA", create_app_layout(
            content,
            user=user,
            current_page="/profile/2fa",
            page_title="Setup Two-Factor Authentication",
            page_subtitle="Secure your account with TOTP"
        ))
    
    @app.post("/profile/2fa/setup")
    def confirm_2fa_setup(request, secret: str, verification_code: str, csrf_token: str = None):
        """Confirm 2FA setup with verification code"""
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
                        P(A("Back to Setup", href="/profile/2fa/setup", cls="btn btn-primary"))
                    )
                    return Titled("Security Error", create_app_layout(
                        content,
                        user=user,
                        page_title="Security Error",
                        page_subtitle="Invalid security token"
                    ))
            
            # Check if 2FA is already enabled
            totp_service = TOTPService(db)
            if totp_service.is_2fa_enabled(user["id"]):
                return RedirectResponse("/profile/2fa", status_code=302)
            
            # Verify the setup
            two_fa = TwoFactorAuthentication(db)
            success, backup_codes = two_fa.confirm_2fa_setup(user["id"], secret, verification_code)
            
            if not success:
                content = Div(
                    create_error_message("Invalid verification code. Please check your authenticator app and try again."),
                    P(A("Back to Setup", href="/profile/2fa/setup", cls="btn btn-primary"))
                )
                return Titled("Setup Failed", create_app_layout(
                    content,
                    user=user,
                    page_title="2FA Setup Failed",
                    page_subtitle="Verification failed"
                ))
            
            # Show backup codes
            content = Div(
                H2("✅ Two-Factor Authentication Enabled!"),
                
                Div(
                    create_success_message("2FA has been successfully enabled for your account."),
                    cls="success-section"
                ),
                
                Div(
                    H3("🆘 Important: Save Your Backup Codes"),
                    P("Store these backup codes in a secure location. You can use them to access your account if you lose your authenticator device."),
                    P("⚠️ Each code can only be used once."),
                    
                    Div(
                        Pre(Code("\n".join(backup_codes)),
                            style="background: #f8f9fa; padding: 1rem; border: 1px solid #dee2e6; border-radius: 4px; font-family: monospace;"),
                        style="margin: 1rem 0;"
                    ),
                    
                    Div(
                        Button("📋 Copy Codes", 
                               onclick=f"navigator.clipboard.writeText('{chr(10).join(backup_codes)}'); this.textContent='✅ Copied!'; setTimeout(() => this.textContent='📋 Copy Codes', 2000);",
                               cls="btn btn-secondary",
                               style="margin-right: 0.5rem;"),
                        Button("🖨️ Print Codes", 
                               onclick="window.print();",
                               cls="btn btn-secondary"),
                        style="margin: 1rem 0;"
                    ),
                    
                    cls="backup-codes-section",
                    style="margin: 2rem 0; padding: 1rem; border: 2px solid #ffc107; border-radius: 4px; background-color: #fff3cd;"
                ),
                
                Div(
                    A("Continue to Security Settings", href="/profile/2fa", cls="btn btn-primary btn-lg"),
                    style="text-align: center; margin: 2rem 0;"
                )
            )
            
            return Titled("2FA Enabled", create_app_layout(
                content,
                user=user,
                current_page="/profile/2fa",
                page_title="2FA Successfully Enabled",
                page_subtitle="Your account is now more secure"
            ))
            
        except Exception as e:
            content = Div(
                create_error_message(f"An error occurred while setting up 2FA: {str(e)}"),
                P(A("Try again", href="/profile/2fa/setup", cls="btn btn-primary"))
            )
            return Titled("Setup Error", create_app_layout(
                content,
                user=user,
                page_title="2FA Setup Error",
                page_subtitle="An error occurred"
            ))
    
    @app.get("/profile/2fa/backup-codes")
    def regenerate_backup_codes_page(request):
        """Page to regenerate backup codes"""
        user = get_current_user(request, db, auth_service)
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Check if 2FA is enabled
        totp_service = TOTPService(db)
        if not totp_service.is_2fa_enabled(user["id"]):
            return RedirectResponse("/profile/2fa", status_code=302)
        
        # Create form with CSRF token
        form_elements = []
        
        # Add CSRF token if protection is enabled
        if csrf_protection:
            session_id = request.cookies.get('session_id')
            form_elements.append(csrf_protection.create_csrf_input(session_id))
        
        form_elements.append(Button("Generate New Backup Codes", type="submit", cls="btn btn-warning"))
        
        content = Div(
            H2("Regenerate Backup Codes"),
            
            Div(
                create_warning_message("This will generate new backup codes and invalidate all existing ones."),
                cls="warning-section"
            ),
            
            P("Backup codes allow you to access your account if you lose your authenticator device. Each code can only be used once."),
            
            P("⚠️ Make sure to save the new codes in a secure location before proceeding."),
            
            Form(
                *form_elements,
                action="/profile/2fa/backup-codes",
                method="post",
                cls="form",
                style="margin: 2rem 0;"
            ),
            
            P(A("← Back to 2FA Settings", href="/profile/2fa", cls="btn btn-secondary"))
        )
        
        return Titled("Regenerate Backup Codes", create_app_layout(
            content,
            user=user,
            current_page="/profile/2fa",
            page_title="Regenerate Backup Codes",
            page_subtitle="Generate new recovery codes"
        ))
    
    @app.post("/profile/2fa/backup-codes")
    def regenerate_backup_codes(request, csrf_token: str = None):
        """Generate new backup codes"""
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
                        P(A("Back", href="/profile/2fa/backup-codes", cls="btn btn-primary"))
                    )
                    return Titled("Security Error", create_app_layout(
                        content,
                        user=user,
                        page_title="Security Error",
                        page_subtitle="Invalid security token"
                    ))
            
            # Check if 2FA is enabled
            totp_service = TOTPService(db)
            if not totp_service.is_2fa_enabled(user["id"]):
                return RedirectResponse("/profile/2fa", status_code=302)
            
            # Generate new backup codes
            two_fa = TwoFactorAuthentication(db)
            backup_codes = two_fa.regenerate_backup_codes(user["id"])
            
            if not backup_codes:
                content = Div(
                    create_error_message("Failed to generate backup codes. Please try again."),
                    P(A("Try again", href="/profile/2fa/backup-codes", cls="btn btn-primary"))
                )
                return Titled("Generation Failed", create_app_layout(
                    content,
                    user=user,
                    page_title="Backup Code Generation Failed",
                    page_subtitle="An error occurred"
                ))
            
            # Show new backup codes
            content = Div(
                H2("✅ New Backup Codes Generated"),
                
                Div(
                    create_success_message("New backup codes have been generated. Your old codes are no longer valid."),
                    cls="success-section"
                ),
                
                Div(
                    H3("🆘 Save These Backup Codes"),
                    P("Store these codes in a secure location. Each code can only be used once."),
                    
                    Div(
                        Pre(Code("\n".join(backup_codes)),
                            style="background: #f8f9fa; padding: 1rem; border: 1px solid #dee2e6; border-radius: 4px; font-family: monospace;"),
                        style="margin: 1rem 0;"
                    ),
                    
                    Div(
                        Button("📋 Copy Codes", 
                               onclick=f"navigator.clipboard.writeText('{chr(10).join(backup_codes)}'); this.textContent='✅ Copied!'; setTimeout(() => this.textContent='📋 Copy Codes', 2000);",
                               cls="btn btn-secondary",
                               style="margin-right: 0.5rem;"),
                        Button("🖨️ Print Codes", 
                               onclick="window.print();",
                               cls="btn btn-secondary"),
                        style="margin: 1rem 0;"
                    ),
                    
                    cls="backup-codes-section",
                    style="margin: 2rem 0; padding: 1rem; border: 2px solid #ffc107; border-radius: 4px; background-color: #fff3cd;"
                ),
                
                Div(
                    A("Back to 2FA Settings", href="/profile/2fa", cls="btn btn-primary"),
                    style="text-align: center; margin: 2rem 0;"
                )
            )
            
            return Titled("New Backup Codes", create_app_layout(
                content,
                user=user,
                current_page="/profile/2fa",
                page_title="Backup Codes Regenerated",
                page_subtitle="Save your new recovery codes"
            ))
            
        except Exception as e:
            content = Div(
                create_error_message(f"An error occurred while generating backup codes: {str(e)}"),
                P(A("Try again", href="/profile/2fa/backup-codes", cls="btn btn-primary"))
            )
            return Titled("Generation Error", create_app_layout(
                content,
                user=user,
                page_title="Backup Code Generation Error",
                page_subtitle="An error occurred"
            ))
    
    @app.get("/profile/2fa/disable")
    def disable_2fa_page(request):
        """Page to disable 2FA"""
        user = get_current_user(request, db, auth_service)
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Check if 2FA is enabled
        totp_service = TOTPService(db)
        if not totp_service.is_2fa_enabled(user["id"]):
            return RedirectResponse("/profile/2fa", status_code=302)
        
        # Create form with CSRF token
        form_elements = [
            Div(
                Label("Current Password:", fr="password"),
                Input(type="password", id="password", name="password", required=True),
                Small("Enter your current password to confirm"),
                cls="form-group"
            ),
            Div(
                Label("Verification Code:", fr="verification_code"),
                Input(type="text", id="verification_code", name="verification_code", 
                      required=True, maxlength="6", pattern=r"\d{6}",
                      placeholder="123456"),
                Small("Enter code from your authenticator app or use a backup code"),
                cls="form-group"
            )
        ]
        
        # Add CSRF token if protection is enabled
        if csrf_protection:
            session_id = request.cookies.get('session_id')
            form_elements.insert(0, csrf_protection.create_csrf_input(session_id))
        
        form_elements.append(Button("Disable 2FA", type="submit", cls="btn btn-danger"))
        
        content = Div(
            H2("Disable Two-Factor Authentication"),
            
            Div(
                create_warning_message("⚠️ This will disable 2FA and make your account less secure."),
                cls="warning-section"
            ),
            
            P("Disabling two-factor authentication will:"),
            Ul(
                Li("Remove the requirement for verification codes when logging in"),
                Li("Delete all your backup codes"),
                Li("Make your account more vulnerable to unauthorized access")
            ),
            
            P("To disable 2FA, please confirm your identity:"),
            
            Form(
                *form_elements,
                action="/profile/2fa/disable",
                method="post",
                cls="form",
                style="margin: 2rem 0;"
            ),
            
            P(A("← Back to 2FA Settings", href="/profile/2fa", cls="btn btn-secondary"))
        )
        
        return Titled("Disable 2FA", create_app_layout(
            content,
            user=user,
            current_page="/profile/2fa",
            page_title="Disable Two-Factor Authentication",
            page_subtitle="Remove 2FA protection"
        ))
    
    @app.post("/profile/2fa/disable")
    def disable_2fa(request, password: str, verification_code: str, csrf_token: str = None):
        """Disable 2FA after verification"""
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
                        P(A("Back", href="/profile/2fa/disable", cls="btn btn-primary"))
                    )
                    return Titled("Security Error", create_app_layout(
                        content,
                        user=user,
                        page_title="Security Error",
                        page_subtitle="Invalid security token"
                    ))
            
            # Check if 2FA is enabled
            totp_service = TOTPService(db)
            if not totp_service.is_2fa_enabled(user["id"]):
                return RedirectResponse("/profile/2fa", status_code=302)
            
            # Verify password
            if not auth_service.verify_password(password, user["password_hash"]):
                content = Div(
                    create_error_message("Invalid password. Please try again."),
                    P(A("Back", href="/profile/2fa/disable", cls="btn btn-primary"))
                )
                return Titled("Invalid Password", create_app_layout(
                    content,
                    user=user,
                    page_title="Invalid Password",
                    page_subtitle="Password verification failed"
                ))
            
            # Verify 2FA code
            two_fa = TwoFactorAuthentication(db)
            if not two_fa.verify_2fa(user["id"], verification_code):
                content = Div(
                    create_error_message("Invalid verification code. Please check your authenticator app or use a backup code."),
                    P(A("Back", href="/profile/2fa/disable", cls="btn btn-primary"))
                )
                return Titled("Invalid Code", create_app_layout(
                    content,
                    user=user,
                    page_title="Invalid Verification Code",
                    page_subtitle="Code verification failed"
                ))
            
            # Disable 2FA
            if not two_fa.disable_2fa(user["id"]):
                content = Div(
                    create_error_message("Failed to disable 2FA. Please try again."),
                    P(A("Try again", href="/profile/2fa/disable", cls="btn btn-primary"))
                )
                return Titled("Disable Failed", create_app_layout(
                    content,
                    user=user,
                    page_title="2FA Disable Failed",
                    page_subtitle="An error occurred"
                ))
            
            # Success
            content = Div(
                H2("✅ Two-Factor Authentication Disabled"),
                
                Div(
                    create_success_message("2FA has been disabled for your account."),
                    cls="success-section"
                ),
                
                Div(
                    create_warning_message("Your account is now less secure. Consider enabling 2FA again for better protection."),
                    cls="warning-section"
                ),
                
                Div(
                    A("Back to Security Settings", href="/profile/2fa", cls="btn btn-primary"),
                    style="text-align: center; margin: 2rem 0;"
                )
            )
            
            return Titled("2FA Disabled", create_app_layout(
                content,
                user=user,
                current_page="/profile/2fa",
                page_title="2FA Disabled",
                page_subtitle="Two-factor authentication removed"
            ))
            
        except Exception as e:
            content = Div(
                create_error_message(f"An error occurred while disabling 2FA: {str(e)}"),
                P(A("Try again", href="/profile/2fa/disable", cls="btn btn-primary"))
            )
            return Titled("Disable Error", create_app_layout(
                content,
                user=user,
                page_title="2FA Disable Error",
                page_subtitle="An error occurred"
            ))