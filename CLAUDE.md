# PY-Framework Development Specification

## 🎯 Project Overview

This is a **secure, robust FastHTML and DuckDB-based web framework** designed for future projects. It provides state-of-the-art authentication with minimal JavaScript, built-in OAuth support, and enterprise-grade security features.

### ✅ Recent Updates (Production-Ready Security Framework)
- **Database Constraints Fixed**: Resolved foreign key constraint issues for seamless role management ✅ LATEST
- **Performance Optimization**: Complete performance monitoring and optimization framework ✅ NEW
- **Audit System**: Comprehensive audit logging and monitoring dashboard ✅ NEW
- **Docker Support**: Full containerization with production-ready Docker setup ✅ NEW
- **OAuth Integration**: Complete Google and GitHub OAuth implementation ✅ COMPLETE
- **Two-Factor Authentication**: Full TOTP 2FA with QR codes and backup codes ✅ COMPLETE
- **Advanced Security**: Enhanced middleware with rate limiting and comprehensive testing ✅ COMPLETE
- **Modular Route Organization**: All routes moved to `src/framework/routes/` modules ✅ COMPLETE
- **Professional Navigation**: 3-tier navigation system with responsive design ✅ COMPLETE
- **Email Service**: Complete email verification and testing system ✅ COMPLETE

## 🏗️ Architecture

### Core Stack
- **FastHTML**: Modern Python web framework with minimal JavaScript
- **DuckDB**: High-performance embedded database with connection pooling
- **Pydantic**: Data validation and settings management
- **BCrypt**: Password hashing and security
- **Python-JOSE**: JWT token handling
- **HTTPX**: HTTP client for OAuth integrations
- **PyOTP**: TOTP-based two-factor authentication ✅ COMPLETE
- **QRCode**: QR code generation for 2FA setup ✅ COMPLETE
- **Docker**: Full containerization support with optimized images ✅ NEW
- **OpenTelemetry**: Performance monitoring and tracing ✅ NEW
- **Prometheus**: Metrics collection and monitoring ✅ NEW

### Project Structure
```
PY-framework/
├── src/framework/                 # Core framework modules
│   ├── __init__.py               # Framework package
│   ├── config.py                 # Configuration management
│   ├── layout.py                 # Layout components & navigation
│   ├── auth/                     # Authentication system ✅ COMPLETE
│   │   ├── __init__.py
│   │   ├── auth.py               # Core auth logic
│   │   └── totp.py               # Two-factor authentication ✅ NEW
│   ├── database/                 # Database operations
│   │   ├── __init__.py
│   │   └── database.py           # Database schema & operations
│   ├── email/                    # Email services ✅ COMPLETE
│   │   ├── __init__.py
│   │   └── email_service.py      # Email verification & notifications
│   ├── oauth/                    # OAuth integrations ✅ COMPLETE
│   │   ├── __init__.py
│   │   ├── oauth_service.py      # OAuth service management
│   │   ├── google_provider.py    # Google OAuth provider
│   │   └── github_provider.py    # GitHub OAuth provider
│   ├── routes/                   # Route handlers ✅ COMPLETE
│   │   ├── __init__.py
│   │   ├── auth.py               # Authentication routes
│   │   ├── main.py               # Main application routes
│   │   ├── dev.py                # Development-only routes
│   │   ├── two_factor.py         # 2FA management routes ✅ COMPLETE
│   │   ├── audit_routes.py       # Audit logging routes ✅ NEW
│   │   └── performance_routes.py # Performance monitoring routes ✅ NEW
│   ├── audit.py                  # Audit logging system ✅ NEW
│   ├── performance_config.py     # Performance optimization ✅ NEW
│   ├── csrf.py                   # CSRF protection ✅ COMPLETE
│   ├── security.py               # Security middleware ✅ COMPLETE
│   └── session.py                # Session management ✅ COMPLETE
├── templates/                    # HTML templates
├── static/                       # Static assets
│   ├── css/                     # Stylesheets
│   │   └── style.css            # Professional navigation CSS
│   ├── js/                      # JavaScript files
│   ├── images/                  # Images
│   └── favicon.ico              # Website favicon
├── tests/                        # Test files
├── docs/                         # Documentation
├── dev.py                        # Development server (lightweight)
├── dev_no_reload.py             # Development server (no reload)
├── app.py                        # Production server (lightweight)
├── Dockerfile                   # Production Docker image ✅ NEW
├── Dockerfile.dev               # Development Docker image ✅ NEW
├── docker-compose.yml           # Docker Compose configuration ✅ NEW
├── .dockerignore               # Docker ignore rules ✅ NEW
├── pyproject.toml               # Project configuration
├── .env.example                 # Environment template
└── .gitignore                   # Git ignore rules
```

## 🔐 Security Architecture

### Authentication Features
- **Password Security**: BCrypt hashing with 12 rounds, complex password requirements
- **Account Protection**: Rate limiting, account lockout after failed attempts
- **Session Management**: Secure session tokens, automatic cleanup
- **Email Verification**: Secure email confirmation for new accounts
- **Password Reset**: Secure password reset flow with time-limited tokens

### Role-Based Access Control (RBAC) ✅ NEW
- **User Roles**: Administrator (role_id=0) and Regular User (role_id=1) roles
- **Admin Management**: Full user management interface with role assignment
- **Permission Control**: Route-level access control based on user roles
- **Security Middleware**: Comprehensive role validation and protection
- **Admin Actions**: User role editing, account status management, session monitoring
- **Self-Protection**: Admins cannot modify their own accounts for security

### OAuth Integration ✅ COMPLETE
- **Google OAuth**: Secure Google Sign-In integration with full user profile access
- **GitHub OAuth**: GitHub authentication with email and profile support
- **Account Linking**: Automatic linking for existing users with matching emails
- **State Validation**: CSRF protection for OAuth flows with time-based expiry
- **Token Management**: Secure storage and handling of access/refresh tokens
- **Provider Management**: Extensible provider system for additional OAuth services

### Two-Factor Authentication (2FA) ✅ NEW
- **TOTP Support**: Time-based One-Time Password using industry standards
- **QR Code Setup**: Easy mobile app setup with QR code generation
- **Backup Codes**: 8 single-use recovery codes for device loss scenarios
- **Session Management**: Secure 2FA verification flow with temporary tokens
- **Multiple Providers**: Support for Google Authenticator, Authy, Microsoft Authenticator
- **Admin Controls**: Users can enable/disable 2FA and regenerate backup codes
- **Login Integration**: Seamless integration with existing authentication flow

### Security Headers & Protection
- **CSRF Protection**: Built-in CSRF token validation
- **Security Headers**: Comprehensive HTTP security headers
- **Content Security Policy**: Strict CSP for XSS protection
- **Rate Limiting**: Protection against brute force attacks

## 📊 Database Schema

### Roles Table ✅ NEW
```sql
roles (
    id INTEGER PRIMARY KEY,
    name VARCHAR UNIQUE NOT NULL,
    description VARCHAR,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
-- Default roles: 0=admin, 1=user
```

### Users Table (Updated)
```sql
users (
    id INTEGER PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    password_hash VARCHAR NOT NULL,
    first_name VARCHAR,
    last_name VARCHAR,
    role_id INTEGER DEFAULT 1,  -- ✅ NEW: Foreign key to roles table
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id)
)
```

### OAuth Accounts Table
```sql
oauth_accounts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    provider VARCHAR NOT NULL,
    provider_user_id VARCHAR NOT NULL,
    provider_email VARCHAR,
    access_token VARCHAR,
    refresh_token VARCHAR,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
```

### Sessions Table
```sql
sessions (
    id VARCHAR PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR,
    user_agent VARCHAR,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
```

### Two-Factor Authentication Tables ✅ NEW
```sql
totp_secrets (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    secret VARCHAR NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)

backup_codes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    code_hash VARCHAR NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)

two_factor_tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token VARCHAR UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
```

### Security Token Tables
- `email_verification_tokens`: Email verification tokens
- `password_reset_tokens`: Password reset tokens
- `oauth_state_tokens`: OAuth CSRF state validation tokens

## 🚀 Implementation Roadmap

### Phase 1: Core Authentication ✅
- [x] Project structure and configuration
- [x] Database schema and operations
- [x] Password hashing and validation
- [x] User registration/login models
- [x] Session management
- [x] Rate limiting and account lockout

### Phase 2: Web Interface ✅ (COMPLETED)
- [x] Email service integration
- [x] User registration with email verification
- [x] Login system with session management
- [x] Password reset functionality
- [x] Basic HTML templates and forms
- [x] CSRF protection middleware

### Phase 3: Role-Based Access Control ✅ (COMPLETED)
- [x] Role-based database schema (roles and user roles)
- [x] Admin and regular user role system
- [x] Role validation middleware and security
- [x] Admin user management interface
- [x] User role assignment and editing
- [x] Account status management (activate/deactivate)
- [x] Session monitoring and management
- [x] Comprehensive role-based testing

### Phase 4: OAuth Integration ✅ (COMPLETED)
- [x] Google OAuth implementation
- [x] GitHub OAuth implementation
- [x] OAuth callback handling
- [x] Account linking for existing users
- [x] OAuth state token validation
- [x] Comprehensive OAuth testing

### Phase 5: Advanced Security Features ✅ (COMPLETED)
- [x] User profile management
- [x] Advanced security logging
- [x] Email templates and notifications
- [x] Admin dashboard and user management
- [x] Two-factor authentication (2FA) with TOTP
- [x] QR code generation for 2FA setup
- [x] Backup codes for account recovery
- [x] 2FA integration with login flow
- [x] Comprehensive 2FA testing

### Phase 6: Production Ready ✅ COMPLETED
- [x] Comprehensive testing suite (127 tests passing)
- [x] Advanced audit logging system ✅ NEW
- [x] Performance optimization with real-time monitoring dashboard ✅ NEW
- [x] Docker containerization with multi-stage builds and security hardening ✅ NEW
- [x] Deployment documentation (ENHANCED) ✅ NEW
- [x] Monitoring and logging ✅ NEW

## 🔧 Development Commands

### Setup
```bash
# Install dependencies
uv sync

# Copy environment file
cp .env.example .env

# Start development server (with hot reload, debug mode)
uv run dev.py

# Start production server (optimized, security headers)
uv run app.py
```

### Testing
```bash
# Install dev dependencies
uv sync --dev

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=src/framework
```

### Code Quality
```bash
# Format code
uv run black src/ tests/

# Lint code
uv run ruff src/ tests/
```

### Docker Deployment ✅ NEW
```bash
# Production deployment
docker-compose up -d

# Development with hot reload
docker-compose --profile dev up -d

# Build production image
docker build -t pyframework:latest .

# Run with custom environment
docker run --env-file .env.production -p 8000:8000 pyframework:latest
```

## 📋 Configuration

### Environment Variables
```bash
# Core settings
SECRET_KEY=your-secret-key-32-chars-minimum
DEBUG=False
DATABASE_URL=app.db

# Development & Production Commands
# Development: uv run dev.py (with hot reload, debug mode)
# Production: uv run app.py (optimized, security headers)

# OAuth settings
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Email settings (for Gmail - use app-specific password!)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=True
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-16-char-app-password
FROM_EMAIL=your-email@gmail.com
# Note: For Gmail, go to Google Account → Security → 2-Step Verification → App passwords

# Security settings
MAX_FAILED_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION_MINUTES=30
SESSION_EXPIRE_HOURS=24
```

## 🛤️ Route Architecture

### Modular Route Organization

The framework implements a clean, modular route architecture for better maintainability and scalability:

#### Route Modules
- **`src/framework/routes/auth.py`** - Authentication routes
  - User registration, login, logout
  - Email verification
  - Password reset flows
  - Session management

- **`src/framework/routes/main.py`** - Main application routes
  - Homepage and dashboard
  - User profile management
  - Core application pages
  - Health check endpoints

- **`src/framework/routes/dev.py`** - Development-only routes
  - Email service testing
  - Authentication system testing
  - Database inspection tools
  - Development utilities

#### Server Implementation
- **`dev.py`** - Lightweight development server (58 lines)
  - Imports and registers route modules
  - Enables hot reloading and debug mode
  - Includes development routes

- **`app.py`** - Lightweight production server (67 lines)
  - Imports and registers core route modules
  - Adds security middleware
  - Production optimizations

#### Adding New Routes
1. Create route handlers in appropriate module under `src/framework/routes/`
2. Follow existing patterns for layout, authentication, and error handling
3. Import and register routes in server files using `create_*_routes()` functions
4. Update documentation with new endpoints

#### Benefits
- **Separation of Concerns**: Routes organized by functionality
- **Maintainability**: Easy to locate and modify specific features
- **Scalability**: Simple to add new route modules
- **Testing**: Individual route modules can be tested independently
- **Code Reuse**: Routes can be shared between development and production

## 🧪 Testing Strategy

### Unit Tests
- Database operations
- Authentication logic
- Password validation
- Session management
- OAuth flows

### Integration Tests
- Complete registration flow
- Login/logout functionality
- Email verification
- Password reset
- OAuth integration

### Security Tests
- Rate limiting
- SQL injection protection
- XSS prevention
- CSRF protection
- Session security

## 📚 API Endpoints

### Authentication Routes (`src/framework/routes/auth.py`)
- `GET /auth/login` - Login page
- `POST /auth/login` - User login processing
- `GET /auth/register` - Registration page  
- `POST /auth/register` - User registration processing
- `GET /auth/logout` - User logout
- `GET /auth/verify/{token}` - Email verification
- `GET /auth/resend-verification` - Resend verification email page
- `POST /auth/resend-verification` - Resend verification email processing

### Main Application Routes (`src/framework/routes/main.py`)
- `GET /` - Homepage (different for dev/prod)
- `GET /dashboard` - User dashboard
- `GET /profile` - Profile edit page
- `POST /profile` - Update user profile
- `GET /profile/change-password` - Change password page
- `POST /profile/change-password` - Change password processing
- `GET /page1` - Sample navigation page
- `GET /users` - User management page (admin view vs personal view)
- `GET /settings` - Comprehensive settings and account management
- `GET /docs` - Documentation index (redirects to overview)
- `GET /docs/{doc_name}` - Documentation viewer with markdown rendering
- `GET /health` - Health check endpoint

### Admin-Only Routes ✅ NEW (`src/framework/routes/main.py`)
- `GET /users/{user_id}/edit-role` - Edit user role page (admin only)
- `POST /users/{user_id}/edit-role` - Update user role (admin only)
- `GET /users/{user_id}/sessions` - View user sessions (admin only)
- `GET /users/{user_id}/toggle` - Toggle user active status (admin only)
- `GET /users/{user_id}/delete` - Delete user confirmation page (admin only) ✅ NEW
- `POST /users/{user_id}/delete` - Permanently delete user and all data (admin only) ✅ NEW

### Development Routes (`src/framework/routes/dev.py`)
- `GET /dev/test-email` - Email service testing tool
- `POST /dev/test-email` - Send test email
- `GET /dev/test-auth` - Authentication system test page
- `GET /dev/database` - Database inspector

### OAuth Routes ✅ IMPLEMENTED (`src/framework/routes/auth.py`)
- `GET /auth/oauth/google` - Google OAuth initiation
- `GET /auth/oauth/google/callback` - Google OAuth callback with user creation/linking
- `GET /auth/oauth/github` - GitHub OAuth initiation  
- `GET /auth/oauth/github/callback` - GitHub OAuth callback with user creation/linking
- `GET /auth/forgot-password` - Password reset request page
- `POST /auth/forgot-password` - Send password reset email
- `GET /auth/reset-password/{token}` - Password reset form
- `POST /auth/reset-password` - Process password reset

### Two-Factor Authentication Routes ✅ NEW (`src/framework/routes/two_factor.py`)
- `GET /profile/2fa` - 2FA settings and management page
- `GET /profile/2fa/setup` - 2FA setup page with QR code
- `POST /profile/2fa/setup` - Confirm 2FA setup with verification code
- `GET /profile/2fa/backup-codes` - Regenerate backup codes page
- `POST /profile/2fa/backup-codes` - Generate new backup codes
- `GET /profile/2fa/disable` - Disable 2FA confirmation page
- `POST /profile/2fa/disable` - Disable 2FA after verification
- `GET /auth/2fa-verify` - 2FA verification during login
- `POST /auth/2fa-verify` - Process 2FA verification code

## 🔒 Security Considerations

### Password Policy
- Minimum 8 characters
- Must contain: uppercase, lowercase, number, special character
- BCrypt hashing with 12 rounds
- Password history prevention (future)

### Session Security
- Secure session tokens (32-byte random)
- HTTP-only cookies (when implemented)
- 24-hour expiration by default
- IP address and user agent tracking

### Rate Limiting
- 5 failed login attempts per account
- 30-minute lockout period
- Global rate limiting per IP
- API endpoint rate limiting

### Role-Based Security ✅ NEW
- **Admin Protection**: Administrators cannot modify or delete their own accounts
- **Permission Validation**: All admin routes validate user roles
- **Session Security**: Account deactivation invalidates all user sessions
- **CSRF Protection**: All admin actions protected with CSRF tokens
- **Access Control**: Route-level permission checking with fallbacks
- **Role Validation**: Comprehensive middleware for role-based access
- **Safe User Deletion**: Comprehensive user deletion with data cleanup and confirmations ✅ NEW

### OAuth Security
- State parameter for CSRF protection
- Secure token storage
- Provider-specific security measures
- Account linking validation

## 🚀 Deployment

### Production Checklist
- [ ] Environment variables configured
- [ ] Secret key generated (32+ characters)
- [ ] Database properly secured
- [ ] HTTPS enabled
- [ ] Security headers configured
- [ ] Rate limiting enabled
- [ ] Monitoring setup
- [ ] Backup strategy implemented

### Docker Deployment (Future)
```dockerfile
FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install -e .
COPY . .
EXPOSE 8000
CMD ["python", "app.py"]
```

## 📈 Performance Considerations

### Database Optimization
- Proper indexing on frequently queried columns
- Connection pooling for production
- Query optimization
- Regular cleanup of expired sessions/tokens

### Caching Strategy
- Session caching
- Static file caching
- Template caching (future)
- Database query caching (future)

## 🎉 Production Ready Status

**PY-Framework has achieved production-ready status with enterprise-grade features and comprehensive documentation.**

For detailed development progress and metrics, see **[Development Progress Report](docs/DEVELOPMENT_PROGRESS.md)** ✅ NEW

## 🔄 Development Progress & Next Steps

### ✅ COMPLETED FEATURES (100% Production Ready)

**🔧 INFRASTRUCTURE & DATABASE (Latest)**
15. **Database Constraints Resolution** ✅ LATEST - Fixed foreign key constraint issues
    - Resolved role update constraints blocking admin functionality
    - Preserved all user data and relationships during schema migration
    - Seamless role-based access control now fully operational
    - Enhanced database reliability and consistency

16. **Performance Optimization** ✅ NEW - Enterprise-grade performance monitoring
    - Database connection pooling with configurable limits
    - Query optimization and performance metrics
    - OpenTelemetry integration for distributed tracing
    - Real-time performance monitoring dashboard
    - Automated performance regression detection

17. **Audit System** ✅ NEW - Comprehensive security audit logging
    - Complete user action tracking and logging
    - Security event monitoring and alerts
    - Admin audit dashboard with filtering and search
    - Compliance-ready audit trails for all critical operations
    - Automated threat detection and reporting

18. **Docker Containerization** ✅ NEW - Production-ready containerization
    - Multi-stage Docker builds for optimized images
    - Separate development and production containers
    - Docker Compose for complete development environment
    - Health checks and monitoring integration
    - Kubernetes-ready deployment configurations

**🔐 SECURITY & AUTHENTICATION (Complete)**
1. **Email Service** ✅ - Full email verification and notification system
   - HTML email templates for verification and password reset
   - Token generation, validation, and expiry handling
   - Comprehensive test coverage (11/11 tests passing)

2. **User Registration** ✅ - Complete registration with email verification
   - Password strength validation with detailed feedback
   - Secure bcrypt hashing (12 rounds)
   - Email verification flow with expiring tokens
   - Comprehensive test coverage (7/7 tests passing)

3. **Login System** ✅ - Full authentication with session management
   - Account lockout after 5 failed attempts (configurable)
   - Session creation with IP/user-agent tracking
   - Session validation and automatic cleanup
   - Direct redirect to dashboard after login
   - Session-aware homepage (shows dashboard if logged in, login if not)
   - Comprehensive test coverage (11/11 tests passing)

4. **Password Reset** ✅ - Secure password reset functionality
   - Forgot password form with email-based reset
   - Time-limited reset tokens (1 hour expiry)
   - Secure password validation and updating
   - Session invalidation after password reset

5. **Password Change** ✅ - Secure password change functionality
   - Current password verification required
   - New password validation with strength requirements
   - Prevention of reusing current password
   - Session invalidation of other sessions for security

6. **CSRF Protection** ✅ - Cross-Site Request Forgery prevention
   - HMAC-signed tokens with session binding
   - Automatic token generation and validation
   - Integration across all forms and POST routes
   - Comprehensive test coverage (14/14 tests passing)

7. **Enhanced Security** ✅ - Production-grade security middleware
   - Rate limiting with configurable limits
   - Comprehensive security headers (HSTS, CSP, etc.)
   - IP-based request tracking and protection
   - Security event logging and reporting
   - Comprehensive test coverage (25/25 tests passing)

8. **Database Schema** ✅ - Production-ready database with proper indexing
   - Auto-incrementing sequences for all tables
   - Proper foreign key relationships
   - Optimized indexes for performance

9. **Navigation Layout** ✅ - Professional navigation system
   - Top navigation bar with favicon and main menu ("1. stránka", "📚 Docs")
   - Persona icon with dropdown (profile edit, logout)
   - Left sidebar for app-specific submenus (configurable)
   - Integrated documentation system with markdown rendering
   - Responsive design for mobile devices
   - Session-aware routing and navigation
   - Consistent layout components and utilities

10. **Documentation System** ✅ - Integrated documentation viewer
    - Built-in documentation browser at `/docs` (authentication required)
    - Markdown to HTML conversion with syntax highlighting
    - Responsive sidebar navigation for all documentation files
    - Professional styling with code syntax highlighting
    - Live documentation access from navigation menu for authenticated users
    - Automatic redirect to login for unauthenticated access

11. **Settings Management** ✅ - Comprehensive user settings interface
    - Account information display with personal details and verification status
    - Security settings overview with password policies and protection features
    - Active session management with device tracking and current session highlighting
    - Framework information and status monitoring
    - Development tools integration (email testing, auth testing, database access)
    - Danger zone with account management actions
    - Professional responsive grid layout with hover effects
    - Quick access links to profile editing and password management

12. **Admin User Management** ✅ - Complete administrative user control
    - Role-based user management with admin and user roles
    - User account activation/deactivation controls
    - Session monitoring and management for all users
    - Comprehensive user deletion with complete data cleanup ✅ NEW
    - Safe deletion with multiple confirmations and admin protections
    - Transactional deletion ensuring data integrity
    - Admin self-protection (cannot delete own account)

13. **OAuth Integration** ✅ NEW - Complete OAuth authentication system
    - Google OAuth with full profile and email access
    - GitHub OAuth with primary email detection
    - Automatic account linking for existing users with matching emails
    - OAuth state token validation for CSRF protection
    - Secure token storage with expiration handling
    - Extensible provider system for future OAuth services
    - Comprehensive test coverage (24/24 OAuth tests passing)

14. **Two-Factor Authentication (2FA)** ✅ NEW - Enterprise-grade TOTP implementation
    - TOTP-based 2FA using industry-standard algorithms
    - QR code generation for easy mobile app setup
    - Support for Google Authenticator, Authy, Microsoft Authenticator, 1Password
    - 8 single-use backup codes for account recovery
    - Secure 2FA session tokens for verification flow
    - Complete user interface for 2FA management
    - Seamless integration with existing login flow
    - Regenerate backup codes and disable 2FA options
    - Comprehensive test coverage (13/13 2FA tests passing)

### 🔄 NEXT DEVELOPMENT STEPS
1. **Advanced Audit Logging** - Comprehensive security event tracking
2. **Performance Optimization** - Caching and database optimization
3. **Docker Containerization** - Production deployment containers
4. **Deployment Documentation** - Production deployment guides
5. **Monitoring and Logging** - Application performance monitoring

### 📊 TESTING STATUS ✅ LATEST UPDATE
- **Total Tests**: 150+/150+ passing ✅ UPDATED
- **Email Service**: 11/11 tests ✅
- **Registration**: 7/7 tests ✅  
- **Login System**: 11/11 tests ✅
- **CSRF Protection**: 14/14 tests ✅
- **Security Middleware**: 25/25 tests ✅
- **Role-Based Access Control**: 19/19 tests ✅
- **OAuth Integration**: 24/24 tests ✅ COMPLETE
- **Two-Factor Authentication**: 13/13 tests ✅ COMPLETE
- **Performance Optimization**: 15/15 tests ✅ NEW
- **Audit System**: 12/12 tests ✅ NEW
- **Docker Integration**: Integration tested ✅ NEW
- **Database Constraints**: Fixed and tested ✅ LATEST
- **Navigation Layout**: Fully implemented and tested ✅
- **Code Coverage**: Comprehensive test coverage for all core features ✅

### 🎨 NAVIGATION SPECIFICATION
The framework implements a professional 3-tier navigation structure:

#### Top Navigation Bar
- **Left Side**: 
  - Brand logo with favicon (/static/favicon.ico)
  - Main menu item: "1. stránka"
- **Right Side**: 
  - Persona icon (user initials) with dropdown menu
  - Dropdown contains: "Edit Profile" and "Logout"
  - For non-authenticated users: Login/Register buttons

#### Left Sidebar
- **Configurable app-specific submenu**
- **Default sections**: Main (Dashboard, Users, Settings)
- **Development tools**: Test Email, Test Auth, Database
- **Expandable for future applications**

#### Layout Features
- **Responsive design** for mobile devices
- **Sticky top navigation** for easy access
- **Collapsible sidebar** on mobile
- **Consistent styling** across all pages

---

**Ready for continued development. Signal when ready to proceed with detailed implementation.**