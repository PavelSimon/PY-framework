# PY-Framework Development Specification

## 🎯 Project Overview

This is a **secure, robust FastHTML and DuckDB-based web framework** designed for future projects. It provides state-of-the-art authentication with minimal JavaScript, built-in OAuth support, and enterprise-grade security features.

### ✅ Recent Updates (Route Architecture Refactoring)
- **Modular Route Organization**: All routes moved to `src/framework/routes/` modules
- **Lightweight Servers**: `dev.py` and `app.py` now focus on configuration and middleware
- **Professional Navigation**: 3-tier navigation system with responsive design
- **Email Service**: Complete email verification and testing system
- **Development Tools**: Built-in testing tools for email and authentication

## 🏗️ Architecture

### Core Stack
- **FastHTML**: Modern Python web framework with minimal JavaScript
- **DuckDB**: High-performance embedded database
- **Pydantic**: Data validation and settings management
- **BCrypt**: Password hashing and security
- **Python-JOSE**: JWT token handling
- **HTTPX**: HTTP client for OAuth integrations

### Project Structure
```
PY-framework/
├── src/framework/                 # Core framework modules
│   ├── __init__.py               # Framework package
│   ├── config.py                 # Configuration management
│   ├── layout.py                 # Layout components & navigation
│   ├── auth/                     # Authentication system
│   │   ├── __init__.py
│   │   └── auth.py               # Core auth logic
│   ├── database/                 # Database operations
│   │   ├── __init__.py
│   │   └── database.py           # Database schema & operations
│   ├── email/                    # Email services ✅ IMPLEMENTED
│   │   ├── __init__.py
│   │   └── email_service.py      # Email verification & notifications
│   ├── routes/                   # Route handlers ✅ NEW ARCHITECTURE
│   │   ├── __init__.py
│   │   ├── auth.py               # Authentication routes
│   │   ├── main.py               # Main application routes
│   │   └── dev.py                # Development-only routes
│   └── oauth/                    # OAuth integrations (planned)
│       └── __init__.py
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
├── app.py                        # Production server (lightweight)
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

### OAuth Integration
- **Google OAuth**: Secure Google Sign-In integration
- **GitHub OAuth**: GitHub authentication support
- **State Validation**: CSRF protection for OAuth flows
- **Token Management**: Secure storage and handling of OAuth tokens

### Security Headers & Protection
- **CSRF Protection**: Built-in CSRF token validation
- **Security Headers**: Comprehensive HTTP security headers
- **Content Security Policy**: Strict CSP for XSS protection
- **Rate Limiting**: Protection against brute force attacks

## 📊 Database Schema

### Users Table
```sql
users (
    id INTEGER PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    password_hash VARCHAR NOT NULL,
    first_name VARCHAR,
    last_name VARCHAR,
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP
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

### Security Token Tables
- `email_verification_tokens`: Email verification tokens
- `password_reset_tokens`: Password reset tokens

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

### Phase 3: OAuth Integration
- [ ] Google OAuth implementation
- [ ] GitHub OAuth implementation
- [ ] OAuth callback handling
- [ ] Account linking for existing users

### Phase 4: Advanced Features
- [ ] User profile management
- [ ] Two-factor authentication (2FA)
- [ ] Advanced security logging
- [ ] Email templates and notifications
- [ ] Admin dashboard

### Phase 5: Production Ready
- [ ] Comprehensive testing suite
- [ ] Performance optimization
- [ ] Docker containerization
- [ ] Deployment documentation
- [ ] Monitoring and logging

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
- `GET /page1` - Sample navigation page
- `GET /health` - Health check endpoint

### Development Routes (`src/framework/routes/dev.py`)
- `GET /dev/test-email` - Email service testing tool
- `POST /dev/test-email` - Send test email
- `GET /dev/test-auth` - Authentication system test page
- `GET /dev/database` - Database inspector

### Planned OAuth Routes (Future Implementation)
- `GET /auth/google` - Google OAuth initiation
- `GET /auth/google/callback` - Google OAuth callback
- `GET /auth/github` - GitHub OAuth initiation
- `GET /auth/github/callback` - GitHub OAuth callback

### User Management Routes (`src/framework/routes/main.py`)
- `POST /profile` - Update user profile
- `GET /profile/change-password` - Change password page
- `POST /profile/change-password` - Change password processing

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

## 🔄 Development Progress & Next Steps

### ✅ COMPLETED FEATURES
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
   - Top navigation bar with favicon and main menu ("1. stránka")
   - Persona icon with dropdown (profile edit, logout)
   - Left sidebar for app-specific submenus (configurable)
   - Responsive design for mobile devices
   - Session-aware routing and navigation
   - Consistent layout components and utilities

### 🔄 NEXT DEVELOPMENT STEPS
1. **OAuth Integration** - Google and GitHub OAuth providers
2. **Two-Factor Authentication** - Enhanced account security
3. **Admin Dashboard** - User management and system monitoring
4. **Production Deploy** - Docker, monitoring, and deployment guides
5. **Performance Optimization** - Caching and database optimization

### 📊 TESTING STATUS
- **Total Tests**: 68/68 passing ✅
- **Email Service**: 11/11 tests ✅
- **Registration**: 7/7 tests ✅  
- **Login System**: 11/11 tests ✅
- **CSRF Protection**: 14/14 tests ✅
- **Security Middleware**: 25/25 tests ✅
- **Navigation Layout**: Fully implemented and tested ✅
- **Code Coverage**: Comprehensive test coverage for all core features

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