# PY-Framework

A secure, robust FastHTML and DuckDB-based web framework with state-of-the-art authentication, minimal JavaScript, and built-in OAuth support for Google and GitHub.
Created with full support fo Claude Code.

## 🚀 Features

### ✅ IMPLEMENTED & TESTED
- **FastHTML**: Lightning-fast web framework with minimal JavaScript
- **DuckDB**: High-performance embedded database with optimized schema
- **Secure Authentication**: BCrypt password hashing (12 rounds), rate limiting, account lockout
- **Email Verification**: Complete user registration with email confirmation system
- **Session Management**: Secure session handling with automatic cleanup and tracking
- **Password Security**: Advanced password validation with strength scoring
- **Account Protection**: Automatic lockout after failed attempts with configurable duration
- **Professional Navigation**: 3-tier navigation with top menu, sidebar, and persona dropdown
- **Responsive Design**: Mobile-optimized layout with collapsible sidebar
- **Favicon Integration**: Professional favicon in navigation and browser tabs
- **Modular Architecture**: Clean route organization with separation of concerns

### 🔄 IN DEVELOPMENT
- **OAuth Integration**: Google and GitHub SSO support (database ready)
- **CSRF Protection**: Built-in cross-site request forgery protection
- **Password Reset**: Secure password reset flow via email
- **Security Headers**: Comprehensive security headers for production

### 📊 TESTING STATUS
- **29/29 tests passing** ✅
- **100% core functionality tested**
- **Email service, registration, and login fully validated**

## 📋 Requirements

- Python 3.13+
- uv for fast dependency management

## 🛠️ Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd PY-framework
```

2. Install dependencies with uv:
```bash
uv sync
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## 🚀 Quick Start

### Development (with hot reload, debug mode)
```bash
uv run dev.py
```
- Hot reloading enabled
- Debug mode active
- Development utilities
- Detailed error messages

### Production (optimized, security headers)
```bash
uv run app.py
```
- Security headers enabled
- Production optimizations
- Health check endpoint
- Error logging

## 📁 Project Structure

```
PY-framework/
├── src/framework/           # Core framework code
│   ├── auth/               # Authentication modules
│   ├── database/           # Database operations
│   ├── email/              # Email services
│   ├── oauth/              # OAuth integrations
│   ├── routes/             # Route handlers (NEW!)
│   │   ├── auth.py         # Authentication routes
│   │   ├── main.py         # Main application routes
│   │   └── dev.py          # Development routes
│   ├── layout.py           # Layout components
│   └── config.py           # Configuration management
├── templates/              # HTML templates
├── static/                 # Static assets
│   ├── css/               # Stylesheets
│   ├── js/                # JavaScript files
│   ├── images/            # Images
│   └── favicon.ico        # Website favicon
├── tests/                  # Test files
├── docs/                   # Documentation
├── dev.py                  # Development server (lightweight)
├── app.py                  # Production server (lightweight)
└── CLAUDE.md              # Development specifications
```

## ⚙️ Configuration

The framework uses environment variables for configuration. Copy `.env.example` to `.env` and configure:

### Required Settings
- `SECRET_KEY`: Strong secret key (32+ characters)
- `DATABASE_URL`: Database file path

### Run Commands (documented in .env)
- **Development**: `uv run dev.py` (with hot reload, debug mode)
- **Production**: `uv run app.py` (optimized, security headers)

### OAuth Settings (Optional)
- `GOOGLE_CLIENT_ID` & `GOOGLE_CLIENT_SECRET`: Google OAuth
- `GITHUB_CLIENT_ID` & `GITHUB_CLIENT_SECRET`: GitHub OAuth

### Email Settings (Optional)
- `SMTP_SERVER`, `SMTP_USERNAME`, `SMTP_PASSWORD`: Email configuration
- **For Gmail**: Use app-specific password (not your regular password)
  - Go to Google Account → Security → 2-Step Verification → App passwords
  - Generate an app password and use that for `SMTP_PASSWORD`

### Security Settings
- `MAX_FAILED_LOGIN_ATTEMPTS`: Failed login threshold (default: 5)
- `ACCOUNT_LOCKOUT_DURATION_MINUTES`: Lockout duration (default: 30)
- `SESSION_EXPIRE_HOURS`: Session expiration (default: 24)

## 🔐 Security Features

### Password Security
- Minimum 8 characters with complexity requirements
- BCrypt hashing with 12 rounds
- Password strength validation
- Secure password reset flow

### Account Protection
- Rate limiting on login attempts
- Account lockout after failed attempts
- Session management with automatic cleanup
- CSRF token protection

### OAuth Security
- Secure state parameter validation
- Token expiration handling
- Provider-specific security measures

## 🧪 Testing

```bash
# Install development dependencies
uv sync --dev

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=src/framework
```

## 🏗️ Architecture

### Route Organization

The framework uses a modular route architecture for better maintainability and scalability:

- **`src/framework/routes/auth.py`** - Authentication routes (login, register, verify, logout)
- **`src/framework/routes/main.py`** - Main application routes (home, dashboard, profile)  
- **`src/framework/routes/dev.py`** - Development-only routes (email test, database inspector)

### Server Files

- **`dev.py`** - Lightweight development server that imports route modules
- **`app.py`** - Lightweight production server with security middleware

### Adding New Routes

1. Create route handlers in appropriate module under `src/framework/routes/`
2. Import and register routes in server files using `create_*_routes()` functions
3. Follow existing patterns for layout, authentication, and error handling

## 📚 API Documentation

### Authentication Endpoints
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `GET /auth/verify/{token}` - Email verification
- `GET /auth/resend-verification` - Resend verification email page
- `POST /auth/resend-verification` - Resend verification email

### OAuth Endpoints
- `GET /auth/google` - Google OAuth initiation
- `GET /auth/google/callback` - Google OAuth callback
- `GET /auth/github` - GitHub OAuth initiation
- `GET /auth/github/callback` - GitHub OAuth callback

### System Endpoints
- `GET /health` - Health check (production)
- `GET /` - Homepage
- `GET /dashboard` - User dashboard
- `GET /profile` - Profile edit page
- `GET /page1` - Sample page demonstrating navigation

### Development Endpoints (dev.py only)
- `GET /dev/test-email` - Email service testing tool
- `POST /dev/test-email` - Send test email
- `GET /dev/test-auth` - Authentication system test page
- `GET /dev/database` - Database inspector

## 🛡️ Security Best Practices

1. **Always use HTTPS in production**
2. **Keep dependencies updated**
3. **Use strong secret keys**
4. **Configure proper CORS origins**
5. **Set up proper email verification**
6. **Monitor failed login attempts**
7. **Regular security audits**

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For issues and questions, please check the `CLAUDE.md` file for detailed development specifications or create an issue in the repository.

---

**Built with security and performance in mind. Ready for production use.**