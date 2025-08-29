# PY-Framework

A secure, robust FastHTML + DuckDB web framework featuring strong authentication, minimal JavaScript, comprehensive audit logging, OAuth, and two‑factor authentication. Built with an emphasis on security, observability, and developer experience.

## Features

### Implemented & Tested
- FastHTML: fast server‑rendered UI with minimal JS
- DuckDB: embedded database with optimized schema
- Authentication: BCrypt hashing (12 rounds), rate limiting, lockout
- RBAC: Admin and user roles with management tooling
- Admin: Role assignment, account management, session monitoring, deletion
- OAuth: Google and GitHub integrations
- Two‑Factor Auth: TOTP with QR codes and backup codes
- Email Verification: Registration with confirmation links
- Sessions: Secure handling, expiry, cleanup, and monitoring
- Password Security: Strength validation and reset flow
- CSRF Protection: HMAC‑signed tokens
- Security Middleware: Headers, rate limiting, IP tracking

### Recently Completed
- Enhanced Monitoring: Prometheus metrics, health checks, alerting
- Database Reliability: Constraint fixes and improved integrity
- Audit Logging: Extensive security event tracking with dashboard
- Performance: Caching, connection instrumentation, query optimization

### Production Ready
- Docker: Production and development images
- Docker Compose: Multi‑env orchestration and volumes
- Container Security: Non‑root user, health checks, hardening

### Documentation Features
- Built‑in `/docs` endpoint for markdown docs
- Quick access menu link for docs
- Syntax highlighting and responsive layout

### Testing Status
- 150+ tests passing across core features
- Coverage on auth, CSRF, sessions, OAuth, 2FA, audit, monitoring, DB

## Requirements
- Python 3.13+
- uv for fast dependency management

## Installation
1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd PY-framework
   ```
2. Install dependencies with uv:
   ```bash
   uv sync
   ```
3. Configure environment:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

## Quick Start

### Development (hot reload)
```bash
uv run dev.py
```

### Development (no reload)
```bash
uv run dev_no_reload.py
```

### Production (optimized)
```bash
uv run app.py
```

### Docker Development
```bash
# Build and run with Docker Compose
docker-compose up --build

# Dev container with hot reload
docker-compose -f docker-compose.yml up dev
```

### Docker Production
```bash
# Build production image
docker build -f Dockerfile -t py-framework:latest .

# Run production container
docker run -p 8000:8000 py-framework:latest
```

## Project Structure
```
PY-framework/
  src/framework/            # Core framework code
    auth/                   # Authentication modules
    database/               # Database operations
    email/                  # Email services
    oauth/                  # OAuth integrations
    routes/                 # Route handlers (modular)
      auth.py               # Authentication & OAuth routes
      main.py               # Main application routes
      dev.py                # Development routes
      two_factor.py         # 2FA management routes
      audit_routes.py       # Audit logging dashboard
      performance_routes.py # Performance monitoring
      monitoring_routes.py  # Enhanced monitoring system
    layout.py               # Layout components
    config.py               # Configuration management
    csrf.py                 # CSRF protection
    security.py             # Security middleware
    session.py              # Session management
  templates/                # HTML templates
  static/                   # Static assets
    css/                    # Stylesheets
    js/                     # JavaScript files
    images/                 # Images
    favicon.ico             # Website favicon
  tests/                    # Test files
  docs/                     # Documentation
  dev.py                    # Development server (lightweight)
  dev_no_reload.py          # Development server (no reload)
  app.py                    # Production server (lightweight)
  Dockerfile                # Production Docker image
  Dockerfile.dev            # Development Docker image
  docker-compose.yml        # Docker Compose configuration
  .dockerignore             # Docker ignore rules
  CLAUDE.md                 # Development specifications
```

## Configuration
Use environment variables (.env) to configure the app.

### Required
- `SECRET_KEY`: Strong secret key (32+ chars)
- `DATABASE_URL`: Database file path

### Run Commands
- Development: `uv run dev.py`
- Production: `uv run app.py`

### OAuth (Optional)
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
- `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`

### Email (Optional)
- `SMTP_SERVER`, `SMTP_USERNAME`, `SMTP_PASSWORD`
- For Gmail app passwords: Google Account > Security > 2-Step Verification > App passwords

### Security
- `MAX_FAILED_LOGIN_ATTEMPTS` (default: 5)
- `ACCOUNT_LOCKOUT_DURATION_MINUTES` (default: 30)
- `SESSION_EXPIRE_HOURS` (default: 24)

## Security Features

### Password Security
- Minimum length + complexity
- BCrypt hashing
- Strength validation and secure reset

### Account Protection
- Rate limiting and lockout
- Session cleanup
- CSRF protection on forms
- Security headers (HSTS, CSP, etc.)
- IP‑based tracking

### OAuth Security
- State validation
- Token expiry handling

## Testing
```bash
# Install dev dependencies
uv sync --dev

# Run tests
uv run pytest

# With coverage (if pytest-cov installed)
uv run pytest --maxfail=1 --disable-warnings -q --cov=src/framework
```

> Last updated: 2025-08-29
> Recent internal changes: DB connections (thread-local + auto-reconnect), audit logging stability, OAuth async mocking compatibility, session rotation/cleanup, simple test RateLimiter, and pytest asyncio config.

