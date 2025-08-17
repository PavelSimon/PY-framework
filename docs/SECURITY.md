# Security Documentation

## 🔐 Security Features Overview

PY-Framework implements comprehensive security measures to protect against common web vulnerabilities and attacks.

## Authentication Security

### Password Security
- **BCrypt Hashing**: 12 rounds for strong password protection
- **Password Requirements**: Minimum 8 characters with complexity requirements
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one number
  - At least one special character
- **Password History**: Prevents reuse of current password during changes
- **Secure Password Reset**: Time-limited tokens (1 hour expiry) via email

### Account Protection
- **Rate Limiting**: Configurable failed login attempt limits (default: 5)
- **Account Lockout**: Automatic lockout after failed attempts (default: 30 minutes)
- **Session Management**: 
  - Secure session tokens (32-byte random)
  - Session expiration (default: 24 hours)
  - IP address and user agent tracking
  - Automatic cleanup of expired sessions
  - Session-aware routing (automatic redirects based on authentication state)
  - Proper session invalidation on logout

## CSRF Protection

### Implementation
- **HMAC-Signed Tokens**: Cryptographically secure token generation
- **Session Binding**: Tokens are bound to user sessions
- **Automatic Integration**: All forms include CSRF tokens
- **Token Validation**: Server-side validation on all state-changing operations

### Usage
- Tokens are automatically added to forms when CSRF protection is enabled
- Supports both form-based and AJAX requests
- Configurable token lifetime (default: 60 minutes)

## Security Middleware

### Rate Limiting
- **IP-Based Limiting**: Configurable requests per time window
- **Production Settings**: 100 requests per hour by default
- **Development Settings**: Rate limiting disabled for development
- **Response Headers**: Includes rate limit information in responses

### Security Headers

#### Production Headers
- **HSTS**: HTTP Strict Transport Security with 1-year max-age
- **CSP**: Content Security Policy with strict directives
- **X-Content-Type-Options**: nosniff
- **X-Frame-Options**: DENY
- **X-XSS-Protection**: 1; mode=block
- **Referrer-Policy**: strict-origin-when-cross-origin
- **Permissions-Policy**: Restricts browser features

#### Development Headers
- Relaxed CSP for development convenience
- No HSTS to avoid browser caching issues
- Basic security headers maintained

### IP Protection
- **Client IP Detection**: Handles X-Forwarded-For and X-Real-IP headers
- **Request Tracking**: Monitors request patterns per IP
- **Security Event Logging**: Logs suspicious activities

## Email Security

### Verification Tokens
- **Secure Token Generation**: 32-byte URL-safe tokens
- **Time-Limited**: Configurable expiration (default: 24 hours)
- **Single Use**: Tokens are invalidated after use
- **Database Storage**: Secure token storage with expiration tracking

### Email Configuration
- **App-Specific Passwords**: Supports Gmail app passwords
- **TLS Encryption**: Secure SMTP connections
- **Error Handling**: Graceful handling of email service failures

## Database Security

### Connection Security
- **Local Database**: DuckDB embedded database for reduced attack surface
- **SQL Injection Protection**: Parameterized queries throughout
- **Schema Validation**: Proper foreign key constraints
- **Index Optimization**: Performance without security compromise

### Data Protection
- **Password Hashing**: Never store plain text passwords
- **Session Isolation**: Users can only access their own data
- **Token Cleanup**: Automatic cleanup of expired tokens

## Security Configuration

### Environment Variables
```bash
# Security settings
SECRET_KEY=your-secret-key-32-chars-minimum
MAX_FAILED_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION_MINUTES=30
SESSION_EXPIRE_HOURS=24
```

### Production vs Development
- **Production**: All security features enabled, strict policies
- **Development**: Relaxed policies for development convenience
- **Automatic Detection**: Framework automatically configures based on environment

## Security Best Practices

### Deployment
1. **Use HTTPS**: Always deploy with SSL/TLS certificates
2. **Strong Secret Keys**: Generate cryptographically secure secret keys
3. **Environment Variables**: Never commit secrets to version control
4. **Regular Updates**: Keep dependencies updated
5. **Monitoring**: Monitor security events and failed login attempts

### Code Security
1. **Input Validation**: Validate all user inputs
2. **Output Encoding**: Properly encode output to prevent XSS
3. **Access Controls**: Verify user permissions for all operations
4. **Error Handling**: Don't leak sensitive information in error messages

## Security Monitoring

### Event Logging
- Failed login attempts
- Account lockouts
- Rate limit violations
- CSRF token failures
- Password reset requests

### Security Reporter
- **Event Storage**: Last 1000 security events
- **Structured Logging**: JSON-formatted security events
- **Production Integration**: Ready for external logging services

## Vulnerability Response

### Reporting
- Security issues should be reported via the repository's issue tracker
- Include detailed reproduction steps
- Allow time for patch development before public disclosure

### Patching
- Security patches will be prioritized
- Breaking changes will be documented
- Migration guides provided for major security updates

---

**This security documentation reflects the current implementation. Review regularly and update as the framework evolves.**