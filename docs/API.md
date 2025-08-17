# API Documentation

## 🚀 PY-Framework API Reference

This document provides comprehensive documentation for all API endpoints in the PY-Framework.

## Base URL

- **Development**: `http://localhost:8000`
- **Production**: Your deployed domain

## Authentication

Most endpoints require user authentication via session cookies. The framework automatically handles session management.

### Session Management
- Sessions are created upon successful login with automatic redirect to dashboard
- Session state is managed in-memory for development, database for production
- Sessions expire after 24 hours by default
- Sessions are invalidated on logout or password change
- Homepage automatically redirects authenticated users to dashboard

## Response Formats

### Success Responses
- **HTML Pages**: Most endpoints return rendered HTML pages
- **JSON Responses**: Health check and API endpoints return JSON
- **Redirects**: Authentication flows use HTTP redirects

### Error Responses
- **4xx Errors**: Client errors (validation, authentication)
- **5xx Errors**: Server errors (handled gracefully)
- **CSRF Errors**: 403 Forbidden for invalid CSRF tokens
- **Rate Limit Errors**: 429 Too Many Requests

## Authentication Endpoints

### User Registration

#### `GET /auth/register`
**Description**: Display user registration form
**Authentication**: None required
**Response**: HTML registration page with CSRF token

#### `POST /auth/register`
**Description**: Process user registration
**Authentication**: None required

**Request Body** (form data):
```
email: string (required) - Valid email address
password: string (required) - Min 8 chars with complexity requirements
first_name: string (optional) - User's first name
last_name: string (optional) - User's last name
csrf_token: string (required if CSRF enabled) - CSRF protection token
```

**Response**: 
- Success: Registration confirmation page
- Error: Registration form with error messages

**Validation Rules**:
- Email must be valid format and unique
- Password must meet complexity requirements
- CSRF token must be valid

### User Login

#### `GET /auth/login`
**Description**: Display login form
**Authentication**: None required
**Response**: HTML login page with CSRF token

#### `POST /auth/login`
**Description**: Authenticate user and create session
**Authentication**: None required

**Request Body** (form data):
```
email: string (required) - User's email address
password: string (required) - User's password
csrf_token: string (required if CSRF enabled) - CSRF protection token
```

**Response**:
- Success: 302 redirect to `/dashboard` with session created
- Error: Login form with error messages

**Security Features**:
- Rate limiting on failed attempts
- Account lockout after 5 failed attempts
- IP and user agent tracking

### Email Verification

#### `GET /auth/verify/{token}`
**Description**: Verify user email with token
**Authentication**: None required

**Parameters**:
- `token` (path): Email verification token from email

**Response**:
- Success: Email verified confirmation page
- Error: Verification failed page

### Password Reset

#### `GET /auth/forgot-password`
**Description**: Display forgot password form
**Authentication**: None required
**Response**: HTML forgot password page

#### `POST /auth/forgot-password`
**Description**: Send password reset email
**Authentication**: None required

**Request Body** (form data):
```
email: string (required) - User's email address
csrf_token: string (required if CSRF enabled) - CSRF protection token
```

**Response**: Always shows success message (prevents email enumeration)

#### `GET /auth/reset-password/{token}`
**Description**: Display password reset form with token validation
**Authentication**: None required

**Parameters**:
- `token` (path): Password reset token from email

**Response**:
- Success: Password reset form
- Error: Invalid/expired token page

#### `POST /auth/reset-password`
**Description**: Process password reset with new password
**Authentication**: None required

**Request Body** (form data):
```
token: string (required) - Password reset token
password: string (required) - New password
confirm_password: string (required) - Password confirmation
csrf_token: string (required if CSRF enabled) - CSRF protection token
```

**Response**:
- Success: Password reset success page
- Error: Reset form with error messages

### Logout

#### `GET /auth/logout`
**Description**: Log out user and clear session
**Authentication**: Session required
**Response**: Logout confirmation page with cleared session cookie

## Main Application Endpoints

### Homepage

#### `GET /`
**Description**: Application homepage with session-aware routing
**Authentication**: None required
**Response**: 
- **Authenticated users**: 302 redirect to `/dashboard`
- **Unauthenticated users (Development)**: Feature overview with login/register links
- **Unauthenticated users (Production)**: Landing page with login/register options

### Dashboard

#### `GET /dashboard`
**Description**: User dashboard with account information
**Authentication**: Session required
**Response**: 
- Success: Dashboard with user information and framework status
- Unauthenticated: Redirect to login page

### User Profile

#### `GET /profile`
**Description**: Display user profile edit form
**Authentication**: Session required
**Response**: Profile edit form with current user data

#### `POST /profile`
**Description**: Update user profile information
**Authentication**: Session required

**Request Body** (form data):
```
first_name: string (optional) - Updated first name
last_name: string (optional) - Updated last name
csrf_token: string (required if CSRF enabled) - CSRF protection token
```

**Response**:
- Success: Profile updated confirmation
- Error: Profile form with error messages

### Password Change

#### `GET /profile/change-password`
**Description**: Display password change form
**Authentication**: Session required
**Response**: Password change form

#### `POST /profile/change-password`
**Description**: Change user password with verification
**Authentication**: Session required

**Request Body** (form data):
```
current_password: string (required) - User's current password
new_password: string (required) - New password (must meet requirements)
confirm_password: string (required) - New password confirmation
csrf_token: string (required if CSRF enabled) - CSRF protection token
```

**Response**:
- Success: Password changed confirmation
- Error: Change form with error messages

**Security Features**:
- Current password verification required
- New password must meet complexity requirements
- New password must be different from current
- All other user sessions are invalidated

### Navigation Pages

#### `GET /page1`
**Description**: Sample navigation page demonstrating layout
**Authentication**: Session required
**Response**: Sample page with navigation demonstration

## System Endpoints

### Health Check

#### `GET /health`
**Description**: System health check endpoint
**Authentication**: None required
**Response** (JSON):
```json
{
  "status": "healthy",
  "framework": "PY-Framework",
  "version": "0.1.0"
}
```

## Development Endpoints

*Available only when running `dev.py`*

### Email Testing

#### `GET /dev/test-email`
**Description**: Email service testing interface
**Authentication**: None required (development only)
**Response**: Email testing form

#### `POST /dev/test-email`
**Description**: Send test email
**Authentication**: None required (development only)

**Request Body** (form data):
```
to_email: string (required) - Recipient email address
csrf_token: string (required if CSRF enabled) - CSRF protection token
```

**Response**: Test email sent confirmation

### Authentication Testing

#### `GET /dev/test-auth`
**Description**: Authentication system testing page
**Authentication**: None required (development only)
**Response**: Authentication testing interface

### Database Inspector

#### `GET /dev/database`
**Description**: Database inspection interface
**Authentication**: None required (development only)
**Response**: Database tables and data overview

## OAuth Endpoints (In Development)

### Google OAuth

#### `GET /auth/google`
**Description**: Initiate Google OAuth flow
**Authentication**: None required
**Response**: Redirect to Google OAuth

#### `GET /auth/google/callback`
**Description**: Handle Google OAuth callback
**Authentication**: OAuth flow
**Response**: Login success or error

### GitHub OAuth

#### `GET /auth/github`
**Description**: Initiate GitHub OAuth flow
**Authentication**: None required
**Response**: Redirect to GitHub OAuth

#### `GET /auth/github/callback`
**Description**: Handle GitHub OAuth callback
**Authentication**: OAuth flow
**Response**: Login success or error

## Rate Limiting

### Production Limits
- **Default**: 100 requests per hour per IP
- **Headers**: Rate limit information in response headers
  - `X-RateLimit-Limit`: Request limit
  - `X-RateLimit-Remaining`: Remaining requests
  - `X-RateLimit-Reset`: Reset timestamp
  - `Retry-After`: Seconds to wait (when rate limited)

### Development
- Rate limiting is disabled in development mode

## CSRF Protection

### Token Requirements
- All POST, PUT, PATCH, DELETE requests require CSRF tokens
- Tokens are automatically included in forms
- AJAX requests should include token in `X-CSRF-Token` header

### Token Management
- Tokens are valid for 60 minutes by default
- Tokens are session-bound for security
- Failed CSRF validation returns 403 Forbidden

## Error Handling

### Common HTTP Status Codes
- `200 OK`: Successful request
- `302 Found`: Redirect (authentication flows)
- `400 Bad Request`: Invalid input data
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: CSRF token invalid or access denied
- `404 Not Found`: Endpoint not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

### Error Pages
- User-friendly error pages for common errors
- Development mode shows detailed error information
- Production mode shows generic error messages

---

**API documentation is updated as new endpoints are added. Check the changelog for API changes.**