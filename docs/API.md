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

### Settings Management

#### `GET /settings`
**Description**: Comprehensive user settings and account management page
**Authentication**: Session required
**Response**: Settings page with multiple sections

**Settings Sections**:
- **Account Information**: Personal details, email verification status, member since date
- **Security Settings**: Password security status, account protection features
- **Active Sessions**: View and manage login sessions across devices
- **Framework Information**: System status and development tools
- **Danger Zone**: Account management actions (logout all sessions, delete account)

**Features**:
- Session management with current session highlighting
- Quick access to profile editing and password change
- Security feature status overview
- Development tools access (in development mode)
- Responsive grid layout with professional styling

### Documentation System

#### `GET /docs`
**Description**: Documentation system homepage
**Authentication**: Session required
**Response**: 
- **Authenticated**: 302 redirect to `/docs/overview`
- **Unauthenticated**: 302 redirect to `/auth/login`

#### `GET /docs/{doc_name}`
**Description**: View specific documentation page with markdown rendering
**Authentication**: Session required

**Parameters**:
- `doc_name` (path): Documentation page name

**Available Documentation Pages**:
- `overview` - Project Overview (README.md)
- `security` - Security Guide
- `api` - API Reference
- `deployment` - Deployment Guide  
- `specifications` - Development Specifications (CLAUDE.md)

**Response**: 
- **Authenticated**: HTML page with markdown content rendered and navigation sidebar
- **Unauthenticated**: 302 redirect to `/auth/login`
- **Invalid doc_name**: 302 redirect to `/docs/overview`

**Features**:
- Responsive sidebar navigation
- Markdown to HTML conversion with syntax highlighting
- Professional styling for code blocks and tables
- Mobile-friendly responsive design

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

## OAuth Endpoints ✅ IMPLEMENTED

### Google OAuth

#### `GET /auth/oauth/google`
**Description**: Initiate Google OAuth flow with state validation
**Authentication**: None required
**Response**: Redirect to Google OAuth consent screen

**Security Features**:
- CSRF state token validation
- Session tracking for OAuth flow
- Automatic cleanup of expired state tokens

#### `GET /auth/oauth/google/callback`
**Description**: Handle Google OAuth callback and create/link user account
**Authentication**: OAuth flow with state validation
**Response**: Login success with session creation or error page

**Query Parameters**:
```
code: string (required) - OAuth authorization code from Google
state: string (required) - CSRF protection state token
```

**Functionality**:
- Validates OAuth state token
- Exchanges code for access token
- Retrieves user profile information
- Links to existing account if email matches
- Creates new account if no existing user found
- Establishes authenticated session

### GitHub OAuth

#### `GET /auth/oauth/github`
**Description**: Initiate GitHub OAuth flow with state validation
**Authentication**: None required
**Response**: Redirect to GitHub OAuth consent screen

**Security Features**:
- CSRF state token validation
- Session tracking for OAuth flow
- Automatic cleanup of expired state tokens

#### `GET /auth/oauth/github/callback`
**Description**: Handle GitHub OAuth callback and create/link user account
**Authentication**: OAuth flow with state validation
**Response**: Login success with session creation or error page

**Query Parameters**:
```
code: string (required) - OAuth authorization code from GitHub
state: string (required) - CSRF protection state token
```

**Functionality**:
- Validates OAuth state token
- Exchanges code for access token
- Retrieves user profile and primary email
- Links to existing account if email matches
- Creates new account if no existing user found
- Establishes authenticated session

## Two-Factor Authentication Endpoints ✅ NEW

### 2FA Management

#### `GET /profile/2fa`
**Description**: Display 2FA settings and management page
**Authentication**: Session required
**Response**: HTML page with 2FA status and management options

**Features**:
- Shows current 2FA status (enabled/disabled)
- Displays remaining backup codes count
- Provides setup instructions if 2FA not enabled
- Management options if 2FA is enabled

#### `GET /profile/2fa/setup`
**Description**: Display 2FA setup page with QR code
**Authentication**: Session required
**Response**: HTML page with QR code and setup instructions

**Features**:
- Generates TOTP secret key
- Creates QR code for mobile app setup
- Provides manual entry option
- Setup verification form

#### `POST /profile/2fa/setup`
**Description**: Confirm 2FA setup with verification code
**Authentication**: Session required

**Request Body** (form data):
```
secret: string (required) - TOTP secret key
verification_code: string (required) - 6-digit TOTP code
csrf_token: string (required) - CSRF protection token
```

**Response**:
- Success: 2FA enabled with backup codes display
- Error: Invalid verification code or setup failure

**Features**:
- Verifies TOTP code against secret
- Enables 2FA for user account
- Generates 8 backup recovery codes
- Provides code display and copy functionality

#### `GET /profile/2fa/backup-codes`
**Description**: Display backup code regeneration page
**Authentication**: Session required
**Role Requirements**: User must have 2FA enabled
**Response**: HTML form to regenerate backup codes

#### `POST /profile/2fa/backup-codes`
**Description**: Generate new backup codes (invalidates old ones)
**Authentication**: Session required
**Role Requirements**: User must have 2FA enabled

**Request Body** (form data):
```
csrf_token: string (required) - CSRF protection token
```

**Response**:
- Success: New backup codes display
- Error: Backup code generation failure

**Features**:
- Invalidates all existing backup codes
- Generates 8 new backup codes
- Provides code display and copy functionality

#### `GET /profile/2fa/disable`
**Description**: Display 2FA disable confirmation page
**Authentication**: Session required
**Role Requirements**: User must have 2FA enabled
**Response**: HTML form to disable 2FA

#### `POST /profile/2fa/disable`
**Description**: Disable 2FA after verification
**Authentication**: Session required
**Role Requirements**: User must have 2FA enabled

**Request Body** (form data):
```
password: string (required) - User's current password
verification_code: string (required) - TOTP code or backup code
csrf_token: string (required) - CSRF protection token
```

**Response**:
- Success: 2FA disabled confirmation
- Error: Invalid password or verification code

**Features**:
- Requires password confirmation
- Accepts TOTP code or backup code for verification
- Completely removes 2FA setup and backup codes
- Security warning about reduced account protection

### 2FA Login Flow

#### `GET /auth/2fa-verify`
**Description**: Display 2FA verification page during login
**Authentication**: 2FA session token required
**Response**: HTML form for 2FA code entry

**Features**:
- Requires valid 2FA session token
- Provides TOTP code input
- Option to use backup code
- Instructions for authenticator apps

#### `POST /auth/2fa-verify`
**Description**: Process 2FA verification code and complete login
**Authentication**: 2FA session token required

**Request Body** (form data):
```
token: string (required) - 2FA session token
verification_code: string (required) - TOTP code or backup code
csrf_token: string (required) - CSRF protection token
```

**Response**:
- Success: Login completed with session creation and dashboard redirect
- Error: Invalid verification code or token

**Features**:
- Validates 2FA session token
- Accepts TOTP codes or backup codes
- Tracks backup code usage
- Creates authenticated session on success
- Automatic redirect to dashboard

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

## Admin Endpoints ✅ NEW

### User Management

#### `GET /users`
**Description**: User management page (admin view vs personal view)
**Authentication**: Session required
**Role Requirements**: None (view changes based on role)
**Response**: 
- Admin users: Full user management interface with all users
- Regular users: Personal account view only

**Admin Features**:
- User statistics and summary
- Complete user list with roles
- Admin tools and actions
- Quick access to user management functions

#### `GET /users/{user_id}/edit-role`
**Description**: Display user role editing form
**Authentication**: Session required
**Role Requirements**: Administrator (role_id = 0)
**Response**: Role editing form for specified user

**URL Parameters**:
```
user_id: integer (required) - ID of user to edit
```

**Security Features**:
- Admin cannot edit their own role
- CSRF protection enabled
- Role validation on target user

#### `POST /users/{user_id}/edit-role`
**Description**: Update user role
**Authentication**: Session required
**Role Requirements**: Administrator (role_id = 0)

**URL Parameters**:
```
user_id: integer (required) - ID of user to edit
```

**Request Body** (form data):
```
role_id: integer (required) - New role ID (0=admin, 1=user)
csrf_token: string (required) - CSRF protection token
```

**Response**:
- Success: Role updated confirmation
- Error: Edit form with error messages

**Security Features**:
- Admin cannot edit their own role
- Role ID validation (must be 0 or 1)
- CSRF protection required

#### `GET /users/{user_id}/sessions`
**Description**: View user's active and historical sessions
**Authentication**: Session required
**Role Requirements**: Administrator (role_id = 0)
**Response**: Session monitoring page for specified user

**URL Parameters**:
```
user_id: integer (required) - ID of user to view sessions for
```

**Session Information Displayed**:
- Session ID (truncated for security)
- Creation and expiration times
- IP address and user agent
- Active/inactive status
- Device information

#### `GET /users/{user_id}/toggle`
**Description**: Toggle user account active status
**Authentication**: Session required
**Role Requirements**: Administrator (role_id = 0)

**URL Parameters**:
```
user_id: integer (required) - ID of user to toggle status
```

**Response**: Status update confirmation

**Security Features**:
- Admin cannot deactivate their own account
- Account deactivation invalidates all user sessions
- Immediate effect on user access

**Behavior**:
- Active users are deactivated
- Inactive users are reactivated
- Deactivation prevents login and invalidates sessions
- Reactivation allows immediate login

## Role-Based Security ✅ NEW

### Access Control
- **Admin Routes**: Require role_id = 0 (Administrator)
- **User Routes**: Require any authenticated user
- **Self-Protection**: Admins cannot modify their own accounts
- **Role Validation**: All admin actions validate user permissions

### Permission Levels
```
Role ID 0 (Administrator):
- Full user management access
- Can edit other users' roles
- Can view all user sessions
- Can activate/deactivate accounts
- Cannot modify own account

Role ID 1 (Regular User):
- Personal account access only
- Can edit own profile
- Can change own password
- Can view own sessions
- No admin functionality
```

### Security Features
- All admin actions require CSRF tokens
- Role validation on every request
- Session-based authentication
- Automatic permission checking
- Graceful access denial handling

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