# Authentication API Documentation

## Overview

The Authentication API provides endpoints for managing user authentication, authorization, and access token management in the Neurodefender system.

## Base URL

```
https://api.neurodefender.com/v1/auth
```

## Token Management

### Generate Access Token

```http
POST /token
Content-Type: application/json
```

Generates a new access token using credentials or refresh token.

**Request Body - Password Grant**

```json
{
  "grant_type": "password",
  "username": "user@example.com",
  "password": "secure_password",
  "scope": ["read:events", "write:alerts"]
}
```

**Request Body - Refresh Token**

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "rt_abc123xyz",
  "scope": ["read:events", "write:alerts"]
}
```

**Response**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "rt_def456uvw",
  "scope": ["read:events", "write:alerts"]
}
```

### Revoke Token

```http
POST /token/revoke
Authorization: Bearer <access_token>
```

Revokes an access token or refresh token.

**Request Body**

```json
{
  "token": "rt_abc123xyz",
  "token_type_hint": "refresh_token"
}
```

**Response**

```json
{
  "status": "success",
  "message": "Token revoked successfully",
  "timestamp": "2024-12-09T10:00:00Z"
}
```

## Multi-Factor Authentication

### Request MFA Challenge

```http
POST /mfa/challenge
Authorization: Bearer <access_token>
```

Requests a new MFA challenge.

**Request Body**

```json
{
  "type": "totp",  // or "sms", "email", "webauthn"
  "destination": "user@example.com"  // required for sms/email
}
```

**Response**

```json
{
  "challenge_id": "cha_789",
  "expires_at": "2024-12-09T10:05:00Z",
  "verification_attempts_remaining": 3,
  "type": "totp"
}
```

### Verify MFA Challenge

```http
POST /mfa/verify
Authorization: Bearer <access_token>
```

Verifies an MFA challenge response.

**Request Body**

```json
{
  "challenge_id": "cha_789",
  "code": "123456",  // TOTP code or other verification token
  "remember_device": true
}
```

**Response**

```json
{
  "status": "success",
  "mfa_token": "mfa_xyz789",
  "device_token": "dt_456abc"  // Only if remember_device is true
}
```

## Session Management

### Get Current Session

```http
GET /session
Authorization: Bearer <access_token>
```

Returns information about the current session.

**Response**

```json
{
  "session_id": "sess_123",
  "user": {
    "id": "usr_456",
    "email": "user@example.com",
    "name": "John Doe"
  },
  "created_at": "2024-12-09T09:00:00Z",
  "expires_at": "2024-12-09T21:00:00Z",
  "last_activity": "2024-12-09T10:00:00Z",
  "mfa_verified": true,
  "permissions": ["read:events", "write:alerts"],
  "device_info": {
    "browser": "Chrome",
    "os": "Windows",
    "ip": "192.168.1.1",
    "location": "New York, US"
  }
}
```

### End Session

```http
DELETE /session
Authorization: Bearer <access_token>
```

Ends the current session.

**Response**

```json
{
  "status": "success",
  "message": "Session ended successfully",
  "timestamp": "2024-12-09T10:15:00Z"
}
```

### List Active Sessions

```http
GET /sessions
Authorization: Bearer <access_token>
```

Lists all active sessions for the current user.

**Response**

```json
{
  "sessions": [
    {
      "session_id": "sess_123",
      "created_at": "2024-12-09T09:00:00Z",
      "last_activity": "2024-12-09T10:00:00Z",
      "device_info": {
        "browser": "Chrome",
        "os": "Windows",
        "ip": "192.168.1.1"
      },
      "is_current": true
    }
  ],
  "total_count": 1
}
```

## Permission Management

### Get User Permissions

```http
GET /permissions
Authorization: Bearer <access_token>
```

Returns the permissions for the current user.

**Response**

```json
{
  "user_id": "usr_456",
  "permissions": [
    {
      "name": "read:events",
      "description": "Read security events",
      "granted_at": "2024-12-09T00:00:00Z",
      "granted_by": "usr_admin"
    }
  ],
  "roles": [
    {
      "name": "security_analyst",
      "description": "Security Analyst Role",
      "permissions": ["read:events", "write:alerts"]
    }
  ]
}
```

### Check Permission

```http
POST /permissions/check
Authorization: Bearer <access_token>
```

Checks if the user has specific permissions.

**Request Body**

```json
{
  "permissions": ["read:events", "write:alerts"],
  "resource_id": "evt_789",  // Optional
  "check_type": "any"  // or "all"
}
```

**Response**

```json
{
  "allowed": true,
  "missing_permissions": [],
  "details": {
    "read:events": true,
    "write:alerts": true
  }
}
```

## Error Handling

### Error Response Format

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid username or password",
  "error_uri": "https://docs.example.com/auth/errors#invalid_grant",
  "timestamp": "2024-12-09T10:20:00Z",
  "request_id": "req_abc123"
}
```

### Common Error Types

- `invalid_request`: The request is missing required parameters or malformed
- `invalid_grant`: Invalid credentials or refresh token
- `invalid_token`: Token is invalid, expired, or revoked
- `insufficient_scope`: Token lacks required permissions
- `unauthorized_client`: Client is not authorized for this grant type
- `mfa_required`: Multi-factor authentication is required
- `session_expired`: User session has expired

## Rate Limiting

### Limits

- Token generation: 10 requests per minute per IP
- Token validation: 100 requests per minute per IP
- MFA verification: 5 attempts per challenge
- Other endpoints: 50 requests per minute per token

### Headers

```http
X-RateLimit-Limit: 50
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1607506800
```

## Security Considerations

1. All endpoints use HTTPS only
2. Tokens are JWT-based with appropriate expiration
3. Refresh tokens are single-use and rotated
4. Failed authentication attempts are rate-limited
5. MFA challenges expire after 5 minutes
6. Sessions are invalidated after 12 hours of inactivity
7. IP-based anomaly detection for authentication attempts
8. Device fingerprinting for suspicious activity detection
