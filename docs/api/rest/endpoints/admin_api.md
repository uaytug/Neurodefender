# Administrative API Documentation

## Overview

The Administrative API provides endpoints for managing and configuring the Neurodefender system. These endpoints require administrative privileges and support system-wide operations.

## Base URL

```plaintext
https://api.neurodefender.com/v1/admin
```

## Authentication

All endpoints require an administrative access token in the Authorization header:

```http
Authorization: Bearer <admin_token>
```

## System Management

### Get System Status

```http
GET /system/status
```

Returns the current status of all system components.

#### Example Response for Get System Status

```json
{
  "status": "healthy",
  "components": [
    {
      "name": "SIEM",
      "status": "healthy",
      "version": "1.2.3",
      "lastUpdate": "2024-12-09T10:00:00Z",
      "metrics": {
        "uptime": "10d",
        "eventRate": 1000,
        "cpuUsage": 45.5,
        "memoryUsage": 67.8
      }
    },
    {
      "name": "NGFW",
      "status": "healthy",
      "version": "2.1.0",
      "lastUpdate": "2024-12-09T10:00:00Z",
      "metrics": {
        "uptime": "15d",
        "throughput": "10Gbps",
        "connections": 50000,
        "blockRate": 0.5
      }
    }
  ],
  "alerts": [
    {
      "severity": "warning",
      "component": "ML Platform",
      "message": "High resource usage detected",
      "timestamp": "2024-12-09T09:45:00Z"
    }
  ]
}
```

### Update System Configuration

```http
PUT /system/config
```

Updates global system configuration.

#### Request Payload for System Configuration

```json
{
  "logging": {
    "level": "INFO",
    "retention": "30d",
    "exportEnabled": true
  },
  "monitoring": {
    "metricsInterval": "15s",
    "alertThresholds": {
      "cpu": 80,
      "memory": 85,
      "diskSpace": 90
    }
  },
  "security": {
    "mfaRequired": true,
    "sessionTimeout": "12h",
    "passwordPolicy": {
      "minLength": 12,
      "requireSpecialChars": true,
      "expiryDays": 90
    }
  }
}
```

#### Response Example

```json
{
  "status": "success",
  "message": "Configuration updated successfully",
  "timestamp": "2024-12-09T10:05:00Z"
}
```

## User Management

### List Users

```http
GET /users
```

### Query Parameters

- `role` (optional): Filter by user role
- `status` (optional): Filter by user status
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 50)

#### Example Response

```json
{
  "users": [
    {
      "id": "usr_123",
      "email": "admin@company.com",
      "name": "John Doe",
      "role": "admin",
      "status": "active",
      "lastLogin": "2024-12-09T09:00:00Z",
      "permissions": ["read:all", "write:all", "admin:all"]
    }
  ],
  "pagination": {
    "total": 100,
    "page": 1,
    "limit": 50,
    "hasMore": true
  }
}
```

### Create User

```http
POST /users
```

#### Request Payload

```json
{
  "email": "user@company.com",
  "name": "Jane Smith",
  "role": "analyst",
  "permissions": ["read:events", "write:alerts"],
  "metadata": {
    "department": "Security",
    "location": "HQ"
  }
}
```

#### Example Response for Update License

```json
{
  "id": "usr_124",
  "email": "user@company.com",
  "name": "Jane Smith",
  "role": "analyst",
  "status": "pending_activation",
  "created_at": "2024-12-09T10:10:00Z",
  "activation_link": "https://..."
}
```

## License Management

### Get License Status

```http
GET /license/status
```

#### Example Response of Lincese Status

```json
{
  "licenseId": "lic_789",
  "status": "active",
  "type": "enterprise",
  "expires": "2025-12-31T23:59:59Z",
  "features": ["siem", "ngfw", "ml_platform", "phishing_protection"],
  "limits": {
    "users": 500,
    "events_per_day": 1000000,
    "nodes": 100
  },
  "usage": {
    "users": 320,
    "events_per_day": 750000,
    "nodes": 45
  }
}
```

### Update License

```http
PUT /license
```

#### Request Payload for License Key

```json
{
  "licenseKey": "XXXX-YYYY-ZZZZ-WWWW",
  "activate": true
}
```

### Example Response for License Update

```json
{
  "status": "success",
  "message": "License updated successfully",
  "validFrom": "2024-12-09T00:00:00Z",
  "validTo": "2025-12-31T23:59:59Z"
}
```

## Backup and Maintenance

### Create Backup

```http
POST /system/backup
```

#### Request Body

```json
{
  "type": "full",
  "includeEvents": true,
  "includeMlModels": true,
  "retention": "30d",
  "encryption": {
    "enabled": true,
    "algorithm": "AES-256"
  }
}
```

#### Response

```json
{
  "backupId": "bkp_456",
  "status": "in_progress",
  "estimatedSize": "50GB",
  "estimatedDuration": "30m",
  "downloadUrl": "https://...",
  "expiresAt": "2024-12-10T10:15:00Z"
}
```

### Schedule Maintenance

```http
POST /system/maintenance
```

#### Request Body for Schedule Maintenance

```json
{
  "type": "upgrade",
  "scheduledTime": "2024-12-15T02:00:00Z",
  "estimatedDuration": "2h",
  "components": ["siem", "ngfw"],
  "notifyUsers": true,
  "allowReschedule": true
}
```

#### Response Example for Schedule Maintenance

```json
{
  "maintenanceId": "mnt_789",
  "status": "scheduled",
  "scheduledTime": "2024-12-15T02:00:00Z",
  "endTime": "2024-12-15T04:00:00Z",
  "notificationsSent": 450
}
```

## Error Responses

### Error Format

```json
{
  "status": "error",
  "code": "ERROR_CODE",
  "message": "Human readable error message",
  "details": {
    "field": "specific_field",
    "reason": "validation_failed"
  },
  "timestamp": "2024-12-09T10:20:00Z",
  "requestId": "req_abc123"
}
```

### Common Error Codes

- `UNAUTHORIZED`: Invalid or missing authentication
- `FORBIDDEN`: Insufficient permissions
- `INVALID_REQUEST`: Malformed request or invalid parameters
- `RESOURCE_NOT_FOUND`: Requested resource doesn't exist
- `INTERNAL_ERROR`: Server-side error
- `LICENSE_ERROR`: License-related issues
- `MAINTENANCE_CONFLICT`: Conflicts with scheduled maintenance

## Rate Limiting

- Default rate limit: 100 requests per minute per IP
- Administrative endpoints: 200 requests per minute per token
- Bulk operations count as multiple requests

### Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1607506800
```
