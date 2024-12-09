# Neurodefender API Specifications

## Overview

This document details the API specifications for the Neurodefender system, covering all interfaces between SIEM, NGFW, ML Platform, and Phishing Protection components. All APIs follow RESTful principles and use JSON for data exchange unless otherwise specified.

## Global Standards

### 1. Authentication

```http
Authorization: Bearer <jwt_token>
```

### 2. Response Format

```json
{
    "status": "success|error",
    "data": {}, // Response payload
    "error": {  // Only present if status is "error"
        "code": "ERROR_CODE",
        "message": "Human readable message",
        "details": {}
    }
}
```

### 3. Common Headers

```http
Content-Type: application/json
X-Request-ID: <uuid>
X-API-Version: v1
```

## SIEM APIs

### 1. Event Ingestion API

#### Submit Events

```http
POST /api/v1/siem/events
Content-Type: application/json

{
    "source": "string",
    "timestamp": "ISO8601",
    "events": [{
        "id": "string",
        "severity": "low|medium|high|critical",
        "category": "string",
        "message": "string",
        "metadata": {}
    }],
    "batch_options": {
        "compression": "none|gzip",
        "encoding": "json|binary"
    }
}
```

#### Batch Query

```http
POST /api/v1/siem/search
Content-Type: application/json

{
    "query": "source = 'firewall' AND severity > 'high'",
    "timerange": {
        "start": "2024-03-09T00:00:00Z",
        "end": "2024-03-09T23:59:59Z"
    },
    "limit": 1000,
    "aggregations": [{
        "field": "severity",
        "type": "terms"
    }]
}
```

## NGFW APIs

### 1. Policy Management

#### Create Policy

```http
POST /api/v1/ngfw/policies
Content-Type: application/json

{
    "name": "string",
    "description": "string",
    "type": "access|threat|application",
    "rules": [{
        "id": "string",
        "priority": integer,
        "conditions": [{
            "field": "string",
            "operator": "string",
            "value": "any"
        }],
        "actions": [{
            "type": "string",
            "parameters": {}
        }]
    }],
    "enabled": boolean
}
```

#### Update Policy

```http
PUT /api/v1/ngfw/policies/{policy_id}
Content-Type: application/json

{
    "name": "string",
    "description": "string",
    "rules": [...],
    "enabled": boolean
}
```

### 2. Threat Detection

#### Submit Traffic for Analysis

```http
POST /api/v1/ngfw/analyze
Content-Type: application/json

{
    "session_id": "string",
    "protocol": "string",
    "source": {
        "ip": "string",
        "port": integer
    },
    "destination": {
        "ip": "string",
        "port": integer
    },
    "payload": "base64",
    "metadata": {}
}
```

## ML Platform APIs

### 1. Model Management

#### Train Model

```http
POST /api/v1/ml/models/train
Content-Type: application/json

{
    "model_id": "string",
    "type": "anomaly|threat|phishing",
    "dataset": {
        "id": "string",
        "version": "string"
    },
    "parameters": {
        "epochs": integer,
        "batch_size": integer,
        "learning_rate": float
    },
    "validation": {
        "split_ratio": float,
        "metrics": ["accuracy", "precision", "recall"]
    }
}
```

#### Inference Request

```http
POST /api/v1/ml/models/predict
Content-Type: application/json

{
    "model_id": "string",
    "instances": [{
        "features": [...],
        "metadata": {}
    }],
    "options": {
        "threshold": float,
        "max_latency": integer
    }
}
```

### 2. Feature Store

#### Update Features

```http
POST /api/v1/ml/features
Content-Type: application/json

{
    "feature_set": "string",
    "features": [{
        "name": "string",
        "value": "any",
        "timestamp": "ISO8601"
    }]
}
```

## Phishing Protection APIs

### 1. Email Analysis

#### Analyze Email

```http
POST /api/v1/phishing/email/analyze
Content-Type: application/json

{
    "message_id": "string",
    "headers": {},
    "body": {
        "text": "string",
        "html": "string"
    },
    "attachments": [{
        "filename": "string",
        "content": "base64",
        "mime_type": "string"
    }],
    "options": {
        "scan_attachments": boolean,
        "check_urls": boolean
    }
}
```

### 2. URL Analysis

#### Check URL

```http
POST /api/v1/phishing/url/check
Content-Type: application/json

{
    "url": "string",
    "context": {
        "source": "string",
        "referrer": "string"
    },
    "options": {
        "follow_redirects": boolean,
        "screenshot": boolean
    }
}
```

## WebSocket APIs

### 1. Real-time Event Stream

```http
GET /ws/v1/events
Protocol: WebSocket

// Subscribe message
{
    "action": "subscribe",
    "channels": ["alerts", "threats", "system"],
    "filters": {
        "severity": ["high", "critical"]
    }
}
```

### 2. Health Check Stream

```http
GET /ws/v1/health
Protocol: WebSocket

// Health update message
{
    "timestamp": "ISO8601",
    "component": "string",
    "status": "healthy|degraded|unhealthy",
    "metrics": {}
}
```

## Error Codes

### Common Error Codes

- `AUTH_001`: Authentication failed
- `AUTH_002`: Invalid token
- `AUTH_003`: Insufficient permissions
- `VAL_001`: Invalid request format
- `VAL_002`: Missing required field
- `SYS_001`: Internal server error
- `SYS_002`: Service unavailable

### Component-specific Error Codes

- `SIEM_001`: Invalid query syntax
- `SIEM_002`: Query timeout
- `NGFW_001`: Invalid policy format
- `NGFW_002`: Rule conflict detected
- `ML_001`: Model not found
- `ML_002`: Training failed
- `PHISH_001`: Analysis timeout
- `PHISH_002`: Invalid URL format

## Rate Limiting

- Default rate limit: 1000 requests per minute per API key
- Burst limit: 100 requests per second
- Headers:

  ```http
  X-RateLimit-Limit: 1000
  X-RateLimit-Remaining: 999
  X-RateLimit-Reset: 1615480800
  ```

## Versioning

- API versioning through URL path: `/api/v1/`
- API versioning through header: `X-API-Version: v1`
- Backward compatibility maintained for one major version

## Security Requirements

1. All endpoints must use TLS 1.3
2. JWT tokens must be rotated every 24 hours
3. API keys must be stored as bcrypt hashes
4. All requests must include a valid X-Request-ID
5. Sensitive data must be encrypted at rest and in transit

## Future Enhancements

- GraphQL API support
- gRPC interfaces for high-performance operations
- Enhanced batch processing capabilities
- Streaming API improvements
- Extended ML model management features
