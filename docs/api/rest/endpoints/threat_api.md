# Threat Management API Documentation

## Overview

The Threat Management API provides endpoints for analyzing, detecting, and managing security threats across the Neurodefender platform. These endpoints support SIEM correlation, NGFW analysis, and phishing protection capabilities.

## Base URL

```
https://api.neurodefender.com/v1/threats
```

## Authentication

All endpoints require an authentication token:

```http
Authorization: Bearer <token>
```

## Threat Analysis

### Analyze Network Traffic

```http
POST /analyze/traffic
```

Analyzes network traffic for potential threats.

**Request Body**

```json
{
  "session_id": "sess_123",
  "flow": {
    "source": {
      "ip": "192.168.1.100",
      "port": 54321,
      "asn": "AS15169"
    },
    "destination": {
      "ip": "203.0.113.1",
      "port": 443,
      "domain": "suspicious-domain.com"
    },
    "protocol": "TCP",
    "bytes_sent": 1500,
    "bytes_received": 4500,
    "start_time": "2024-12-09T10:00:00Z",
    "duration": "PT5S"
  },
  "metadata": {
    "device_id": "device_789",
    "application": "chrome",
    "category": "web_traffic"
  }
}
```

**Response**

```json
{
  "analysis_id": "ana_456",
  "verdict": "suspicious",
  "score": 0.85,
  "threats": [
    {
      "type": "anomaly",
      "name": "Unusual Outbound Connection",
      "severity": "high",
      "confidence": 0.92,
      "indicators": [
        {
          "type": "ip_reputation",
          "value": "203.0.113.1",
          "description": "Known C2 server"
        }
      ]
    }
  ],
  "recommended_actions": [
    {
      "type": "block",
      "target": "destination_ip",
      "priority": "high"
    }
  ]
}
```

### Analyze Email

```http
POST /analyze/email
```

Analyzes email content for phishing attempts.

**Request Body**

```json
{
  "message_id": "msg_123",
  "metadata": {
    "from": "suspicious@example.com",
    "to": ["user@company.com"],
    "subject": "Urgent: Account Verification Required",
    "timestamp": "2024-12-09T10:05:00Z"
  },
  "content": {
    "text": "Please verify your account...",
    "html": "<html>Please verify...</html>"
  },
  "attachments": [
    {
      "filename": "document.pdf",
      "content_type": "application/pdf",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size": 125000
    }
  ],
  "urls": [
    {
      "url": "https://malicious-site.com/verify",
      "context": "href"
    }
  ]
}
```

**Response**

```json
{
  "analysis_id": "ana_789",
  "verdict": "malicious",
  "confidence": 0.98,
  "categories": ["phishing", "credential_theft"],
  "threats": [
    {
      "type": "phishing",
      "confidence": 0.95,
      "indicators": [
        {
          "type": "domain_reputation",
          "value": "malicious-site.com",
          "source": "threat_intel"
        },
        {
          "type": "content_analysis",
          "value": "credential_harvesting",
          "confidence": 0.92
        }
      ]
    }
  ],
  "analyzed_elements": {
    "attachments": [
      {
        "filename": "document.pdf",
        "verdict": "clean",
        "confidence": 0.89
      }
    ],
    "urls": [
      {
        "url": "https://malicious-site.com/verify",
        "verdict": "malicious",
        "categories": ["phishing"],
        "confidence": 0.97
      }
    ]
  }
}
```

### Analyze URL

```http
POST /analyze/url
```

Analyzes URLs for malicious content.

**Request Body**

```json
{
  "url": "https://suspicious-domain.com/login",
  "context": {
    "referrer": "email",
    "user_agent": "Mozilla/5.0...",
    "timestamp": "2024-12-09T10:10:00Z"
  },
  "options": {
    "fetch_content": true,
    "capture_screenshot": true,
    "follow_redirects": true
  }
}
```

**Response**

```json
{
  "analysis_id": "ana_101",
  "url": {
    "original": "https://suspicious-domain.com/login",
    "final": "https://malicious-site.com/phish",
    "redirects": [
      {
        "url": "https://redirect.suspicious-domain.com/r",
        "status_code": 302
      }
    ]
  },
  "verdict": "malicious",
  "categories": ["phishing", "impersonation"],
  "confidence": 0.96,
  "threats": [
    {
      "type": "brand_impersonation",
      "target": "legitimate-bank.com",
      "confidence": 0.98
    }
  ],
  "analysis_details": {
    "ssl_cert": {
      "issuer": "Let's Encrypt",
      "valid_from": "2024-11-09T00:00:00Z",
      "valid_to": "2025-02-09T23:59:59Z"
    },
    "domain_info": {
      "creation_date": "2024-12-08T00:00:00Z",
      "registrar": "NameCheap Inc.",
      "country": "RU"
    },
    "visual_similarity": {
      "matched_brand": "legitimate-bank.com",
      "similarity_score": 0.95
    }
  }
}
```

## Threat Intelligence

### Get Threat Intelligence Feed

```http
GET /intel/feed
```

Retrieves current threat intelligence data.

**Query Parameters**

- `type` (optional): Filter by indicator type (ip, domain, hash, url)
- `confidence` (optional): Minimum confidence score (0.0-1.0)
- `age` (optional): Maximum age in hours
- `limit` (optional): Number of indicators to return (default: 100)

**Response**

```json
{
  "indicators": [
    {
      "id": "ind_123",
      "type": "ip",
      "value": "203.0.113.1",
      "confidence": 0.95,
      "severity": "high",
      "labels": ["c2", "malware"],
      "first_seen": "2024-12-08T00:00:00Z",
      "last_seen": "2024-12-09T10:15:00Z",
      "sources": ["internal_analysis", "threat_feeds"],
      "metadata": {
        "malware_family": "emotet",
        "attack_type": "botnet"
      }
    }
  ],
  "pagination": {
    "next_cursor": "cursor_xyz",
    "has_more": true
  }
}
```

### Submit Threat Indicator

```http
POST /intel/indicators
```

Submits new threat intelligence indicators.

**Request Body**

```json
{
  "indicators": [
    {
      "type": "domain",
      "value": "malicious-domain.com",
      "confidence": 0.85,
      "severity": "high",
      "labels": ["phishing"],
      "context": {
        "detection_source": "phishing_analysis",
        "associated_campaign": "banking_trojan_q4_2024"
      }
    }
  ]
}
```

**Response**

```json
{
  "submitted": 1,
  "accepted": 1,
  "rejected": 0,
  "indicators": [
    {
      "id": "ind_456",
      "status": "accepted",
      "value": "malicious-domain.com"
    }
  ]
}
```

## Threat Hunting

### Search Threats

```http
POST /hunt/search
```

Searches for threats across all data sources.

**Request Body**

```json
{
  "query": {
    "type": "compound",
    "operator": "AND",
    "conditions": [
      {
        "field": "threat.severity",
        "operator": ">=",
        "value": "high"
      },
      {
        "field": "source.ip",
        "operator": "cidr",
        "value": "192.168.0.0/16"
      }
    ]
  },
  "timerange": {
    "start": "2024-12-09T00:00:00Z",
    "end": "2024-12-09T23:59:59Z"
  },
  "aggregations": [
    {
      "field": "threat.type",
      "type": "terms"
    }
  ]
}
```

**Response**

```json
{
  "total_matches": 150,
  "aggregations": {
    "threat.type": [
      {
        "key": "malware",
        "count": 75
      },
      {
        "key": "phishing",
        "count": 45
      }
    ]
  },
  "results": [
    {
      "id": "threat_789",
      "timestamp": "2024-12-09T10:20:00Z",
      "type": "malware",
      "severity": "critical",
      "source": {
        "ip": "192.168.1.100",
        "hostname": "workstation-1"
      },
      "details": {
        "malware_family": "ransomware",
        "detection_method": "ml_behavior"
      }
    }
  ]
}
```

## Error Responses

### Error Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": {
      "field": "confidence",
      "reason": "must be between 0.0 and 1.0"
    },
    "request_id": "req_abc123"
  }
}
```

### Common Error Codes

- `VALIDATION_ERROR`: Invalid request parameters
- `ANALYSIS_FAILED`: Analysis process failed
- `RESOURCE_NOT_FOUND`: Requested resource not found
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `INTERNAL_ERROR`: Internal server error

## Rate Limiting

- Analysis endpoints: 100 requests per minute
- Intel queries: 1000 requests per minute
- Submissions: 50 requests per minute

**Headers**

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1607506800
```
