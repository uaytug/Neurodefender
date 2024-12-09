# API Curl Examples

## Authentication Examples

### Generate Access Token

```bash
curl -X POST "https://api.neurodefender.com/v1/auth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "username": "user@example.com",
    "password": "secure_password",
    "scope": ["read:events", "write:alerts"]
  }'
```

### Refresh Token

```bash
curl -X POST "https://api.neurodefender.com/v1/auth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "refresh_token",
    "refresh_token": "rt_abc123xyz"
  }'
```

### Verify MFA Challenge

```bash
curl -X POST "https://api.neurodefender.com/v1/auth/mfa/verify" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_id": "cha_789",
    "code": "123456"
  }'
```

## SIEM Examples

### Ingest Security Event

```bash
curl -X POST "https://api.neurodefender.com/v1/siem/events" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "firewall",
    "severity": "high",
    "timestamp": "2024-12-09T10:00:00Z",
    "message": "Suspicious outbound connection detected",
    "metadata": {
      "source_ip": "192.168.1.100",
      "destination_ip": "203.0.113.1",
      "protocol": "TCP"
    }
  }'
```

### Query Events

```bash
curl -X POST "https://api.neurodefender.com/v1/siem/search" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "severity:high AND source:firewall",
    "timerange": {
      "start": "2024-12-09T00:00:00Z",
      "end": "2024-12-09T23:59:59Z"
    },
    "limit": 100
  }'
```

### Create Alert Rule

```bash
curl -X POST "https://api.neurodefender.com/v1/siem/rules" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "High Severity Firewall Events",
    "description": "Detect high severity events from firewall",
    "conditions": [
      {
        "field": "severity",
        "operator": "equals",
        "value": "high"
      },
      {
        "field": "source",
        "operator": "equals",
        "value": "firewall"
      }
    ],
    "actions": [
      {
        "type": "notify",
        "parameters": {
          "channels": ["email", "slack"],
          "priority": "high"
        }
      }
    ],
    "enabled": true
  }'
```

## NGFW Examples

### Update Firewall Policy

```bash
curl -X PUT "https://api.neurodefender.com/v1/ngfw/policies/pol_123" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "rules": [
      {
        "priority": 1,
        "action": "block",
        "conditions": {
          "source_cidr": "192.168.0.0/16",
          "destination_port": 3389,
          "protocol": "TCP"
        }
      }
    ],
    "comment": "Block RDP access"
  }'
```

### Analyze Traffic

```bash
curl -X POST "https://api.neurodefender.com/v1/ngfw/analyze" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "sess_123",
    "flow": {
      "source": {
        "ip": "192.168.1.100",
        "port": 54321
      },
      "destination": {
        "ip": "203.0.113.1",
        "port": 443
      },
      "protocol": "TCP"
    },
    "metadata": {
      "application": "chrome"
    }
  }'
```

## ML Platform Examples

### Train Model

```bash
curl -X POST "https://api.neurodefender.com/v1/ml/models/train" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "model_id": "model_123",
    "dataset": {
      "id": "dataset_456",
      "version": "1.0.0"
    },
    "parameters": {
      "epochs": 100,
      "batch_size": 32,
      "learning_rate": 0.001
    }
  }'
```

### Get Model Status

```bash
curl -X GET "https://api.neurodefender.com/v1/ml/models/model_123/status" \
  -H "Authorization: Bearer <access_token>"
```

## Phishing Protection Examples

### Analyze Email

```bash
curl -X POST "https://api.neurodefender.com/v1/phishing/email/analyze" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "message_id": "msg_123",
    "metadata": {
      "from": "suspicious@example.com",
      "to": ["user@company.com"],
      "subject": "Urgent: Account Verification Required"
    },
    "content": {
      "text": "Please verify your account...",
      "html": "<html>Please verify...</html>"
    },
    "urls": [
      {
        "url": "https://suspicious-site.com/verify",
        "context": "href"
      }
    ]
  }'
```

### Check URL

```bash
curl -X POST "https://api.neurodefender.com/v1/phishing/url/check" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://suspicious-site.com/login",
    "options": {
      "fetch_content": true,
      "capture_screenshot": true
    }
  }'
```

## Administrative Examples

### Get System Status

```bash
curl -X GET "https://api.neurodefender.com/v1/admin/system/status" \
  -H "Authorization: Bearer <access_token>"
```

### Create Backup

```bash
curl -X POST "https://api.neurodefender.com/v1/admin/system/backup" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "full",
    "includeEvents": true,
    "includeMlModels": true,
    "retention": "30d"
  }'
```

## Using jq for JSON Processing

### Parse Event Search Results

```bash
curl -s -X POST "https://api.neurodefender.com/v1/siem/search" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "severity:high",
    "limit": 10
  }' | jq '.events[] | {id: .id, severity: .severity, message: .message}'
```

### Extract Access Token

```bash
curl -s -X POST "https://api.neurodefender.com/v1/auth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "username": "user@example.com",
    "password": "secure_password"
  }' | jq -r '.access_token'
```

## Error Handling Examples

### Handle Rate Limiting

```bash
response=$(curl -s -w "%{http_code}" -X POST "https://api.neurodefender.com/v1/siem/events" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{...}')

http_code=${response: -3}
body=${response:0:${#response}-3}

if [ "$http_code" -eq 429 ]; then
  retry_after=$(echo $body | jq -r '.error.retry_after')
  echo "Rate limit exceeded. Retry after $retry_after seconds"
fi
```

### Refresh Token on Expiry

```bash
response=$(curl -s -w "%{http_code}" -X GET "https://api.neurodefender.com/v1/siem/events" \
  -H "Authorization: Bearer <access_token>")

if [ "$http_code" -eq 401 ]; then
  new_token=$(curl -s -X POST "https://api.neurodefender.com/v1/auth/token" \
    -H "Content-Type: application/json" \
    -d '{
      "grant_type": "refresh_token",
      "refresh_token": "'$refresh_token'"
    }' | jq -r '.access_token')
  # Retry original request with new token
fi
```
