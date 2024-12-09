# GraphQL Mutation Examples

## Overview

This document provides practical examples of GraphQL mutations for the Neurodefender API. Each example includes the mutation query, variables, and sample responses.

## Authentication Mutations

### Create API Token

```graphql
mutation CreateAPIToken($input: CreateAPITokenInput!) {
  createAPIToken(input: $input) {
    token
    expiresAt
    permissions
  }
}

# Variables
{
  "input": {
    "name": "SIEM Integration Token",
    "expiration": "24h",
    "permissions": ["READ_EVENTS", "WRITE_EVENTS"]
  }
}

# Response
{
  "data": {
    "createAPIToken": {
      "token": "eyJhbGciOiJIUzI1NiIs...",
      "expiresAt": "2024-12-10T00:00:00Z",
      "permissions": ["READ_EVENTS", "WRITE_EVENTS"]
    }
  }
}
```

## SIEM Mutations

### Create Alert Rule

```graphql
mutation CreateAlertRule($input: AlertRuleInput!) {
  createAlertRule(input: $input) {
    id
    name
    conditions {
      field
      operator
      value
    }
    actions {
      type
      parameters
    }
    enabled
  }
}

# Variables
{
  "input": {
    "name": "High Severity Network Events",
    "conditions": [
      {
        "field": "severity",
        "operator": "GREATER_THAN",
        "value": "high"
      },
      {
        "field": "source.type",
        "operator": "EQUALS",
        "value": "firewall"
      }
    ],
    "actions": [
      {
        "type": "NOTIFY",
        "parameters": {
          "channels": ["email", "slack"],
          "priority": "high"
        }
      }
    ],
    "enabled": true
  }
}
```

### Ingest Security Events

```graphql
mutation IngestEvents($input: EventsBatchInput!) {
  ingestEvents(input: $input) {
    successCount
    failureCount
    errors {
      eventId
      message
    }
  }
}

# Variables
{
  "input": {
    "source": "ngfw",
    "events": [
      {
        "id": "evt-123",
        "timestamp": "2024-12-09T10:00:00Z",
        "severity": "high",
        "message": "Suspicious outbound connection detected",
        "metadata": {
          "sourceIp": "192.168.1.100",
          "destinationIp": "203.0.113.1",
          "protocol": "TCP"
        }
      }
    ]
  }
}
```

## NGFW Mutations

### Update Firewall Policy

```graphql
mutation UpdateFirewallPolicy($input: PolicyUpdateInput!) {
  updateFirewallPolicy(input: $input) {
    id
    version
    rules {
      id
      priority
      action
      conditions
    }
    deploymentStatus
  }
}

# Variables
{
  "input": {
    "policyId": "pol-789",
    "rules": [
      {
        "priority": 1,
        "action": "BLOCK",
        "conditions": {
          "sourceIp": "192.168.0.0/16",
          "destinationPort": 3389,
          "protocol": "TCP"
        }
      }
    ],
    "comment": "Block RDP access"
  }
}
```

### Deploy ML Model

```graphql
mutation DeployModel($input: ModelDeploymentInput!) {
  deployModel(input: $input) {
    id
    status
    version
    deploymentConfig {
      resources
      scaling
    }
  }
}

# Variables
{
  "input": {
    "modelId": "model-456",
    "target": "NGFW",
    "configuration": {
      "minReplicas": 2,
      "maxReplicas": 5,
      "resources": {
        "cpu": "2",
        "memory": "4Gi"
      }
    }
  }
}
```

## Phishing Protection Mutations

### Create URL Block Rule

```graphql
mutation CreateURLBlockRule($input: URLRuleInput!) {
  createURLBlockRule(input: $input) {
    id
    pattern
    category
    action
    createdAt
  }
}

# Variables
{
  "input": {
    "pattern": "*.suspicious-domain.com/*",
    "category": "PHISHING",
    "action": "BLOCK",
    "description": "Known phishing campaign"
  }
}
```

### Submit Email Analysis

```graphql
mutation AnalyzeEmail($input: EmailAnalysisInput!) {
  analyzeEmail(input: $input) {
    id
    status
    threatScore
    indicators {
      type
      value
      confidence
    }
    recommendations {
      action
      reason
    }
  }
}

# Variables
{
  "input": {
    "messageId": "msg-123",
    "headers": {
      "from": "sender@example.com",
      "subject": "Urgent: Account Verification Required"
    },
    "body": {
      "text": "Please verify your account...",
      "html": "<html>Please verify...</html>"
    },
    "attachments": [
      {
        "filename": "document.pdf",
        "content": "base64_encoded_content",
        "mimeType": "application/pdf"
      }
    ]
  }
}
```

## Error Handling Examples

### Error Response Format

```graphql
{
  "errors": [
    {
      "message": "Failed to create alert rule",
      "extensions": {
        "code": "VALIDATION_ERROR",
        "field": "conditions",
        "details": "Invalid operator for field type"
      }
    }
  ]
}
```

## Batch Operations

### Batch Update Events

```graphql
mutation BatchUpdateEvents($input: BatchEventUpdateInput!) {
  batchUpdateEvents(input: $input) {
    successCount
    failureCount
    results {
      eventId
      status
      error
    }
  }
}

# Variables
{
  "input": {
    "updates": [
      {
        "eventId": "evt-123",
        "status": "RESOLVED",
        "resolution": "FALSE_POSITIVE"
      },
      {
        "eventId": "evt-124",
        "status": "IN_PROGRESS",
        "assignee": "analyst@example.com"
      }
    ]
  }
}
```

## Best Practices

1. Always include error handling in your mutations
2. Use meaningful operation names
3. Group related mutations in a single request when possible
4. Include necessary authentication headers:

   ```plaintext
   {
     "Authorization": "Bearer <token>",
     "X-Request-ID": "<uuid>"
   }
   ```

## Rate Limiting

- Mutations are subject to rate limits based on the token type
- Default: 1000 mutations per minute
- Batch operations count as multiple operations based on the batch size
