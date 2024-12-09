# GraphQL Query Examples

## Overview

This document provides examples of GraphQL queries for the Neurodefender API. Each example includes the query structure, variables, and sample responses.

## Authentication Queries

### Get Current Token Info

```graphql
query GetTokenInfo {
  tokenInfo {
    isValid
    expiresAt
    permissions
    metadata {
      createdAt
      lastUsed
      createdBy
    }
  }
}

# Response
{
  "data": {
    "tokenInfo": {
      "isValid": true,
      "expiresAt": "2024-12-10T00:00:00Z",
      "permissions": ["READ_EVENTS", "WRITE_EVENTS"],
      "metadata": {
        "createdAt": "2024-12-09T00:00:00Z",
        "lastUsed": "2024-12-09T10:30:00Z",
        "createdBy": "admin@example.com"
      }
    }
  }
}
```

## SIEM Queries

### Search Security Events

```graphql
query SearchEvents($input: EventSearchInput!) {
  searchEvents(input: $input) {
    totalCount
    pageInfo {
      hasNextPage
      endCursor
    }
    events {
      id
      timestamp
      severity
      source {
        type
        identifier
      }
      message
      metadata
    }
  }
}

# Variables
{
  "input": {
    "timeRange": {
      "start": "2024-12-09T00:00:00Z",
      "end": "2024-12-09T23:59:59Z"
    },
    "filters": {
      "severity": ["high", "critical"],
      "sourceType": ["firewall", "ids"]
    },
    "pagination": {
      "first": 100,
      "after": "cursor_value"
    }
  }
}
```

### Get Alert Rules

```graphql
query GetAlertRules($input: AlertRuleFilterInput!) {
  alertRules(input: $input) {
    rules {
      id
      name
      enabled
      conditions {
        field
        operator
        value
      }
      actions {
        type
        parameters
      }
      statistics {
        triggeredCount
        lastTriggered
      }
    }
    totalCount
  }
}

# Variables
{
  "input": {
    "status": "ENABLED",
    "category": "NETWORK_SECURITY",
    "limit": 50,
    "offset": 0
  }
}
```

## NGFW Queries

### Get Firewall Policies

```graphql
query GetFirewallPolicies($input: PolicyQueryInput!) {
  firewallPolicies(input: $input) {
    policies {
      id
      name
      version
      rules {
        id
        priority
        action
        conditions
        statistics {
          matchCount
          lastMatched
        }
      }
      metadata {
        createdAt
        modifiedAt
        author
      }
    }
  }
}

# Variables
{
  "input": {
    "status": "ACTIVE",
    "type": "SECURITY",
    "includeStatistics": true
  }
}
```

### Get ML Model Status

```graphql
query GetModelStatus($modelId: ID!) {
  mlModel(id: $modelId) {
    id
    status
    version
    metrics {
      accuracy
      falsePositiveRate
      latency
    }
    deployments {
      environment
      status
      health
      resources {
        cpu
        memory
        gpu
      }
    }
  }
}

# Variables
{
  "modelId": "model-456"
}
```

## Phishing Protection Queries

### Get URL Analysis Results

```graphql
query GetURLAnalysis($input: URLQueryInput!) {
  urlAnalysis(input: $input) {
    results {
      url
      category
      threatScore
      analysis {
        timestamp
        verdict
        confidence
        indicators {
          type
          value
          severity
        }
      }
      history {
        firstSeen
        lastSeen
        verdictChanges
      }
    }
  }
}

# Variables
{
  "input": {
    "url": "https://suspicious-domain.com/login",
    "includeHistory": true
  }
}
```

### Get Email Analysis Status

```graphql
query GetEmailAnalysisStatus($input: EmailQueryInput!) {
  emailAnalysis(input: $input) {
    messageId
    status
    scanResults {
      timestamp
      threatScore
      categories {
        type
        confidence
        indicators
      }
      attachments {
        filename
        verdict
        threatTypes
      }
      urls {
        url
        category
        blockStatus
      }
    }
  }
}

# Variables
{
  "input": {
    "messageId": "msg-123",
    "includeAttachments": true
  }
}
```

## System Status Queries

### Get Component Health Status

```graphql
query GetSystemHealth {
  systemHealth {
    components {
      name
      status
      version
      metrics {
        uptime
        latency
        errorRate
      }
      dependencies {
        name
        status
        latency
      }
    }
    alerts {
      severity
      message
      timestamp
      component
    }
  }
}
```

### Get Performance Metrics

```graphql
query GetPerformanceMetrics($input: MetricsQueryInput!) {
  performanceMetrics(input: $input) {
    timeRange {
      start
      end
    }
    metrics {
      name
      values {
        timestamp
        value
      }
      statistics {
        min
        max
        average
        p95
        p99
      }
    }
  }
}

# Variables
{
  "input": {
    "metrics": ["cpu_usage", "memory_usage", "request_latency"],
    "timeRange": {
      "start": "2024-12-09T00:00:00Z",
      "end": "2024-12-09T23:59:59Z"
    },
    "interval": "5m"
  }
}
```

## Query Best Practices

1. Field Selection
   - Only request needed fields
   - Use fragments for repeated field sets
   - Consider query complexity limits

2. Pagination

   ```graphql
   # Use cursor-based pagination for large datasets
   {
     first: 100,
     after: "cursor_value"
   }
   ```

3. Error Handling

   ```graphql
   # Include error handling in queries
   {
     data {
       result
     }
     errors {
       message
       path
       extensions
     }
   }
   ```

4. Performance Tips
   - Use appropriate page sizes
   - Implement caching where possible
   - Consider query complexity
   - Use aliases for clarity

## Common Query Parameters

### Time Range Format

```graphql
timeRange: {
  start: "ISO8601 DateTime",
  end: "ISO8601 DateTime"
}
```

### Pagination Options

```graphql
pagination: {
  first: Int,
  after: String,   # Cursor-based
  # OR
  limit: Int,
  offset: Int      # Offset-based
}
```

### Filtering Options

```graphql
filters: {
  field: [Value],
  range: {
    field: String,
    gt: Value,
    lt: Value
  }
}
```
