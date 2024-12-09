# Neurodefender Data Format Standards

## Overview

This document specifies the standardized data formats used throughout the Neurodefender system. These formats ensure consistency in data exchange between components and provide a unified approach to data storage and processing.

## Event Formats

### 1. Security Event Format

```json
{
    "event_id": "string (UUID)",
    "timestamp": "string (ISO8601)",
    "source": {
        "type": "string (siem|ngfw|ml|phishing)",
        "component": "string",
        "instance_id": "string"
    },
    "severity": "string (low|medium|high|critical)",
    "category": "string",
    "metadata": {
        "customer_id": "string",
        "environment": "string",
        "tags": ["string"]
    },
    "details": {
        // Event-specific details
    }
}
```

### 2. Alert Format

```json
{
    "alert_id": "string (UUID)",
    "creation_time": "string (ISO8601)",
    "update_time": "string (ISO8601)",
    "status": "string (new|investigating|resolved|false_positive)",
    "severity": "string (low|medium|high|critical)",
    "title": "string",
    "description": "string",
    "related_events": ["string (event_id)"],
    "assignee": "string",
    "resolution": {
        "type": "string",
        "description": "string",
        "timestamp": "string (ISO8601)"
    },
    "indicators": [{
        "type": "string (ip|domain|hash|url)",
        "value": "string",
        "confidence": "float"
    }]
}
```

## Threat Intelligence Formats

### 1. Indicator Format

```json
{
    "id": "string (UUID)",
    "type": "string (ip|domain|url|file|email)",
    "value": "string",
    "confidence": "float (0.0-1.0)",
    "severity": "string (low|medium|high|critical)",
    "valid_from": "string (ISO8601)",
    "valid_until": "string (ISO8601)",
    "tags": ["string"],
    "context": {
        "malware_family": "string",
        "attack_type": "string",
        "threat_actor": "string"
    },
    "enrichment": {
        "geolocation": {
            "country": "string",
            "city": "string",
            "coordinates": [float, float]
        },
        "asn": {
            "number": "integer",
            "organization": "string"
        }
    }
}
```

### 2. MITRE ATT&CK Format

```json
{
    "technique_id": "string",
    "tactic": "string",
    "description": "string",
    "detection": {
        "rules": [{
            "type": "string",
            "pattern": "string",
            "platform": "string"
        }]
    },
    "mitigation": [{
        "id": "string",
        "description": "string",
        "effectiveness": "string"
    }]
}
```

## ML Data Formats

### 1. Feature Vector Format

```json
{
    "vector_id": "string (UUID)",
    "timestamp": "string (ISO8601)",
    "feature_set": "string",
    "features": {
        "numeric": {
            "feature_name": "float"
        },
        "categorical": {
            "feature_name": "string"
        },
        "binary": {
            "feature_name": "boolean"
        }
    },
    "metadata": {
        "source": "string",
        "version": "string"
    }
}
```

### 2. Model Prediction Format

```json
{
    "prediction_id": "string (UUID)",
    "model_id": "string",
    "model_version": "string",
    "timestamp": "string (ISO8601)",
    "input_vector_id": "string",
    "prediction": {
        "class": "string",
        "probability": "float",
        "scores": {
            "class_name": "float"
        }
    },
    "explanation": {
        "feature_importance": {
            "feature_name": "float"
        },
        "confidence_score": "float"
    }
}
```

## Network Traffic Formats

### 1. Flow Record Format

```json
{
    "flow_id": "string (UUID)",
    "start_time": "string (ISO8601)",
    "end_time": "string (ISO8601)",
    "source": {
        "ip": "string",
        "port": "integer",
        "asn": "integer"
    },
    "destination": {
        "ip": "string",
        "port": "integer",
        "asn": "integer"
    },
    "protocol": "integer",
    "bytes_sent": "integer",
    "bytes_received": "integer",
    "packets_sent": "integer",
    "packets_received": "integer",
    "application": {
        "protocol": "string",
        "category": "string"
    },
    "flags": {
        "syn": "boolean",
        "ack": "boolean",
        "fin": "boolean",
        "rst": "boolean"
    }
}
```

### 2. Packet Metadata Format

```json
{
    "packet_id": "string (UUID)",
    "timestamp": "string (ISO8601)",
    "flow_id": "string",
    "direction": "string (inbound|outbound)",
    "length": "integer",
    "headers": {
        "ethernet": {},
        "ip": {},
        "transport": {}
    },
    "payload_metadata": {
        "type": "string",
        "length": "integer",
        "entropy": "float"
    }
}
```

## Configuration Formats

### 1. Policy Format

```json
{
    "policy_id": "string (UUID)",
    "name": "string",
    "description": "string",
    "version": "string",
    "enabled": "boolean",
    "priority": "integer",
    "rules": [{
        "rule_id": "string",
        "name": "string",
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
    "metadata": {
        "created_by": "string",
        "created_at": "string (ISO8601)",
        "last_modified": "string (ISO8601)"
    }
}
```

### 2. System Configuration Format

```json
{
    "component": "string",
    "version": "string",
    "settings": {
        "category": {
            "setting_name": {
                "value": "any",
                "type": "string",
                "description": "string",
                "default": "any",
                "validation": {
                    "type": "string",
                    "parameters": {}
                }
            }
        }
    },
    "dependencies": [{
        "component": "string",
        "version": "string",
        "required": "boolean"
    }]
}
```

## Data Validation

### 1. Schema Validation

- All data formats must be validated against JSON Schema definitions
- Schema versioning follows semantic versioning
- Backward compatibility must be maintained for one major version

### 2. Data Quality Requirements

- Timestamps must be in UTC
- String fields must be UTF-8 encoded
- Binary data must be base64 encoded
- Numeric fields must use specified precision
- Enums must use predefined values

## Data Lifecycle

### 1. Retention Policies

- Security events: 1 year
- Alert data: 2 years
- Flow records: 90 days
- Raw packets: 7 days
- ML features: 180 days

### 2. Archival Format

- Parquet for structured data
- Custom binary format for packet data
- Compressed JSON for configuration data

## Future Enhancements

- Protocol Buffers support
- Apache Avro integration
- Binary format optimization
- Custom compression schemes
- Enhanced metadata support
