# gRPC Client Examples

## Overview

This document provides practical examples of gRPC client implementations for the Neurodefender services. Examples are provided in multiple languages with complete code samples and explanations.

## Prerequisites

```bash
# Python dependencies
pip install grpcio grpcio-tools

# Go dependencies
go get google.golang.org/grpc

# Rust dependencies
cargo add tonic tonic-build
```

## SIEM Service

### Event Ingestion (Python)

```python
import grpc
from neurodefender.siem import siem_pb2
from neurodefender.siem import siem_pb2_grpc

def ingest_events():
    # Create a secure channel
    creds = grpc.ssl_channel_credentials()
    channel = grpc.secure_channel('siem.neurodefender.com:443', creds)
    
    # Create a stub (client)
    stub = siem_pb2_grpc.SIEMServiceStub(channel)
    
    # Create event
    event = siem_pb2.SecurityEvent(
        source="firewall",
        severity="HIGH",
        timestamp="2024-12-09T10:00:00Z",
        message="Suspicious outbound connection detected",
        metadata={
            "source_ip": "192.168.1.100",
            "destination_ip": "203.0.113.1",
            "protocol": "TCP"
        }
    )
    
    try:
        # Send event
        response = stub.IngestEvent(event)
        print(f"Event ingested successfully: {response.event_id}")
    except grpc.RpcError as e:
        print(f"Error ingesting event: {e.details()}")

```

### Event Stream Subscription (Go)

```go
package main

import (
    "context"
    "log"
    "time"
    
    "google.golang.org/grpc"
    pb "neurodefender/siem"
)

func subscribeToEvents() {
    // Create connection
    conn, err := grpc.Dial("siem.neurodefender.com:443", grpc.WithTransportCredentials(
        credentials.NewClientTLSFromCert(nil, "")))
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()
    
    client := pb.NewSIEMServiceClient(conn)
    
    // Create subscription request
    req := &pb.SubscriptionRequest{
        Filters: &pb.EventFilter{
            Severity: []string{"HIGH", "CRITICAL"},
            SourceTypes: []string{"firewall", "ids"},
        },
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 1*time.Hour)
    defer cancel()
    
    // Subscribe to event stream
    stream, err := client.SubscribeEvents(ctx, req)
    if err != nil {
        log.Fatalf("Failed to subscribe: %v", err)
    }
    
    // Process events
    for {
        event, err := stream.Recv()
        if err != nil {
            log.Printf("Stream error: %v", err)
            break
        }
        
        log.Printf("Received event: %v", event)
    }
}
```

## NGFW Service

### Traffic Analysis (Rust)

```rust
use tonic::{transport::Channel, Request};
use neurodefender::ngfw::{NgfwClient, TrafficAnalysisRequest};

async fn analyze_traffic() -> Result<(), Box<dyn std::error::Error>> {
    // Create client
    let channel = Channel::from_static("http://ngfw.neurodefender.com:443")
        .connect()
        .await?;
    
    let mut client = NgfwClient::new(channel);
    
    // Create analysis request
    let request = Request::new(TrafficAnalysisRequest {
        session_id: "sess-123".to_string(),
        protocol: "TCP".to_string(),
        source: Some(Endpoint {
            ip: "192.168.1.100".to_string(),
            port: 12345,
        }),
        destination: Some(Endpoint {
            ip: "203.0.113.1".to_string(),
            port: 443,
        }),
        payload: vec![/* packet data */],
    });
    
    // Send request
    let response = client.analyze_traffic(request).await?;
    println!("Analysis result: {:?}", response.get_ref());
    
    Ok(())
}
```

### Policy Management (Python)

```python
import grpc
from neurodefender.ngfw import ngfw_pb2
from neurodefender.ngfw import ngfw_pb2_grpc

async def update_policy():
    channel = grpc.aio.secure_channel(
        'ngfw.neurodefender.com:443',
        grpc.ssl_channel_credentials()
    )
    
    stub = ngfw_pb2_grpc.NGFWServiceStub(channel)
    
    # Create policy update
    policy = ngfw_pb2.FirewallPolicy(
        name="Block RDP Access",
        rules=[
            ngfw_pb2.FirewallRule(
                priority=1,
                action="BLOCK",
                conditions={
                    "source_cidr": "192.168.0.0/16",
                    "destination_port": 3389,
                    "protocol": "TCP"
                }
            )
        ]
    )
    
    try:
        response = await stub.UpdatePolicy(policy)
        print(f"Policy updated successfully: {response.policy_id}")
    except grpc.RpcError as e:
        print(f"Error updating policy: {e.details()}")
```

## ML Platform Service

### Model Inference (Go)

```go
package main

import (
    "context"
    "log"
    
    "google.golang.org/grpc"
    pb "neurodefender/ml"
)

func performInference() {
    conn, err := grpc.Dial("ml.neurodefender.com:443", grpc.WithTransportCredentials(
        credentials.NewClientTLSFromCert(nil, "")))
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()
    
    client := pb.NewMLServiceClient(conn)
    
    // Create inference request
    req := &pb.InferenceRequest{
        ModelId: "threat-detection-v1",
        Features: []*pb.Feature{
            {
                Name: "packet_size",
                Value: &pb.Feature_NumericValue{NumericValue: 1500},
            },
            {
                Name: "protocol",
                Value: &pb.Feature_CategoryValue{CategoryValue: "TCP"},
            },
        },
    }
    
    // Perform inference
    resp, err := client.Predict(context.Background(), req)
    if err != nil {
        log.Fatalf("Inference failed: %v", err)
    }
    
    log.Printf("Prediction: %v (confidence: %v)", 
        resp.Prediction, resp.Confidence)
}
```

## Best Practices

### Error Handling

```python
def handle_grpc_errors(func):
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                print("Service unavailable, retrying...")
                # Implement retry logic
            elif e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                print("Request timed out")
            elif e.code() == grpc.StatusCode.UNAUTHENTICATED:
                print("Authentication failed")
            else:
                print(f"Unexpected error: {e.details()}")
            raise
    return wrapper
```

### Connection Management

```go
func createSecureConnection(target string) (*grpc.ClientConn, error) {
    // Load TLS credentials
    creds, err := credentials.NewClientTLSFromFile(
        "cert.pem",
        "")
    if err != nil {
        return nil, fmt.Errorf("failed to load credentials: %v", err)
    }
    
    // Create connection with options
    conn, err := grpc.Dial(
        target,
        grpc.WithTransportCredentials(creds),
        grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16*1024*1024)),
        grpc.WithKeepaliveParams(keepalive.ClientParameters{
            Time:                10 * time.Second,
            Timeout:             5 * time.Second,
            PermitWithoutStream: true,
        }),
    )
    
    return conn, err
}
```

### Stream Processing

```rust
use tokio::sync::mpsc;
use tonic::Streaming;

async fn process_event_stream(
    mut stream: Streaming<Event>,
    tx: mpsc::Sender<Event>
) -> Result<(), Box<dyn std::error::Error>> {
    while let Some(event) = stream.message().await? {
        // Process event
        if event.severity == "CRITICAL" {
            // Handle critical events immediately
            handle_critical_event(&event).await?;
        }
        
        // Forward event to processing pipeline
        tx.send(event).await?;
    }
    Ok(())
}
```

## Authentication

### Token-based Authentication

```python
import grpc

def create_authenticated_channel():
    # Create credentials
    token = "your-auth-token"
    credentials = grpc.access_token_call_credentials(token)
    
    # Combine with SSL credentials
    ssl_credentials = grpc.ssl_channel_credentials()
    composite_credentials = grpc.composite_channel_credentials(
        ssl_credentials, credentials)
    
    # Create channel
    return grpc.secure_channel(
        'api.neurodefender.com:443',
        composite_credentials
    )
```

### Certificate-based Authentication

```go
func createMTLSConnection() (*grpc.ClientConn, error) {
    // Load client certificate
    certificate, err := tls.LoadX509KeyPair(
        "client-cert.pem",
        "client-key.pem")
    if err != nil {
        return nil, err
    }
    
    // Create TLS config
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{certificate},
        RootCAs:     certPool,
    }
    
    // Create connection
    creds := credentials.NewTLS(tlsConfig)
    conn, err := grpc.Dial(
        "api.neurodefender.com:443",
        grpc.WithTransportCredentials(creds))
    
    return conn, err
}
```

## Performance Optimization

### Batch Processing

```python
async def batch_ingest_events(events, batch_size=100):
    async for batch in create_batches(events, batch_size):
        request = siem_pb2.BatchIngestRequest(events=batch)
        try:
            response = await stub.BatchIngestEvents(request)
            print(f"Ingested {response.success_count} events")
        except grpc.RpcError as e:
            print(f"Batch ingestion failed: {e.details()}")
```

### Connection Pooling

```go
type ClientPool struct {
    clients chan pb.ServiceClient
    size    int
}

func NewClientPool(size int) (*ClientPool, error) {
    pool := &ClientPool{
        clients: make(chan pb.ServiceClient, size),
        size:    size,
    }
    
    for i := 0; i < size; i++ {
        client, err := createClient()
        if err != nil {
            return nil, err
        }
        pool.clients <- client
    }
    
    return pool, nil
}
```

## Monitoring and Debugging

### Interceptors for Logging

```python
class LoggingInterceptor(grpc.UnaryUnaryClientInterceptor):
    def intercept_unary_unary(self, continuation, client_call_details, request):
        start = time.time()
        response = continuation(client_call_details, request)
        duration = time.time() - start
        
        print(f"gRPC call: {client_call_details.method}")
        print(f"Duration: {duration:.2f}s")
        print(f"Status: {response.code()}")
        
        return response
```

### Metrics Collection

```go
func metricsInterceptor(ctx context.Context, method string, req, reply interface{}, 
    cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
    
    startTime := time.Now()
    err := invoker(ctx, method, req, reply, cc, opts...)
    duration := time.Since(startTime)
    
    // Record metrics
    metrics.RecordLatency(method, duration)
    metrics.IncrementCallCount(method)
    if err != nil {
        metrics.IncrementErrorCount(method)
    }
    
    return err
}
```
