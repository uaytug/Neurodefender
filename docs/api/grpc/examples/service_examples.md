# gRPC Service Examples

## Overview

This document provides examples of gRPC service implementations for the Neurodefender platform. Examples include server-side code for SIEM, NGFW, and ML Platform services.

## SIEM Service

### Event Ingestion Service (Go)

```go
package siem

import (
    "context"
    "time"
    
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
    pb "neurodefender/proto/siem"
)

type SIEMServer struct {
    eventProcessor EventProcessor
    pb.UnimplementedSIEMServiceServer
}

func NewSIEMServer(processor EventProcessor) *SIEMServer {
    return &SIEMServer{
        eventProcessor: processor,
    }
}

func (s *SIEMServer) IngestEvent(ctx context.Context, event *pb.SecurityEvent) (*pb.IngestResponse, error) {
    // Validate event
    if err := validateEvent(event); err != nil {
        return nil, status.Error(codes.InvalidArgument, err.Error())
    }
    
    // Process event
    eventID, err := s.eventProcessor.ProcessEvent(ctx, event)
    if err != nil {
        return nil, status.Error(codes.Internal, "Failed to process event")
    }
    
    return &pb.IngestResponse{
        EventId: eventID,
        Timestamp: time.Now().UTC().Format(time.RFC3339),
    }, nil
}

func (s *SIEMServer) SubscribeEvents(req *pb.SubscriptionRequest, stream pb.SIEMService_SubscribeEventsServer) error {
    // Create subscription
    sub := s.eventProcessor.Subscribe(req.Filters)
    defer sub.Close()
    
    // Stream events
    for {
        select {
        case event := <-sub.Events():
            if err := stream.Send(event); err != nil {
                return status.Error(codes.Internal, "Failed to send event")
            }
        case <-stream.Context().Done():
            return nil
        }
    }
}
```

### Event Processing Implementation (Go)

```go
type EventProcessor interface {
    ProcessEvent(ctx context.Context, event *pb.SecurityEvent) (string, error)
    Subscribe(filters *pb.EventFilter) EventSubscription
}

type eventProcessor struct {
    store     EventStore
    enricher  EventEnricher
    correlator EventCorrelator
}

func (p *eventProcessor) ProcessEvent(ctx context.Context, event *pb.SecurityEvent) (string, error) {
    // Enrich event
    enriched, err := p.enricher.Enrich(ctx, event)
    if err != nil {
        return "", fmt.Errorf("enrichment failed: %v", err)
    }
    
    // Correlate event
    correlated, err := p.correlator.Correlate(ctx, enriched)
    if err != nil {
        return "", fmt.Errorf("correlation failed: %v", err)
    }
    
    // Store event
    eventID, err := p.store.Store(ctx, correlated)
    if err != nil {
        return "", fmt.Errorf("storage failed: %v", err)
    }
    
    return eventID, nil
}
```

## NGFW Service

### Traffic Analysis Service (Rust)

```rust
use tonic::{Request, Response, Status};
use neurodefender::ngfw::{NgfwService, TrafficAnalysisRequest, TrafficAnalysisResponse};

#[derive(Debug)]
pub struct NGFWServer {
    analyzer: TrafficAnalyzer,
    model_service: MLModelService,
}

#[tonic::async_trait]
impl NgfwService for NGFWServer {
    async fn analyze_traffic(
        &self,
        request: Request<TrafficAnalysisRequest>,
    ) -> Result<Response<TrafficAnalysisResponse>, Status> {
        let traffic = request.into_inner();
        
        // Extract features
        let features = self.analyzer.extract_features(&traffic)
            .map_err(|e| Status::internal(format!("Feature extraction failed: {}", e)))?;
        
        // Perform inference
        let prediction = self.model_service.predict(&features)
            .await
            .map_err(|e| Status::internal(format!("Prediction failed: {}", e)))?;
        
        // Apply policy
        let action = self.analyzer.determine_action(&prediction)
            .map_err(|e| Status::internal(format!("Policy application failed: {}", e)))?;
        
        Ok(Response::new(TrafficAnalysisResponse {
            action: action.to_string(),
            threat_score: prediction.score,
            categories: prediction.categories,
            metadata: prediction.metadata,
        }))
    }
}

impl NGFWServer {
    pub fn new(analyzer: TrafficAnalyzer, model_service: MLModelService) -> Self {
        Self {
            analyzer,
            model_service,
        }
    }
}
```

### Policy Management Service (Rust)

```rust
#[tonic::async_trait]
impl PolicyService for NGFWServer {
    async fn update_policy(
        &self,
        request: Request<UpdatePolicyRequest>,
    ) -> Result<Response<UpdatePolicyResponse>, Status> {
        let policy = request.into_inner();
        
        // Validate policy
        self.validator.validate_policy(&policy)
            .map_err(|e| Status::invalid_argument(format!("Invalid policy: {}", e)))?;
        
        // Update policy
        let version = self.policy_manager.update_policy(policy)
            .await
            .map_err(|e| Status::internal(format!("Policy update failed: {}", e)))?;
        
        // Deploy policy
        self.deployer.deploy_policy(&version)
            .await
            .map_err(|e| Status::internal(format!("Policy deployment failed: {}", e)))?;
        
        Ok(Response::new(UpdatePolicyResponse {
            policy_id: version.id,
            version: version.version,
            status: "DEPLOYED".to_string(),
        }))
    }
}
```

## ML Platform Service

### Model Inference Service (Python)

```python
from concurrent import futures
import grpc
from neurodefender.ml import ml_pb2, ml_pb2_grpc

class MLService(ml_pb2_grpc.MLServiceServicer):
    def __init__(self, model_registry, feature_store):
        self.model_registry = model_registry
        self.feature_store = feature_store

    async def Predict(self, request, context):
        try:
            # Load model
            model = await self.model_registry.get_model(request.model_id)
            if not model:
                await context.abort(grpc.StatusCode.NOT_FOUND, "Model not found")
            
            # Prepare features
            features = await self.feature_store.prepare_features(request.features)
            
            # Perform inference
            prediction = await model.predict(features)
            
            return ml_pb2.PredictionResponse(
                prediction=prediction.label,
                confidence=prediction.confidence,
                features=prediction.feature_importance,
                metadata=prediction.metadata
            )
        except Exception as e:
            await context.abort(grpc.StatusCode.INTERNAL, str(e))

def serve():
    server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=10))
    ml_pb2_grpc.add_MLServiceServicer_to_server(
        MLService(ModelRegistry(), FeatureStore()), server)
    server.add_insecure_port('[::]:50051')
    return server
```

### Model Training Service (Python)

```python
class MLTrainingService(ml_pb2_grpc.MLTrainingServiceServicer):
    def __init__(self, trainer, model_registry):
        self.trainer = trainer
        self.model_registry = model_registry

    async def TrainModel(self, request, context):
        try:
            # Validate training request
            if not self._validate_training_request(request):
                await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid training config")
            
            # Start training
            training_id = await self.trainer.start_training(
                dataset_id=request.dataset_id,
                config=request.training_config
            )
            
            return ml_pb2.TrainingResponse(
                training_id=training_id,
                status="TRAINING",
                start_time=datetime.utcnow().isoformat()
            )
        except Exception as e:
            await context.abort(grpc.StatusCode.INTERNAL, str(e))

    async def GetTrainingStatus(self, request, context):
        try:
            status = await self.trainer.get_status(request.training_id)
            return ml_pb2.TrainingStatusResponse(
                training_id=request.training_id,
                status=status.state,
                metrics=status.metrics,
                completion=status.completion_percentage
            )
        except Exception as e:
            await context.abort(grpc.StatusCode.INTERNAL, str(e))
```

## Common Service Patterns

### Authentication Middleware (Go)

```go
func AuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, 
    handler grpc.UnaryHandler) (interface{}, error) {
    
    // Extract token
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok {
        return nil, status.Error(codes.Unauthenticated, "Missing metadata")
    }
    
    token := md.Get("authorization")
    if len(token) == 0 {
        return nil, status.Error(codes.Unauthenticated, "Missing token")
    }
    
    // Validate token
    claims, err := validateToken(token[0])
    if err != nil {
        return nil, status.Error(codes.Unauthenticated, "Invalid token")
    }
    
    // Add claims to context
    newCtx := context.WithValue(ctx, "claims", claims)
    
    return handler(newCtx, req)
}
```

### Rate Limiting (Go)

```go
type RateLimiter struct {
    limiter *rate.Limiter
}

func (l *RateLimiter) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, 
        handler grpc.UnaryHandler) (interface{}, error) {
        
        if !l.limiter.Allow() {
            return nil, status.Error(codes.ResourceExhausted, "Rate limit exceeded")
        }
        
        return handler(ctx, req)
    }
}
```

### Error Handling (Rust)

```rust
pub trait ErrorHandler {
    fn handle_error(&self, err: Error) -> Status {
        match err {
            Error::NotFound(msg) => Status::not_found(msg),
            Error::InvalidArgument(msg) => Status::invalid_argument(msg),
            Error::Internal(msg) => Status::internal(msg),
            Error::Unauthenticated(msg) => Status::unauthenticated(msg),
            _ => Status::unknown("Unknown error occurred"),
        }
    }
}

impl ErrorHandler for NGFWServer {}
```

### Metrics Collection (Python)

```python
class MetricsInterceptor:
    def __init__(self, metrics_client):
        self.metrics = metrics_client

    async def intercept_service(self, continuation, handler_call_details):
        start_time = time.time()
        try:
            response = await continuation(handler_call_details)
            self.metrics.record_success(
                method=handler_call_details.method,
                duration=time.time() - start_time
            )
            return response
        except Exception as e:
            self.metrics.record_error(
                method=handler_call_details.method,
                error_type=type(e).__name__
            )
            raise
```

### Health Checking (Go)

```go
type HealthServer struct {
    pb.UnimplementedHealthServer
    services map[string]HealthChecker
}

func (s *HealthServer) Check(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
    service := req.Service
    
    if checker, ok := s.services[service]; ok {
        status, err := checker.Check(ctx)
        if err != nil {
            return &pb.HealthCheckResponse{
                Status: pb.HealthCheckResponse_NOT_SERVING,
            }, nil
        }
        return &pb.HealthCheckResponse{
            Status: status,
        }, nil
    }
    
    return nil, status.Error(codes.NotFound, "Service not found")
}
```

## Deployment Configuration

### Server Configuration (Go)

```go
func NewServer(opts ...ServerOption) (*grpc.Server, error) {
    // Create server with options
    server := grpc.NewServer(
        grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
            AuthInterceptor,
            RateLimitInterceptor,
            MetricsInterceptor,
        )),
        grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
            StreamAuthInterceptor,
            StreamRateLimitInterceptor,
            StreamMetricsInterceptor,
        )),
    )
    
    // Register services
    pb.RegisterSIEMServiceServer(server, NewSIEMServer())
    pb.RegisterHealthServer(server, NewHealthServer())
    
    return server, nil
}
```
