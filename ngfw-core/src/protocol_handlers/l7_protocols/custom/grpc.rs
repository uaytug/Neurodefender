use std::sync::Arc;
use tokio::sync::RwLock;
use bytes::Bytes;
use h2::Frame;
use tonic::codec::{Decoder, Encoder};

use crate::packet_processor::packet_analyzer::ProtocolInfo;
use crate::threat_detection::ml_engine::inference::Engine as MLEngine;
use crate::secure_channel::tls::TLSInspector;

/// Represents the state of a gRPC stream
#[derive(Debug)]
pub struct GRPCStream {
    stream_id: u32,
    method_name: String,
    headers: Vec<(String, String)>,
    message_count: u32,
    bytes_transferred: u64,
    start_time: std::time::Instant,
}

/// gRPC protocol handler for inspecting and analyzing gRPC traffic
pub struct GRPCHandler {
    ml_engine: Arc<MLEngine>,
    tls_inspector: Arc<TLSInspector>,
    active_streams: Arc<RwLock<hashmap::HashMap<u32, GRPCStream>>>,
}

impl GRPCHandler {
    pub fn new(ml_engine: Arc<MLEngine>, tls_inspector: Arc<TLSInspector>) -> Self {
        Self {
            ml_engine,
            tls_inspector,
            active_streams: Arc::new(RwLock::new(hashmap::HashMap::new())),
        }
    }

    /// Process incoming gRPC frame
    pub async fn process_frame(&self, frame: Frame<Bytes>) -> Result<ProtocolInfo, Box<dyn std::error::Error>> {
        match frame {
            Frame::Headers(headers) => {
                self.handle_headers(headers).await?;
            }
            Frame::Data(data) => {
                self.handle_data(data).await?;
            }
            Frame::Trailers(trailers) => {
                self.handle_trailers(trailers).await?;
            }
            _ => {}
        }

        Ok(self.generate_protocol_info().await?)
    }

    /// Handle gRPC headers frame
    async fn handle_headers(&self, headers: h2::frame::Headers) -> Result<(), Box<dyn std::error::Error>> {
        let stream_id = headers.stream_id().as_u32();
        let mut headers_map = Vec::new();

        // Extract method name and other important headers
        for header in headers.fields() {
            if header.name() == ":path" {
                headers_map.push(("method".to_string(), header.value().to_str()?.to_string()));
            }
            headers_map.push((
                header.name().to_string(),
                header.value().to_str()?.to_string(),
            ));
        }

        let stream = GRPCStream {
            stream_id,
            method_name: headers_map
                .iter()
                .find(|(k, _)| k == "method")
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            headers: headers_map,
            message_count: 0,
            bytes_transferred: 0,
            start_time: std::time::Instant::now(),
        };

        self.active_streams.write().await.insert(stream_id, stream);
        Ok(())
    }

    /// Handle gRPC data frame
    async fn handle_data(&self, data: h2::frame::Data) -> Result<(), Box<dyn std::error::Error>> {
        let stream_id = data.stream_id().as_u32();
        let payload = data.payload();
        
        // Update stream statistics
        if let Some(stream) = self.active_streams.write().await.get_mut(&stream_id) {
            stream.message_count += 1;
            stream.bytes_transferred += payload.len() as u64;
            
            // Perform threat analysis on the payload
            let features = self.extract_features(stream, payload).await?;
            let threat_score = self.ml_engine.predict(&features).await?;
            
            if threat_score > 0.8 {
                // Log high-risk gRPC activity
                log::warn!(
                    "High-risk gRPC activity detected - Stream: {}, Method: {}, Score: {}",
                    stream_id,
                    stream.method_name,
                    threat_score
                );
            }
        }

        Ok(())
    }

    /// Handle gRPC trailers frame
    async fn handle_trailers(&self, trailers: h2::frame::Headers) -> Result<(), Box<dyn std::error::Error>> {
        let stream_id = trailers.stream_id().as_u32();
        
        // Clean up stream state
        self.active_streams.write().await.remove(&stream_id);
        Ok(())
    }

    /// Extract features for ML analysis
    async fn extract_features(&self, stream: &GRPCStream, payload: &[u8]) -> Result<Vec<f32>, Box<dyn std::error::Error>> {
        let mut features = Vec::new();
        
        // Message size
        features.push(payload.len() as f32);
        
        // Message frequency
        let duration = stream.start_time.elapsed().as_secs_f32();
        features.push(stream.message_count as f32 / duration);
        
        // Bytes per second
        features.push(stream.bytes_transferred as f32 / duration);
        
        // Entropy of payload
        features.push(self.calculate_entropy(payload));
        
        Ok(features)
    }

    /// Calculate Shannon entropy of payload
    fn calculate_entropy(&self, data: &[u8]) -> f32 {
        let mut frequency = [0.0f32; 256];
        let len = data.len() as f32;

        // Calculate frequency of each byte
        for &byte in data {
            frequency[byte as usize] += 1.0;
        }

        // Calculate entropy
        -frequency.iter()
            .filter(|&&freq| freq > 0.0)
            .map(|&freq| {
                let p = freq / len;
                p * p.log2()
            })
            .sum::<f32>()
    }

    /// Generate protocol information for the packet analyzer
    async fn generate_protocol_info(&self) -> Result<ProtocolInfo, Box<dyn std::error::Error>> {
        let streams = self.active_streams.read().await;
        let total_bytes: u64 = streams.values().map(|s| s.bytes_transferred).sum();
        let total_messages: u32 = streams.values().map(|s| s.message_count).sum();

        Ok(ProtocolInfo {
            protocol: "gRPC".to_string(),
            details: Some(serde_json::json!({
                "active_streams": streams.len(),
                "total_messages": total_messages,
                "total_bytes": total_bytes,
            })),
            risk_level: self.calculate_risk_level(&streams).await?,
        })
    }

    /// Calculate overall risk level based on active streams
    async fn calculate_risk_level(&self, streams: &hashmap::HashMap<u32, GRPCStream>) -> Result<f32, Box<dyn std::error::Error>> {
        let mut max_risk = 0.0f32;

        for stream in streams.values() {
            let features = self.extract_features(stream, &[]).await?;
            let risk = self.ml_engine.predict(&features).await?;
            max_risk = max_risk.max(risk);
        }

        Ok(max_risk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_grpc_handler() {
        // Add comprehensive tests here
        // Test header processing
        // Test data frame analysis
        // Test threat detection
        // Test cleanup
    }
}