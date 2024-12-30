use std::sync::Arc;
use tokio::sync::RwLock;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use tungstenite::protocol::{Frame, CloseFrame, OpCode};

use crate::packet_processor::packet_analyzer::ProtocolInfo;
use crate::threat_detection::ml_engine::inference::Engine as MLEngine;
use crate::secure_channel::tls::TLSInspector;

/// WebSocket frame metadata for analysis
#[derive(Debug, Clone)]
struct FrameMetadata {
    opcode: OpCode,
    payload_len: usize,
    is_masked: bool,
    timestamp: std::time::Instant,
}

/// Represents an active WebSocket connection
#[derive(Debug)]
pub struct WebSocketConnection {
    connection_id: String,
    uri: String,
    headers: Vec<(String, String)>,
    frame_history: Vec<FrameMetadata>,
    total_bytes: u64,
    start_time: std::time::Instant,
    last_activity: std::time::Instant,
}

impl WebSocketConnection {
    fn new(connection_id: String, uri: String, headers: Vec<(String, String)>) -> Self {
        let now = std::time::Instant::now();
        Self {
            connection_id,
            uri,
            headers,
            frame_history: Vec::new(),
            total_bytes: 0,
            start_time: now,
            last_activity: now,
        }
    }

    fn update_activity(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    fn add_frame(&mut self, frame: &Frame) {
        let metadata = FrameMetadata {
            opcode: frame.opcode(),
            payload_len: frame.payload().len(),
            is_masked: frame.is_masked(),
            timestamp: std::time::Instant::now(),
        };
        self.frame_history.push(metadata);
        self.total_bytes += frame.payload().len() as u64;
    }
}

/// WebSocket protocol handler for inspecting and analyzing WebSocket traffic
pub struct WebSocketHandler {
    ml_engine: Arc<MLEngine>,
    tls_inspector: Arc<TLSInspector>,
    active_connections: Arc<RwLock<hashmap::HashMap<String, WebSocketConnection>>>,
}

impl WebSocketHandler {
    pub fn new(ml_engine: Arc<MLEngine>, tls_inspector: Arc<TLSInspector>) -> Self {
        Self {
            ml_engine,
            tls_inspector,
            active_connections: Arc::new(RwLock::new(hashmap::HashMap::new())),
        }
    }

    /// Process WebSocket handshake
    pub async fn handle_handshake(
        &self,
        connection_id: String,
        uri: String,
        headers: Vec<(String, String)>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = WebSocketConnection::new(connection_id.clone(), uri, headers);
        self.active_connections.write().await.insert(connection_id, connection);
        Ok(())
    }

    /// Process WebSocket frame
    pub async fn process_frame(
        &self,
        connection_id: &str,
        frame: Frame,
    ) -> Result<ProtocolInfo, Box<dyn std::error::Error>> {
        let mut connections = self.active_connections.write().await;
        
        if let Some(connection) = connections.get_mut(connection_id) {
            connection.update_activity();
            connection.add_frame(&frame);

            // Analyze frame based on opcode
            match frame.opcode() {
                OpCode::Text | OpCode::Binary => {
                    self.analyze_data_frame(connection, &frame).await?;
                }
                OpCode::Close => {
                    if let Some(close_frame) = frame.into_close() {
                        self.handle_close_frame(connection, close_frame).await?;
                    }
                    connections.remove(connection_id);
                }
                OpCode::Ping | OpCode::Pong => {
                    self.analyze_control_frame(connection, &frame).await?;
                }
                _ => {}
            }
        }

        self.generate_protocol_info(connection_id).await
    }

    /// Analyze data frames (Text/Binary)
    async fn analyze_data_frame(
        &self,
        connection: &WebSocketConnection,
        frame: &Frame,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let features = self.extract_features(connection, frame).await?;
        let threat_score = self.ml_engine.predict(&features).await?;

        if threat_score > 0.8 {
            log::warn!(
                "High-risk WebSocket activity detected - Connection: {}, URI: {}, Score: {}",
                connection.connection_id,
                connection.uri,
                threat_score
            );
        }

        Ok(())
    }

    /// Handle close frames
    async fn handle_close_frame(
        &self,
        connection: &WebSocketConnection,
        close_frame: CloseFrame,
    ) -> Result<(), Box<dyn std::error::Error>> {
        log::info!(
            "WebSocket connection closing - ID: {}, Code: {}, Reason: {}",
            connection.connection_id,
            close_frame.code,
            close_frame.reason
        );
        Ok(())
    }

    /// Analyze control frames (Ping/Pong)
    async fn analyze_control_frame(
        &self,
        connection: &WebSocketConnection,
        frame: &Frame,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Monitor ping/pong patterns for potential anomalies
        let frame_history = &connection.frame_history;
        let control_frame_ratio = frame_history
            .iter()
            .filter(|f| matches!(f.opcode, OpCode::Ping | OpCode::Pong))
            .count() as f32
            / frame_history.len() as f32;

        if control_frame_ratio > 0.5 {
            log::warn!(
                "Unusual control frame pattern detected - Connection: {}",
                connection.connection_id
            );
        }

        Ok(())
    }

    /// Extract features for ML analysis
    async fn extract_features(
        &self,
        connection: &WebSocketConnection,
        frame: &Frame,
    ) -> Result<Vec<f32>, Box<dyn std::error::Error>> {
        let mut features = Vec::new();

        // Frame size
        features.push(frame.payload().len() as f32);

        // Message frequency
        let duration = connection.start_time.elapsed().as_secs_f32();
        features.push(connection.frame_history.len() as f32 / duration);

        // Bytes per second
        features.push(connection.total_bytes as f32 / duration);

        // Control frame ratio
        let control_frames = connection.frame_history
            .iter()
            .filter(|f| matches!(f.opcode, OpCode::Ping | OpCode::Pong))
            .count();
        features.push(control_frames as f32 / connection.frame_history.len() as f32);

        // Payload entropy
        features.push(self.calculate_entropy(frame.payload()));

        Ok(features)
    }

    /// Calculate Shannon entropy of payload
    fn calculate_entropy(&self, data: &[u8]) -> f32 {
        let mut frequency = [0.0f32; 256];
        let len = data.len() as f32;

        for &byte in data {
            frequency[byte as usize] += 1.0;
        }

        -frequency.iter()
            .filter(|&&freq| freq > 0.0)
            .map(|&freq| {
                let p = freq / len;
                p * p.log2()
            })
            .sum::<f32>()
    }

    /// Generate protocol information
    async fn generate_protocol_info(
        &self,
        connection_id: &str,
    ) -> Result<ProtocolInfo, Box<dyn std::error::Error>> {
        let connections = self.active_connections.read().await;
        let connection = connections.get(connection_id);

        Ok(ProtocolInfo {
            protocol: "WebSocket".to_string(),
            details: connection.map(|conn| {
                serde_json::json!({
                    "uri": conn.uri,
                    "total_frames": conn.frame_history.len(),
                    "total_bytes": conn.total_bytes,
                    "duration": conn.start_time.elapsed().as_secs(),
                })
            }),
            risk_level: connection
                .map(|conn| self.calculate_risk_level(conn))
                .transpose()
                .await?
                .unwrap_or(0.0),
        })
    }

    /// Calculate risk level based on connection patterns
    async fn calculate_risk_level(&self, connection: &WebSocketConnection) -> Result<f32, Box<dyn std::error::Error>> {
        let mut risk_factors = Vec::new();

        // Analyze frame patterns
        let frame_rate = connection.frame_history.len() as f32 / connection.start_time.elapsed().as_secs_f32();
        risk_factors.push(if frame_rate > 1000.0 { 0.8 } else { 0.0 });

        // Check for large frames
        let large_frames = connection.frame_history
            .iter()
            .filter(|f| f.payload_len > 100_000)
            .count();
        risk_factors.push(if large_frames > 10 { 0.6 } else { 0.0 });

        // Evaluate connection duration
        let duration = connection.start_time.elapsed().as_secs();
        risk_factors.push(if duration > 3600 { 0.4 } else { 0.0 });

        // Return maximum risk factor
        Ok(risk_factors.into_iter().fold(0.0f32, f32::max))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_websocket_handler() {
        // Add tests for:
        // - Connection management
        // - Frame processing
        // - Threat detection
        // - Risk level calculation
    }
}