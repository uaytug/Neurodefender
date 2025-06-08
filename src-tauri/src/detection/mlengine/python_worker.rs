use std::process::{Command, Stdio, Child};
use std::io::{BufReader, BufWriter, Write, BufRead};
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use log::{debug, error, info};
use crate::capture::packet::PacketInfo;
use super::MlResult;

/// Command to send to Python process
#[derive(Serialize)]
#[serde(tag = "type")]
enum PythonCommand {
    #[serde(rename = "predict_batch")]
    PredictBatch { packets: Vec<PacketInfo> },
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "stats")]
    Stats,
}

/// Response from Python process
#[derive(Deserialize)]
#[serde(tag = "type")]
enum PythonResponse {
    #[serde(rename = "batch_results")]
    BatchResults { results: Vec<MlResult> },
    #[serde(rename = "pong")]
    Pong { status: String },
    #[serde(rename = "stats")]
    Stats { stats: serde_json::Value },
    #[serde(rename = "error")]
    Error { error: String },
}

/// Python worker process manager
pub struct PythonWorker {
    process: Arc<Mutex<Child>>,
    stdin: Arc<Mutex<BufWriter<std::process::ChildStdin>>>,
    stdout: Arc<Mutex<BufReader<std::process::ChildStdout>>>,
    worker_id: usize,
}

impl PythonWorker {
    /// Create a new Python worker
    pub fn new(worker_id: usize, model_path: &str) -> Result<Self, String> {
        info!("Starting Python worker {} with model: {}", worker_id, model_path);
        
        // Get the path to py_engine.py
        let py_engine_path = std::env::current_dir()
            .map_err(|e| format!("Failed to get current directory: {}", e))?
            .join("py_engine.py");
        
        // Start Python process
        let mut child = Command::new("python3")
            .arg(&py_engine_path)
            .arg("--service")
            .env("PYTHONUNBUFFERED", "1")
            .env("MODEL_ID", model_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn Python process: {}", e))?;
        
        // Get stdin/stdout handles
        let stdin = child.stdin.take()
            .ok_or_else(|| "Failed to get stdin handle".to_string())?;
        let stdout = child.stdout.take()
            .ok_or_else(|| "Failed to get stdout handle".to_string())?;
        
        let stdin_writer = BufWriter::new(stdin);
        let stdout_reader = BufReader::new(stdout);
        
        let worker = Self {
            process: Arc::new(Mutex::new(child)),
            stdin: Arc::new(Mutex::new(stdin_writer)),
            stdout: Arc::new(Mutex::new(stdout_reader)),
            worker_id,
        };
        
        // Test the connection
        worker.ping()?;
        
        info!("Python worker {} initialized successfully", worker_id);
        Ok(worker)
    }
    
    /// Send a ping to check if the worker is healthy
    fn ping(&self) -> Result<(), String> {
        let command = PythonCommand::Ping;
        let response = self.send_command(command)?;
        
        match response {
            PythonResponse::Pong { status } => {
                if status == "healthy" {
                    Ok(())
                } else {
                    Err(format!("Worker unhealthy: {}", status))
                }
            }
            _ => Err("Unexpected response to ping".to_string()),
        }
    }
    
    /// Process a batch of packets
    pub async fn process_batch(&self, packets: Vec<PacketInfo>) -> Result<Vec<Option<MlResult>>, String> {
        debug!("Worker {} processing batch of {} packets", self.worker_id, packets.len());
        
        let command = PythonCommand::PredictBatch { packets };
        let response = self.send_command(command)?;
        
        match response {
            PythonResponse::BatchResults { results } => {
                Ok(results.into_iter().map(Some).collect())
            }
            PythonResponse::Error { error } => {
                error!("Python worker {} error: {}", self.worker_id, error);
                Err(format!("Python error: {}", error))
            }
            _ => Err("Unexpected response type".to_string()),
        }
    }
    
    /// Send a command to the Python process and get response
    fn send_command(&self, command: PythonCommand) -> Result<PythonResponse, String> {
        // Serialize command
        let command_json = serde_json::to_string(&command)
            .map_err(|e| format!("Failed to serialize command: {}", e))?;
        
        // Send command
        {
            let mut stdin = self.stdin.lock().unwrap();
            writeln!(stdin, "{}", command_json)
                .map_err(|e| format!("Failed to write to Python process: {}", e))?;
            stdin.flush()
                .map_err(|e| format!("Failed to flush stdin: {}", e))?;
        }
        
        // Read response
        let response_line = {
            let mut stdout = self.stdout.lock().unwrap();
            let mut line = String::new();
            stdout.read_line(&mut line)
                .map_err(|e| format!("Failed to read from Python process: {}", e))?;
            line
        };
        
        // Parse response
        serde_json::from_str(&response_line)
            .map_err(|e| format!("Failed to parse Python response: {} (response: {})", e, response_line))
    }
    
    /// Check if the worker process is still running
    pub fn is_alive(&self) -> bool {
        if let Ok(mut process) = self.process.lock() {
            match process.try_wait() {
                Ok(None) => true,  // Still running
                Ok(Some(status)) => {
                    error!("Python worker {} exited with status: {}", self.worker_id, status);
                    false
                }
                Err(e) => {
                    error!("Failed to check Python worker {} status: {}", self.worker_id, e);
                    false
                }
            }
        } else {
            false
        }
    }
}

impl Drop for PythonWorker {
    fn drop(&mut self) {
        info!("Shutting down Python worker {}", self.worker_id);
        
        // Try to kill the process gracefully
        if let Ok(mut process) = self.process.lock() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
} 