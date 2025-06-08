#!/usr/bin/env python3
"""
Enhanced ML Engine for Network Intrusion Detection
Supports batch processing and persistent model loading
"""

import json
import sys
import logging
import time
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import torch.nn.functional as F

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MLEngine:
    """Enhanced ML Engine with batch processing support"""
    
    def __init__(self, model_id: str = "rdpahalavan/bert-network-packet-flow-header-payload"):
        """Initialize the ML engine with model and tokenizer"""
        self.model_id = model_id
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"Using device: {self.device}")
        
        # Load configuration
        self.config_path = Path(__file__).parent.parent / "model" / "config.json"
        self.id2label = self._load_config()
        
        # Load model and tokenizer
        logger.info(f"Loading model: {model_id}")
        self.tokenizer = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_id)
        self.model.to(self.device)
        self.model.eval()
        logger.info("Model loaded successfully")
        
        # Performance tracking
        self.total_predictions = 0
        self.total_time = 0.0
    
    def _load_config(self) -> Dict[int, str]:
        """Load label configuration"""
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            # Convert string keys to int
            return {int(k): v for k, v in cfg["id2label"].items()}
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            # Fallback to basic labels
            return {
                0: "normal",
                1: "attack",
                2: "suspicious"
            }
    
    def preprocess_packet(self, packet: Dict) -> str:
        """Convert packet info to text representation for the model"""
        # Extract relevant features
        features = []
        
        # Basic packet info
        features.append(f"src_ip:{packet.get('source_ip', 'unknown')}")
        features.append(f"dst_ip:{packet.get('destination_ip', 'unknown')}")
        features.append(f"protocol:{packet.get('protocol', 'unknown')}")
        features.append(f"size:{packet.get('size', 0)}")
        
        # Port information
        if 'source_port' in packet:
            features.append(f"src_port:{packet['source_port']}")
        if 'destination_port' in packet:
            features.append(f"dst_port:{packet['destination_port']}")
        
        # Flags and additional info
        if 'flags' in packet:
            features.append(f"flags:{packet['flags']}")
        if 'payload_size' in packet:
            features.append(f"payload_size:{packet['payload_size']}")
        
        # Combine features into text
        return " ".join(features)
    
    def predict_batch(self, packets: List[Dict]) -> List[Dict]:
        """Process a batch of packets and return predictions"""
        start_time = time.time()
        results = []
        
        try:
            # Preprocess all packets
            texts = [self.preprocess_packet(packet) for packet in packets]
            
            # Tokenize batch
            inputs = self.tokenizer(
                texts,
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=512
            )
            
            # Move to device
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Run inference
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
            
            # Process predictions
            probs = F.softmax(logits, dim=-1)
            predictions = torch.argmax(probs, dim=-1)
            
            # Convert to results
            for i, (pred_idx, prob_dist) in enumerate(zip(predictions, probs)):
                pred_idx = int(pred_idx.item())
                confidence = float(prob_dist[pred_idx].item())
                label = self.id2label.get(pred_idx, "unknown")
                
                # Determine threat type based on label
                threat_type = self._get_threat_type(label)
                
                results.append({
                    "prediction": label,
                    "confidence": confidence,
                    "threat_type": threat_type,
                    "processing_time_ms": 0  # Will be updated
                })
            
            # Update performance metrics
            processing_time = (time.time() - start_time) * 1000  # ms
            avg_time_per_packet = processing_time / len(packets)
            
            # Update result processing times
            for result in results:
                result["processing_time_ms"] = int(avg_time_per_packet)
            
            self.total_predictions += len(packets)
            self.total_time += processing_time
            
            logger.debug(f"Processed batch of {len(packets)} packets in {processing_time:.2f}ms")
            
        except Exception as e:
            logger.error(f"Error in batch prediction: {e}")
            # Return error results
            results = [{
                "prediction": "error",
                "confidence": 0.0,
                "threat_type": None,
                "processing_time_ms": 0
            } for _ in packets]
        
        return results
    
    def predict_single(self, packet: Dict) -> Dict:
        """Process a single packet (wrapper around batch processing)"""
        results = self.predict_batch([packet])
        return results[0] if results else {
            "prediction": "error",
            "confidence": 0.0,
            "threat_type": None,
            "processing_time_ms": 0
        }
    
    def _get_threat_type(self, label: str) -> Optional[str]:
        """Map prediction label to threat type"""
        label_lower = label.lower()
        
        threat_mapping = {
            "ddos": "denial_of_service",
            "dos": "denial_of_service",
            "port scan": "reconnaissance",
            "reconnaissance": "reconnaissance",
            "backdoor": "malware",
            "bot": "malware",
            "worms": "malware",
            "exploits": "exploitation",
            "shellcode": "exploitation",
            "web attack": "web_attack",
            "sql injection": "web_attack",
            "xss": "web_attack",
            "brute force": "authentication_attack",
            "patator": "authentication_attack",
            "infiltration": "lateral_movement",
            "heartbleed": "vulnerability_exploit",
            "normal": None,
            "analysis": "suspicious_activity",
            "fuzzers": "suspicious_activity",
            "generic": "suspicious_activity"
        }
        
        for key, threat_type in threat_mapping.items():
            if key in label_lower:
                return threat_type
        
        return "unknown_threat" if label_lower != "normal" else None
    
    def get_stats(self) -> Dict:
        """Get engine statistics"""
        avg_time = self.total_time / max(self.total_predictions, 1)
        return {
            "total_predictions": self.total_predictions,
            "total_time_ms": self.total_time,
            "average_time_per_prediction_ms": avg_time
        }


def main():
    """Main entry point for the ML engine service"""
    logger.info("Starting ML Engine service")
    
    # Initialize engine
    engine = MLEngine()
    
    # Process commands from stdin
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            
            # Parse command
            try:
                command = json.loads(line.strip())
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON: {line}")
                continue
            
            # Handle different command types
            cmd_type = command.get("type", "predict")
            
            if cmd_type == "predict_batch":
                # Batch prediction
                packets = command.get("packets", [])
                results = engine.predict_batch(packets)
                response = {
                    "type": "batch_results",
                    "results": results
                }
            
            elif cmd_type == "predict":
                # Single prediction (backward compatibility)
                packet = command.get("packet", {})
                result = engine.predict_single(packet)
                response = {
                    "type": "result",
                    "result": result
                }
            
            elif cmd_type == "stats":
                # Get statistics
                response = {
                    "type": "stats",
                    "stats": engine.get_stats()
                }
            
            elif cmd_type == "ping":
                # Health check
                response = {
                    "type": "pong",
                    "status": "healthy"
                }
            
            else:
                response = {
                    "type": "error",
                    "error": f"Unknown command type: {cmd_type}"
                }
            
            # Send response
            print(json.dumps(response))
            sys.stdout.flush()
            
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            error_response = {
                "type": "error",
                "error": str(e)
            }
            print(json.dumps(error_response))
            sys.stdout.flush()
    
    logger.info("ML Engine service stopped")


# Legacy function for backward compatibility
def predict(text: str) -> Tuple[str, float]:
    """Legacy prediction function"""
    # This would need to use a global engine instance
    # For now, return a placeholder
    return "normal", 0.95


# For direct script execution
def analyze(packet: Dict) -> Dict:
    """Analyze a single packet (legacy interface)"""
    engine = MLEngine()
    return engine.predict_single(packet)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--service":
        # Run as a service
        main()
    else:
        # Legacy mode - read single packet from stdin
        data = sys.stdin.read()
        packet = json.loads(data)
        result = analyze(packet)
        print(json.dumps(result))