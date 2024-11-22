import logging
import joblib
import numpy as np
from scapy.layers.inet import IP, TCP, UDP

logger = logging.getLogger("firewall")

class AnomalyDetector:
    def __init__(self, model_path):
        """
        Initialize the Anomaly Detector with a pre-trained model.
        Args:
            model_path: Path to the pre-trained anomaly detection model.
        """
        try:
            self.model = joblib.load(model_path)
            logger.info(f"Loaded anomaly detection model from {model_path}")
        except FileNotFoundError:
            logger.error(f"Model file not found: {model_path}")
            self.model = None
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            self.model = None

    def extract_features(self, packet):
        """
        Extract features from a packet for anomaly detection.
        Args:
            packet: The scapy packet to be analyzed.
        Returns:
            A feature vector as a numpy array.
        """
        try:
            features = []
            # Extract common features from packet
            features.append(len(packet))  # Packet length
            features.append(packet[IP].ttl)  # Time to live (TTL)

            if TCP in packet or UDP in packet:
                features.append(packet[IP].proto)  # Protocol (TCP/UDP)
                features.append(packet[IP].src)  # Source IP address (converted to numerical representation)
                features.append(packet[IP].dst)  # Destination IP address (converted to numerical representation)
                if TCP in packet:
                    features.append(packet[TCP].sport)  # Source port
                    features.append(packet[TCP].dport)  # Destination port
                elif UDP in packet:
                    features.append(packet[UDP].sport)  # Source port
                    features.append(packet[UDP].dport)  # Destination port
            else:
                features.extend([0, 0, 0, 0, 0])  # Pad features if no TCP/UDP

            return np.array(features)
        except Exception as e:
            logger.error(f"Error extracting features from packet: {str(e)}")
            return None

    def is_anomalous(self, packet):
        """
        Determine if a packet is anomalous using the trained model.
        Args:
            packet: The scapy packet to be analyzed.
        Returns:
            True if the packet is anomalous, False otherwise.
        """
        if not self.model:
            logger.error("No model loaded for anomaly detection.")
            return False

        features = self.extract_features(packet)
        if features is None:
            return False

        try:
            prediction = self.model.predict([features])[0]
            if prediction == 1:  # Assuming 1 indicates anomaly
                logger.warning(f"Anomalous packet detected: {packet.summary()}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error during anomaly prediction: {str(e)}")
            return False
