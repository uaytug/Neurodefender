import logging
from scapy.layers.inet import IP, TCP, UDP
from src.threat_intelligence import ThreatIntelligence
from src.anomaly_detector import AnomalyDetector

logger = logging.getLogger("firewall")

class PacketInspector:
    def __init__(self, threat_intel, anomaly_detector):
        """
        Initialize the Packet Inspector with threat intelligence and anomaly detector.
        Args:
            threat_intel: Instance of the ThreatIntelligence class.
            anomaly_detector: Instance of the AnomalyDetector class.
        """
        self.threat_intel = threat_intel
        self.anomaly_detector = anomaly_detector

    def inspect_packet(self, packet):
        """
        Inspect a packet for threats and anomalies.
        Args:
            packet: The scapy packet to be inspected.
        Returns:
            A dictionary containing inspection results.
        """
        try:
            inspection_results = {
                "is_threat": False,
                "is_anomalous": False,
                "action": "allow"
            }

            # Check if the packet source or destination IP is a known threat
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if self.threat_intel.is_threat(src_ip) or self.threat_intel.is_threat(dst_ip):
                    inspection_results["is_threat"] = True
                    inspection_results["action"] = "drop"
                    logger.warning(f"Packet identified as a threat: {packet.summary()}")

            # Check for anomalies using the anomaly detector
            if self.anomaly_detector.is_anomalous(packet):
                inspection_results["is_anomalous"] = True
                inspection_results["action"] = "drop"
                logger.warning(f"Anomalous packet detected: {packet.summary()}")

            return inspection_results
        except Exception as e:
            logger.error(f"Error inspecting packet: {str(e)}")
            return {"is_threat": False, "is_anomalous": False, "action": "drop"}

if __name__ == "__main__":
    # Example usage
    feed_urls = [
        "https://example.com/threat-feed-1.txt",
        "https://example.com/threat-feed-2.txt"
    ]
    threat_intel = ThreatIntelligence(feed_urls)
    threat_intel.update_threat_data()

    anomaly_detector = AnomalyDetector("ai_model/model.pkl")

    packet_inspector = PacketInspector(threat_intel, anomaly_detector)
    # Example packet (would need a real packet for actual use)
    dummy_packet = IP(src="192.168.1.2", dst="192.168.1.3") / TCP(sport=12345, dport=80)
    results = packet_inspector.inspect_packet(dummy_packet)
    print(f"Inspection results: {results}")
