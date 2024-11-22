import logging
from scapy.layers.inet import TCP

logger = logging.getLogger("firewall")

class ConnectionTracker:
    def __init__(self):
        """
        Initialize the Connection Tracker to keep track of active connections.
        """
        self.connections = {}

    def track_packet(self, packet):
        """
        Track a packet to maintain the state of connections.
        Args:
            packet: The scapy packet to be tracked.
        """
        try:
            if TCP in packet:
                connection_id = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
                reverse_connection_id = (packet[IP].dst, packet[IP].src, packet[TCP].dport, packet[TCP].sport)

                # Handle TCP flags to track connection state
                flags = packet[TCP].flags

                if flags == "S":  # SYN - Start of a new connection
                    self.connections[connection_id] = "SYN_SENT"
                    logger.info(f"Tracking new connection: {connection_id}")
                elif flags == "SA":  # SYN-ACK - Acknowledging connection
                    if reverse_connection_id in self.connections and self.connections[reverse_connection_id] == "SYN_SENT":
                        self.connections[reverse_connection_id] = "SYN_ACK_RECEIVED"
                        logger.info(f"Connection acknowledged: {reverse_connection_id}")
                elif flags == "A":  # ACK - Connection established
                    if connection_id in self.connections and self.connections[connection_id] in ["SYN_SENT", "SYN_ACK_RECEIVED"]:
                        self.connections[connection_id] = "ESTABLISHED"
                        logger.info(f"Connection established: {connection_id}")
                elif flags == "F":  # FIN - Connection termination
                    if connection_id in self.connections:
                        del self.connections[connection_id]
                        logger.info(f"Connection terminated: {connection_id}")
                elif flags == "R":  # RST - Connection reset
                    if connection_id in self.connections:
                        del self.connections[connection_id]
                        logger.info(f"Connection reset: {connection_id}")
        except Exception as e:
            logger.error(f"Error tracking packet: {str(e)}")
