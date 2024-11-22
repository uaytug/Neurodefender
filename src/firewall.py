import scapy.all as scapy
import netfilterqueue
import json
import logging
from src.rules import load_rules, is_packet_allowed
from src.connection_tracker import ConnectionTracker
from src.log_handler import setup_logger

# Setup Logging
setup_logger()
logger = logging.getLogger("firewall")

# Load Firewall Rules
rules = load_rules("config/firewall_rules.json")

# Initialize Connection Tracker for Stateful Inspection
connection_tracker = ConnectionTracker()

def process_packet(packet):
    """
    Process packets captured by the firewall.
    Args:
        packet: The packet captured by NetfilterQueue.
    """
    try:
        # Convert NetfilterQueue packet to scapy packet
        scapy_packet = scapy.IP(packet.get_payload())

        # Stateful inspection - track connections
        connection_tracker.track_packet(scapy_packet)

        # Check if packet matches firewall rules
        if is_packet_allowed(scapy_packet, rules):
            logger.info(f"Packet allowed: {scapy_packet.summary()}")
            packet.accept()
        else:
            logger.warning(f"Packet dropped: {scapy_packet.summary()}")
            packet.drop()
    except Exception as e:
        logger.error(f"Error processing packet: {str(e)}")
        packet.drop()


def main():
    """
    Main function to set up and run the firewall.
    """
    try:
        # Bind the NetfilterQueue
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        logger.info("Firewall is running and processing packets...")
        queue.run()
    except KeyboardInterrupt:
        logger.info("Firewall stopped by user.")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
    finally:
        queue.unbind()

if __name__ == "__main__":
    main()
