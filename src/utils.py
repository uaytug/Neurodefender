import ipaddress
import logging

logger = logging.getLogger("firewall")

def validate_ip(ip_address):
    """
    Validate an IP address.
    Args:
        ip_address: The IP address to be validated.
    Returns:
        True if the IP address is valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        logger.error(f"Invalid IP address: {ip_address}")
        return False

def convert_ip_to_numeric(ip_address):
    """
    Convert an IP address to its numerical representation.
    Args:
        ip_address: The IP address to be converted.
    Returns:
        The numerical representation of the IP address.
    """
    try:
        return int(ipaddress.ip_address(ip_address))
    except ValueError as e:
        logger.error(f"Error converting IP address to numeric: {str(e)}")
        return None

def log_packet(packet, message="Packet Information"):
    """
    Log detailed information about a packet.
    Args:
        packet: The scapy packet to be logged.
        message: A message to include in the log.
    """
    try:
        logger.info(f"{message}: {packet.summary()} - {packet.show(dump=True)}")
    except Exception as e:
        logger.error(f"Error logging packet information: {str(e)}")

if __name__ == "__main__":
    # Example usage
    example_ip = "192.168.1.1"
    if validate_ip(example_ip):
        numeric_ip = convert_ip_to_numeric(example_ip)
        if numeric_ip is not None:
            logger.info(f"Numeric representation of {example_ip} is {numeric_ip}")
