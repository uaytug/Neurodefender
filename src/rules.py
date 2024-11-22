import json
import logging
from scapy.layers.inet import IP

logger = logging.getLogger("firewall")

def load_rules(file_path):
    """
    Load firewall rules from a JSON file.
    Args:
        file_path: Path to the JSON file containing firewall rules.
    Returns:
        A list of firewall rules.
    """
    try:
        with open(file_path, 'r') as rules_file:
            rules = json.load(rules_file)
            logger.info(f"Loaded {len(rules)} firewall rules from {file_path}")
            return rules
    except FileNotFoundError:
        logger.error(f"Rules file not found: {file_path}")
        return []
    except json.JSONDecodeError:
        logger.error(f"Error decoding rules file: {file_path}")
        return []


def is_packet_allowed(packet, rules):
    """
    Check if a packet matches any of the firewall rules.
    Args:
        packet: The scapy packet to be checked.
        rules: A list of firewall rules.
    Returns:
        True if the packet is allowed, False otherwise.
    """
    for rule in rules:
        if match_rule(packet, rule):
            logger.info(f"Packet matches rule: {rule}")
            return rule.get("action", "allow") == "allow"
    return False


def match_rule(packet, rule):
    """
    Match a packet against a specific rule.
    Args:
        packet: The scapy packet to be checked.
        rule: A firewall rule.
    Returns:
        True if the packet matches the rule, False otherwise.
    """
    try:
        # Check IP addresses
        if "src_ip" in rule and packet[IP].src != rule["src_ip"]:
            return False
        if "dst_ip" in rule and packet[IP].dst != rule["dst_ip"]:
            return False

        # Check protocols (TCP/UDP)
        if "protocol" in rule and packet.proto != rule["protocol"]:
            return False

        # Check ports if specified
        if "src_port" in rule and hasattr(packet, "sport") and packet.sport != rule["src_port"]:
            return False
        if "dst_port" in rule and hasattr(packet, "dport") and packet.dport != rule["dst_port"]:
            return False

        return True
    except Exception as e:
        logger.error(f"Error matching packet against rule: {str(e)}")
        return False
