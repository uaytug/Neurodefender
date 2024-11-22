import json
import argparse
import logging

logger = logging.getLogger("firewall")
logging.basicConfig(level=logging.INFO)

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
        logger.warning(f"Rules file not found: {file_path}. Starting with an empty ruleset.")
        return []
    except json.JSONDecodeError:
        logger.error(f"Error decoding rules file: {file_path}")
        return []

def save_rules(rules, file_path):
    """
    Save firewall rules to a JSON file.
    Args:
        rules: A list of firewall rules.
        file_path: Path to the JSON file to save the rules.
    """
    try:
        with open(file_path, 'w') as rules_file:
            json.dump(rules, rules_file, indent=4)
            logger.info(f"Saved {len(rules)} firewall rules to {file_path}")
    except Exception as e:
        logger.error(f"Error saving rules to file: {str(e)}")

def add_rule(rule, file_path):
    """
    Add a new rule to the firewall rules file.
    Args:
        rule: A dictionary representing the rule to be added.
        file_path: Path to the JSON file containing firewall rules.
    """
    rules = load_rules(file_path)
    rules.append(rule)
    save_rules(rules, file_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Add a new firewall rule.")
    parser.add_argument("--src_ip", type=str, help="Source IP address")
    parser.add_argument("--dst_ip", type=str, help="Destination IP address")
    parser.add_argument("--protocol", type=str, choices=["TCP", "UDP"], help="Protocol (TCP/UDP)")
    parser.add_argument("--src_port", type=int, help="Source port number")
    parser.add_argument("--dst_port", type=int, help="Destination port number")
    parser.add_argument("--action", type=str, choices=["allow", "drop"], required=True, help="Action to take (allow/drop)")
    parser.add_argument("--file", type=str, default="config/firewall_rules.json", help="Path to the firewall rules file")

    args = parser.parse_args()

    new_rule = {
        "src_ip": args.src_ip,
        "dst_ip": args.dst_ip,
        "protocol": args.protocol,
        "src_port": args.src_port,
        "dst_port": args.dst_port,
        "action": args.action
    }

    # Remove keys with None values to keep the rule concise
    new_rule = {k: v for k, v in new_rule.items() if v is not None}

    add_rule(new_rule, args.file)
