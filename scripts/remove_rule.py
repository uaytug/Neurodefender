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

def remove_rule(rule_index, file_path):
    """
    Remove a rule from the firewall rules file by its index.
    Args:
        rule_index: Index of the rule to be removed.
        file_path: Path to the JSON file containing firewall rules.
    """
    rules = load_rules(file_path)
    if 0 <= rule_index < len(rules):
        removed_rule = rules.pop(rule_index)
        logger.info(f"Removed rule at index {rule_index}: {removed_rule}")
        save_rules(rules, file_path)
    else:
        logger.error(f"Invalid rule index: {rule_index}. No rule removed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Remove a firewall rule.")
    parser.add_argument("--index", type=int, required=True, help="Index of the rule to remove")
    parser.add_argument("--file", type=str, default="config/firewall_rules.json", help="Path to the firewall rules file")

    args = parser.parse_args()
    remove_rule(args.index, args.file)
