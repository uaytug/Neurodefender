import logging
import requests
import json
from datetime import datetime

logger = logging.getLogger("firewall")

class ThreatAnalysis:
    def __init__(self, feed_urls, local_cache_path="config/threat_cache.json"):
        """
        Initialize the Threat Analysis module.
        Args:
            feed_urls: A list of URLs to fetch threat intelligence feeds from.
            local_cache_path: Path to store locally cached threat data.
        """
        self.feed_urls = feed_urls
        self.local_cache_path = local_cache_path
        self.threat_data = set()
        self.load_local_cache()

    def load_local_cache(self):
        """
        Load locally cached threat data to reduce reliance on external sources.
        """
        try:
            with open(self.local_cache_path, 'r') as cache_file:
                cache = json.load(cache_file)
                self.threat_data.update(cache.get("threat_ips", []))
                logger.info(f"Loaded {len(self.threat_data)} entries from local cache.")
        except FileNotFoundError:
            logger.warning(f"No local cache found at {self.local_cache_path}. Starting fresh.")
        except json.JSONDecodeError:
            logger.error(f"Error decoding local cache file at {self.local_cache_path}.")

    def update_threat_data(self):
        """
        Fetch and update threat intelligence data from the provided feed URLs.
        """
        new_threats = set()
        for url in self.feed_urls:
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.text.splitlines()
                new_threats.update(data)
                logger.info(f"Fetched {len(data)} new threat entries from {url}")
            except requests.RequestException as e:
                logger.error(f"Failed to fetch threat data from {url}: {str(e)}")

        # Update the current threat data
        self.threat_data.update(new_threats)
        logger.info(f"Total threat data entries updated to {len(self.threat_data)}.")
        self.save_local_cache()

    def save_local_cache(self):
        """
        Save the current threat data to a local cache file.
        """
        try:
            with open(self.local_cache_path, 'w') as cache_file:
                json.dump({"threat_ips": list(self.threat_data)}, cache_file, indent=4)
                logger.info(f"Threat data cached locally at {self.local_cache_path}.")
        except Exception as e:
            logger.error(f"Error saving threat data to local cache: {str(e)}")

    def is_threat(self, ip_address):
        """
        Check if an IP address is in the threat intelligence data.
        Args:
            ip_address: The IP address to check.
        Returns:
            True if the IP address is identified as a threat, False otherwise.
        """
        if ip_address in self.threat_data:
            logger.warning(f"IP address {ip_address} identified as a threat.")
            return True
        return False

    def log_threat(self, ip_address):
        """
        Log a threat detection with the timestamp.
        Args:
            ip_address: The IP address identified as a threat.
        """
        try:
            logger.warning(f"Threat detected: IP {ip_address} at {datetime.now().isoformat()}")
        except Exception as e:
            logger.error(f"Error logging threat: {str(e)}")

if __name__ == "__main__":
    # Example usage
    feed_urls = [
        "https://example.com/threat-feed-1.txt",
        "https://example.com/threat-feed-2.txt"
    ]
    threat_analysis = ThreatAnalysis(feed_urls)
    threat_analysis.update_threat_data()
    ip_to_check = "192.168.1.1"
    if threat_analysis.is_threat(ip_to_check):
        threat_analysis.log_threat(ip_to_check)
    else:
        print(f"IP {ip_to_check} is not a threat.")
