import logging
import requests
import json

logger = logging.getLogger("firewall")

class ThreatIntelligence:
    def __init__(self, feed_urls):
        """
        Initialize the Threat Intelligence module.
        Args:
            feed_urls: A list of URLs to fetch threat intelligence feeds from.
        """
        self.feed_urls = feed_urls
        self.threat_data = set()

    def update_threat_data(self):
        """
        Fetch and update threat intelligence data from the provided feed URLs.
        """
        for url in self.feed_urls:
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.text.splitlines()
                self.threat_data.update(data)
                logger.info(f"Updated threat data from {url}, entries added: {len(data)}")
            except requests.RequestException as e:
                logger.error(f"Failed to fetch threat data from {url}: {str(e)}")

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

if __name__ == "__main__":
    # Example usage
    feed_urls = [
        "https://example.com/threat-feed-1.txt",
        "https://example.com/threat-feed-2.txt"
    ]
    ti = ThreatIntelligence(feed_urls)
    ti.update_threat_data()
    ip_to_check = "192.168.1.1"
    if ti.is_threat(ip_to_check):
        print(f"IP {ip_to_check} is a known threat.")
    else:
        print(f"IP {ip_to_check} is not a threat.")
