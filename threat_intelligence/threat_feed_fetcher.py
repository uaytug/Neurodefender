import logging
import requests
from datetime import datetime

logger = logging.getLogger("firewall")

class ThreatFeedFetcher:
    def __init__(self, feed_urls):
        """
        Initialize the Threat Feed Fetcher.
        Args:
            feed_urls: A list of URLs to fetch threat intelligence feeds from.
        """
        self.feed_urls = feed_urls
        self.threat_data = set()

    def fetch_feeds(self):
        """
        Fetch and update threat intelligence data from the provided feed URLs.
        """
        fetched_data = set()
        for url in self.feed_urls:
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.text.splitlines()
                fetched_data.update(data)
                logger.info(f"Fetched {len(data)} threat entries from {url}.")
            except requests.RequestException as e:
                logger.error(f"Failed to fetch threat data from {url}: {str(e)}")

        self.threat_data = fetched_data
        logger.info(f"Total threat data entries fetched: {len(self.threat_data)}.")

    def save_feed(self, file_path="feeds/threat_feed_cache.txt"):
        """
        Save the fetched threat data to a file for later use.
        Args:
            file_path: Path to the file to store the threat feed data.
        """
        try:
            with open(file_path, 'w') as file:
                for entry in self.threat_data:
                    file.write(f"{entry}\n")
                logger.info(f"Threat feed data saved to {file_path}.")
        except Exception as e:
            logger.error(f"Error saving threat feed data: {str(e)}")

    def get_threat_data(self):
        """
        Get the current threat data.
        Returns:
            A set containing all threat entries fetched.
        """
        return self.threat_data

if __name__ == "__main__":
    # Example usage
    feed_urls = [
        "https://example.com/threat-feed-1.txt",
        "https://example.com/threat-feed-2.txt"
    ]
    fetcher = ThreatFeedFetcher(feed_urls)
    fetcher.fetch_feeds()
    fetcher.save_feed()
    for threat in fetcher.get_threat_data():
        print(f"Threat IP: {threat}")
