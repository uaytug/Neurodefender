import logging
import logging.config
import os

def setup_logger(config_path='config/logging.conf', default_level=logging.INFO):
    """
    Set up logging configuration from a file.
    Args:
        config_path: Path to the logging configuration file.
        default_level: Default logging level if the config file is not found.
    """
    if os.path.exists(config_path):
        logging.config.fileConfig(config_path, disable_existing_loggers=False)
        logging.info(f"Logging configuration loaded from {config_path}")
    else:
        logging.basicConfig(level=default_level)
        logging.warning(f"Logging configuration file not found. Using default level: {logging.getLevelName(default_level)}")

if __name__ == "__main__":
    # Example usage
    setup_logger()
    logger = logging.getLogger("firewall")
    logger.info("This is an informational message for the firewall log.")
    logger.error("This is an error message for the firewall log.")
