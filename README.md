# NGFW Project with AI Anomaly Detection

## Overview

This project is a Next-Generation Firewall (NGFW) integrated with AI-based anomaly detection and threat intelligence capabilities. The firewall offers traditional packet filtering, stateful inspection, and advanced AI-driven anomaly detection to provide robust security against network threats. Additionally, threat intelligence feeds are used to block known malicious entities.

## Features

- **Packet Filtering**: Traditional firewall functionality to filter packets based on predefined rules.
- **Stateful Inspection**: Tracks the state of active connections and ensures packets are part of established sessions.
- **AI Anomaly Detection**: Uses a pre-trained machine learning model to identify anomalous network activities.
- **Threat Intelligence Integration**: Fetches and uses threat intelligence feeds to block traffic from known malicious IP addresses.
- **Logging**: Comprehensive logging for all activities, including packet inspection, threat detection, and anomalies.
- **Web Dashboard**: A UI for managing firewall rules, viewing logs, and monitoring network activity (future implementation).

## File Structure

```md
ngfw_project/
│
├── src/
│   ├── firewall.py                   # Main firewall script
│   ├── packet_inspector.py           # Module for packet inspection logic
│   ├── connection_tracker.py         # Stateful inspection logic (track open connections)
│   ├── log_handler.py                # Module to handle logging
│   ├── rules.py                      # Rule management (add/update/delete rules)
│   ├── anomaly_detector.py           # AI-based anomaly detection logic
│   ├── threat_intelligence.py        # Threat intelligence module for IP reputation check, URL filtering
│   ├── utils.py                      # Utility functions used across the project
│
├── ai_model/
│   ├── model_training.py             # Script to train the AI model
│   ├── data_preprocessing.py         # Module for data preprocessing before training
│   ├── model.py                      # Trained model for anomaly detection
│   ├── model_inference.py            # Script to run the model in production for real-time detection
│   ├── datasets/                     # Directory for training datasets
│
├── config/
│   ├── firewall_rules.json           # JSON file containing predefined rules
│   ├── anomaly_config.json           # Configuration for anomaly detection parameters
│   ├── logging.conf                  # Logging configuration (e.g., format, location)
│
├── logs/
│   ├── firewall.log                  # Log file for firewall activity (denied packets, etc.)
│   ├── anomaly_detection.log         # Log file for anomaly detection alerts
│
├── tests/
│   ├── test_firewall.py              # Unit tests for firewall functionalities
│   ├── test_packet_inspector.py      # Tests for packet inspection
│   ├── test_rules.py                 # Tests for rule management
│
├── ui/
│   ├── dashboard.py                  # Web-based dashboard for NGFW (using Flask or similar)
│   ├── static/                       # Static files for the dashboard (CSS, JS)
│   ├── templates/                    # HTML templates for dashboard UI
│
├── README.md                         # Project overview and setup instructions
├── requirements.txt                  # Python dependencies
└── LICENSE                           # License for the project
```

## Getting Started

### Prerequisites

- Python 3.8 or higher
- `pip` for installing Python dependencies
- Linux-based system for using NetfilterQueue and iptables (for packet capturing)

### Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/yourusername/ngfw_project.git
   cd ngfw_project
   ```

2. Install the required dependencies:

   ```sh
   pip install -r requirements.txt
   ```

3. Set up logging configuration (optional):
   Modify `config/logging.conf` to customize logging as needed.

### Running the Firewall

1. Set up `iptables` to redirect traffic to NetfilterQueue:

   ```sh
   sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
   ```

2. Run the main firewall script:

   ```sh
   python src/firewall.py
   ```

### Stopping the Firewall

To stop the firewall and remove the iptables rule:

```sh
sudo iptables -D FORWARD -j NFQUEUE --queue-num 0
```

## Configuration

- **Firewall Rules**: Modify `config/firewall_rules.json` to add, update, or delete firewall rules.
- **Anomaly Detection**: The pre-trained AI model can be updated or retrained using scripts in `ai_model/`.
- **Threat Intelligence Feeds**: Update the list of threat intelligence URLs in `threat_intelligence.py`.

## Logging

All activities are logged, including packet inspections, threat detections, and anomalies. Logs can be found in the `logs/` directory:

- `firewall.log` for general firewall activity.
- `anomaly_detection.log` for alerts triggered by the anomaly detector.

## Testing

- Unit tests are provided in the `tests/` directory.
- Run the tests using `pytest`:

  ```sh
  pytest tests/
  ```

## Contributing

Feel free to open issues or submit pull requests to improve the project. Contributions are welcome!

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgements

- **Scapy**: Used for packet crafting and manipulation.
- **NetfilterQueue**: Used to interface with iptables for packet capture and modification.
- **Joblib**: Used for saving and loading the AI model.

## Future Work

- Implement a web-based dashboard for managing firewall rules and monitoring activity in real-time.
- Improve the anomaly detection model with more diverse datasets and additional feature engineering.
