#!/bin/bash

# Script to start the firewall

# Define the NetfilterQueue queue number
QUEUE_NUM=0

# Add iptables rule to redirect packets to NetfilterQueue
sudo iptables -I FORWARD -j NFQUEUE --queue-num $QUEUE_NUM

# Start the firewall Python script
python3 src/firewall.py

# Clean up iptables rule on exit
trap "sudo iptables -D FORWARD -j NFQUEUE --queue-num $QUEUE_NUM" EXIT

# Inform the user
echo "Firewall started. Press Ctrl+C to stop."
