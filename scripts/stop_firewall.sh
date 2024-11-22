#!/bin/bash

# Script to stop the firewall

# Define the NetfilterQueue queue number
QUEUE_NUM=0

# Remove iptables rule to stop redirecting packets to NetfilterQueue
sudo iptables -D FORWARD -j NFQUEUE --queue-num $QUEUE_NUM

# Inform the user
echo "Firewall stopped."
