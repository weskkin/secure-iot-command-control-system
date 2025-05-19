#!/bin/bash

# MQTT Broker Startup Script
# This script starts the Mosquitto MQTT broker with TLS configuration

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Secure MQTT Broker...${NC}"

# Check if config file exists
if [ ! -f "config/mosquitto.conf" ]; then
    echo -e "${RED}Error: config/mosquitto.conf not found!${NC}"
    exit 1
fi

# Check if certificates exist
if [ ! -f "certificates/ca/certs/ca.cert.pem" ]; then
    echo -e "${RED}Error: CA certificate not found!${NC}"
    exit 1
fi

if [ ! -f "certificates/ca/intermediate/certs/mqtt_broker.cert.pem" ]; then
    echo -e "${RED}Error: Broker certificate not found!${NC}"
    exit 1
fi

# Create temporary directory for persistence
mkdir -p /tmp/mosquitto

# Start the broker
echo -e "${GREEN}Starting Mosquitto with TLS configuration...${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"

# Run mosquitto with our configuration
mosquitto -c config/mosquitto.conf -v