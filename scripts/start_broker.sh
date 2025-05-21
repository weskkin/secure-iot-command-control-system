#!/bin/bash

# MQTT Broker Startup Script
# This script starts the Mosquitto MQTT broker with TLS configuration

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Secure MQTT Broker...${NC}"

# Get absolute project root path (two levels up from script location)
PROJECT_ROOT=$(dirname "$(dirname "$(realpath "$0")")")

# Create secure persistence directory
PERSIST_DIR="${PROJECT_ROOT}/mosquitto_persistence"
mkdir -p "$PERSIST_DIR"
chmod 700 "$PERSIST_DIR"

# Check if config file exists
if [ ! -f "${PROJECT_ROOT}/config/mosquitto.conf" ]; then
    echo -e "${RED}Error: mosquitto.conf not found at ${PROJECT_ROOT}/config/mosquitto.conf${NC}"
    exit 1
fi

# Start the broker
echo -e "${GREEN}Starting Mosquitto with TLS configuration...${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"

# Start mosquitto with only the config file
mosquitto -c "${PROJECT_ROOT}/config/mosquitto.conf" -v