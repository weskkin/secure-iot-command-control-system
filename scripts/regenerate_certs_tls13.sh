#!/bin/bash

# Set paths
CA_DIR="certificates/ca"
INTERMEDIATE_DIR="certificates/ca/intermediate"

echo "Regenerating certificates with SAN fields for TLS 1.3..."

# Navigate to project directory
cd ~/Desktop/secure-iot-command-control-system

# Clean up only end-entity certificates (keep CA certificates and structure)
rm -f $INTERMEDIATE_DIR/certs/mqtt_broker.cert.pem
rm -f $INTERMEDIATE_DIR/certs/flask-web.cert.pem
rm -f $INTERMEDIATE_DIR/certs/command_center.cert.pem
rm -f $INTERMEDIATE_DIR/certs/device_001.cert.pem
rm -f $INTERMEDIATE_DIR/certs/audit_monitor.cert.pem
rm -f $INTERMEDIATE_DIR/certs/*-chain.cert.pem

# DON'T remove CA certificates:
# - Keep ca.cert.pem 
# - Keep intermediate.cert.pem
# - Keep ca-chain.cert.pem

# Create CSR directory if it doesn't exist
mkdir -p $INTERMEDIATE_DIR/csr

# Clear the CA database entries for certificates we're regenerating
# This prevents the "already a certificate" error
cp $INTERMEDIATE_DIR/index.txt $INTERMEDIATE_DIR/index.txt.backup
# Remove entries that match our certificates (keep only CA entries)
grep -v "/CN=localhost\|/CN=command-center\|/CN=device_001\|/CN=flask-web\|/CN=mqtt-broker" $INTERMEDIATE_DIR/index.txt > $INTERMEDIATE_DIR/index.txt.new || true
mv $INTERMEDIATE_DIR/index.txt.new $INTERMEDIATE_DIR/index.txt

echo "Regenerating server certificates..."

# MQTT Broker Certificate
openssl req -config $INTERMEDIATE_DIR/openssl.cnf \
    -key $INTERMEDIATE_DIR/private/mqtt_broker.key.pem \
    -new -sha256 -out $INTERMEDIATE_DIR/csr/mqtt_broker.csr.pem \
    -subj "/C=TR/ST=Istanbul/L=Istanbul/O=IoT Security/OU=IoT/CN=mqtt-broker" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"

openssl ca -config $INTERMEDIATE_DIR/openssl.cnf \
    -extensions server_cert -days 375 -notext -md sha256 \
    -in $INTERMEDIATE_DIR/csr/mqtt_broker.csr.pem \
    -out $INTERMEDIATE_DIR/certs/mqtt_broker.cert.pem \
    -batch

# Flask Web Certificate
openssl req -config $INTERMEDIATE_DIR/openssl.cnf \
    -key $INTERMEDIATE_DIR/private/flask-web.key.pem \
    -new -sha256 -out $INTERMEDIATE_DIR/csr/flask-web.csr.pem \
    -subj "/C=TR/ST=Istanbul/L=Istanbul/O=IoT Security/OU=IoT/CN=flask-web" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"

openssl ca -config $INTERMEDIATE_DIR/openssl.cnf \
    -extensions server_cert -days 375 -notext -md sha256 \
    -in $INTERMEDIATE_DIR/csr/flask-web.csr.pem \
    -out $INTERMEDIATE_DIR/certs/flask-web.cert.pem \
    -batch

# Command Center Certificate (client)
openssl req -config $INTERMEDIATE_DIR/openssl.cnf \
    -key $INTERMEDIATE_DIR/private/command_center.key.pem \
    -new -sha256 -out $INTERMEDIATE_DIR/csr/command_center.csr.pem \
    -subj "/C=TR/ST=Istanbul/L=Istanbul/O=IoT Security/OU=IoT/CN=command-center" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"

openssl ca -config $INTERMEDIATE_DIR/openssl.cnf \
    -extensions usr_cert -days 375 -notext -md sha256 \
    -in $INTERMEDIATE_DIR/csr/command_center.csr.pem \
    -out $INTERMEDIATE_DIR/certs/command_center.cert.pem \
    -batch

# Device Certificate (client)
openssl req -config $INTERMEDIATE_DIR/openssl.cnf \
    -key $INTERMEDIATE_DIR/private/device_001.key.pem \
    -new -sha256 -out $INTERMEDIATE_DIR/csr/device_001.csr.pem \
    -subj "/C=TR/ST=Istanbul/L=Istanbul/O=IoT Security/OU=IoT/CN=device_001" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"

openssl ca -config $INTERMEDIATE_DIR/openssl.cnf \
    -extensions usr_cert -days 375 -notext -md sha256 \
    -in $INTERMEDIATE_DIR/csr/device_001.csr.pem \
    -out $INTERMEDIATE_DIR/certs/device_001.cert.pem \
    -batch

echo "Creating certificate chains..."

# Check if ca-chain.cert.pem exists, if not create it
if [ ! -f "$INTERMEDIATE_DIR/certs/ca-chain.cert.pem" ]; then
    echo "Creating ca-chain.cert.pem..."
    cat $INTERMEDIATE_DIR/certs/intermediate.cert.pem \
        $CA_DIR/certs/ca.cert.pem > \
        $INTERMEDIATE_DIR/certs/ca-chain.cert.pem
fi

# Create certificate chains
cat $INTERMEDIATE_DIR/certs/mqtt_broker.cert.pem \
    $INTERMEDIATE_DIR/certs/intermediate.cert.pem > \
    $INTERMEDIATE_DIR/certs/broker-chain.cert.pem

cat $INTERMEDIATE_DIR/certs/flask-web.cert.pem \
    $INTERMEDIATE_DIR/certs/intermediate.cert.pem > \
    $INTERMEDIATE_DIR/certs/flask-web-chain.cert.pem

cat $INTERMEDIATE_DIR/certs/command_center.cert.pem \
    $INTERMEDIATE_DIR/certs/intermediate.cert.pem > \
    $INTERMEDIATE_DIR/certs/client-chain.cert.pem

cat $INTERMEDIATE_DIR/certs/device_001.cert.pem \
    $INTERMEDIATE_DIR/certs/intermediate.cert.pem > \
    $INTERMEDIATE_DIR/certs/device_001-chain.cert.pem

echo "Verifying certificates..."
openssl verify -CAfile $INTERMEDIATE_DIR/certs/ca-chain.cert.pem \
    $INTERMEDIATE_DIR/certs/mqtt_broker.cert.pem

echo "Certificate regeneration complete!"
