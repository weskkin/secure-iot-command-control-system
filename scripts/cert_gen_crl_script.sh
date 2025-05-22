#!/bin/bash

# Set paths
CA_DIR="certificates/ca"
INTERMEDIATE_DIR="certificates/ca/intermediate"
CRL_DIR="certificates/crl"

echo "Regenerating certificates with SAN fields for TLS 1.3 and CRL support..."

# Navigate to project directory
cd ~/Desktop/secure-iot-command-control-system

# Create CRL directory structure
mkdir -p $CRL_DIR
mkdir -p $INTERMEDIATE_DIR/crl

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

# Initialize CRL number if it doesn't exist
if [ ! -f "$INTERMEDIATE_DIR/crlnumber" ]; then
    echo "1000" > $INTERMEDIATE_DIR/crlnumber
fi

# Initialize root CA CRL number if it doesn't exist
if [ ! -f "$CA_DIR/crlnumber" ]; then
    echo "1000" > $CA_DIR/crlnumber
fi

echo "Generating initial CRLs..."

# Generate Root CA CRL
openssl ca -config $CA_DIR/openssl.cnf \
    -gencrl -out $CRL_DIR/ca.crl.pem

# Generate Intermediate CA CRL
openssl ca -config $INTERMEDIATE_DIR/openssl.cnf \
    -gencrl -out $CRL_DIR/intermediate.crl.pem

# Convert CRLs to DER format for distribution
openssl crl -in $CRL_DIR/ca.crl.pem -outform DER -out $CRL_DIR/ca.crl
openssl crl -in $CRL_DIR/intermediate.crl.pem -outform DER -out $CRL_DIR/intermediate.crl

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

echo "Updating CRLs after certificate generation..."

# Regenerate CRLs to include any new certificates
openssl ca -config $CA_DIR/openssl.cnf \
    -gencrl -out $CRL_DIR/ca.crl.pem

openssl ca -config $INTERMEDIATE_DIR/openssl.cnf \
    -gencrl -out $CRL_DIR/intermediate.crl.pem

# Update DER format CRLs
openssl crl -in $CRL_DIR/ca.crl.pem -outform DER -out $CRL_DIR/ca.crl
openssl crl -in $CRL_DIR/intermediate.crl.pem -outform DER -out $CRL_DIR/intermediate.crl

echo "Creating CRL distribution points..."

# Create a combined CRL for easy distribution
cat $CRL_DIR/ca.crl.pem $CRL_DIR/intermediate.crl.pem > $CRL_DIR/combined.crl.pem

# Set proper permissions for CRL files
chmod 644 $CRL_DIR/*.crl*

echo "Verifying certificates..."
openssl verify -CAfile $INTERMEDIATE_DIR/certs/ca-chain.cert.pem \
    -crl_check -CRLfile $CRL_DIR/intermediate.crl.pem \
    $INTERMEDIATE_DIR/certs/mqtt_broker.cert.pem

echo "Certificate regeneration complete!"
echo ""
echo "CRL Information:"
echo "==============="
echo "Root CA CRL: $CRL_DIR/ca.crl.pem"
echo "Intermediate CA CRL: $CRL_DIR/intermediate.crl.pem"
echo "Combined CRL: $CRL_DIR/combined.crl.pem"
echo ""
echo "CRL Management Commands:"
echo "========================"
echo "To revoke a certificate:"
echo "  openssl ca -config $INTERMEDIATE_DIR/openssl.cnf -revoke <certificate_file>"
echo ""
echo "To update CRL after revocation:"
echo "  openssl ca -config $INTERMEDIATE_DIR/openssl.cnf -gencrl -out $CRL_DIR/intermediate.crl.pem"
echo ""
echo "To check CRL contents:"
echo "  openssl crl -in $CRL_DIR/intermediate.crl.pem -noout -text"
echo ""
echo "To verify certificate with CRL check:"
echo "  openssl verify -CAfile $INTERMEDIATE_DIR/certs/ca-chain.cert.pem -crl_check -CRLfile $CRL_DIR/intermediate.crl.pem <certificate_file>"
echo ""

# Create a helper script for CRL management
cat > manage_crl.sh << 'EOF'
#!/bin/bash

# CRL Management Helper Script
CA_DIR="certificates/ca"
INTERMEDIATE_DIR="certificates/ca/intermediate"
CRL_DIR="certificates/crl"

case "$1" in
    "revoke")
        if [ -z "$2" ]; then
            echo "Usage: $0 revoke <certificate_file>"
            exit 1
        fi
        echo "Revoking certificate: $2"
        openssl ca -config $INTERMEDIATE_DIR/openssl.cnf -revoke "$2"
        echo "Updating CRL..."
        openssl ca -config $INTERMEDIATE_DIR/openssl.cnf -gencrl -out $CRL_DIR/intermediate.crl.pem
        openssl crl -in $CRL_DIR/intermediate.crl.pem -outform DER -out $CRL_DIR/intermediate.crl
        echo "CRL updated successfully!"
        ;;
    "update-crl")
        echo "Updating intermediate CRL..."
        openssl ca -config $INTERMEDIATE_DIR/openssl.cnf -gencrl -out $CRL_DIR/intermediate.crl.pem
        openssl crl -in $CRL_DIR/intermediate.crl.pem -outform DER -out $CRL_DIR/intermediate.crl
        echo "Updating root CA CRL..."
        openssl ca -config $CA_DIR/openssl.cnf -gencrl -out $CRL_DIR/ca.crl.pem
        openssl crl -in $CRL_DIR/ca.crl.pem -outform DER -out $CRL_DIR/ca.crl
        cat $CRL_DIR/ca.crl.pem $CRL_DIR/intermediate.crl.pem > $CRL_DIR/combined.crl.pem
        echo "CRLs updated successfully!"
        ;;
    "check-crl")
        echo "Root CA CRL contents:"
        openssl crl -in $CRL_DIR/ca.crl.pem -noout -text
        echo ""
        echo "Intermediate CA CRL contents:"
        openssl crl -in $CRL_DIR/intermediate.crl.pem -noout -text
        ;;
    "verify")
        if [ -z "$2" ]; then
            echo "Usage: $0 verify <certificate_file>"
            exit 1
        fi
        echo "Verifying certificate with CRL check: $2"
        openssl verify -CAfile $INTERMEDIATE_DIR/certs/ca-chain.cert.pem -crl_check -CRLfile $CRL_DIR/intermediate.crl.pem "$2"
        ;;
    *)
        echo "CRL Management Helper"
        echo "Usage: $0 {revoke|update-crl|check-crl|verify} [certificate_file]"
        echo ""
        echo "Commands:"
        echo "  revoke <cert_file>   - Revoke a certificate and update CRL"
        echo "  update-crl          - Update all CRLs"
        echo "  check-crl           - Display CRL contents"
        echo "  verify <cert_file>  - Verify certificate with CRL check"
        ;;
esac
EOF

chmod +x manage_crl.sh

echo "Created CRL management helper script: manage_crl.sh"