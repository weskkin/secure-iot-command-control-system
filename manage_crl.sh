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
