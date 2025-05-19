# Certificate Setup Instructions

This document explains how to set up certificates for the Secure IoT Command and Control System.

## Prerequisites

- OpenSSL installed on your system
- The project structure should already be in place

## Certificate Structure

The system requires the following certificates:

```
certificates/
├── ca/
│   ├── certs/
│   │   └── ca.cert.pem                    # Root CA certificate
│   ├── private/
│   │   └── ca.key.pem                     # Root CA private key
│   └── intermediate/
│       ├── certs/
│       │   ├── intermediate.cert.pem      # Intermediate CA certificate
│       │   ├── ca-chain.cert.pem          # CA chain file
│       │   ├── mqtt_broker.cert.pem       # MQTT broker certificate
│       │   ├── broker-chain.cert.pem      # Broker + Intermediate chain
│       │   ├── command_center.cert.pem    # Command center certificate
│       │   ├── client-chain.cert.pem      # Client + Intermediate chain
│       │   ├── device_001.cert.pem        # Device certificate
│       │   └── device_001-chain.cert.pem  # Device + Intermediate chain
│       └── private/
│           ├── intermediate.key.pem       # Intermediate CA private key
│           ├── mqtt_broker.key.pem        # MQTT broker private key
│           ├── command_center.key.pem     # Command center private key
│           └── device_001.key.pem         # Device private key
```

## Setup Instructions

1. **Create Certificate Directory Structure**:
   ```bash
   mkdir -p certificates/ca/{certs,private,intermediate/{certs,private}}
   ```

2. **Generate Root CA** (follow Jamie Linux's CA guide)

3. **Generate Intermediate CA** (follow Jamie Linux's CA guide)

4. **Generate Server Certificate for MQTT Broker** (follow Jamie Linux's CA guide)

5. **Generate Client Certificates** for Command Center and Devices (follow Jamie Linux's CA guide)

6. **Update Configuration Paths** in code files:
   - Update paths in `app.py`
   - Update paths in `device.py`
   - Update paths in `config/mosquitto.conf`

## Security Notes

- ⚠️ **NEVER** commit private keys (*.key.pem) to version control
- ⚠️ **NEVER** share private keys via email, chat, or other unsecure channels
- 🔒 Store private keys with restricted permissions: `chmod 600 *.key.pem`
- 🔒 Regularly rotate certificates in production environments
- 🔒 Use strong passphrases for CA private keys

## File Permissions

Set appropriate permissions for certificate files:

```bash
# Make private keys readable only by owner
chmod 600 certificates/ca/private/*.key.pem
chmod 600 certificates/ca/intermediate/private/*.key.pem

# Make certificates readable by owner and group
chmod 644 certificates/ca/certs/*.cert.pem
chmod 644 certificates/ca/intermediate/certs/*.cert.pem
```

## Environment-Specific Paths

The current code uses absolute paths. For production deployment, consider:

1. Using environment variables for certificate paths
2. Relative paths from a base certificate directory
3. Docker secrets or similar secure mounting mechanisms

## Regenerating Certificates

If you need to regenerate certificates (e.g., due to expiration or compromise):

1. Follow the same steps as initial setup
2. Update the paths in configuration files if necessary
3. Restart all services (broker, command center, devices)

## Troubleshooting

- **Permission Denied**: Check file permissions with `ls -la certificates/`
- **File Not Found**: Verify paths in configuration files match actual certificate locations
- **TLS Handshake Failures**: Ensure certificate chains are complete and valid