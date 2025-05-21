import time
import random
import paho.mqtt.client as mqtt 
import json
import ssl
import os
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import re
from pathlib import Path

class IoTDevice:
    def __init__(self, device_id, device_type):
        self.device_id = device_id
        self.device_type = device_type
        self.status = 'offline'
        self.mqtt_client = None # Placeholder for MQTT client instance
        self.connected = False

        self.allowed_commands = {
            "temperature_sensor": ["read_temperature", "restart"],
            "security_camera": ["activate", "deactivate", "restart", "status_check"]
        }

        # TLS certificate paths
        # Get the absolute path to this script's directory
        base_dir = Path(__file__).parent.absolute()
        
        # TLS certificate paths - Update these paths
        self.ca_cert = base_dir / "ca.cert.pem"
        self.device_cert = base_dir / "device_certs/device_001-chain.cert.pem"
        self.device_key = base_dir / "device_certs/device_001.key.pem"

        print(f"CA Path: {self.ca_cert}")
        print(f"Device Cert Path: {self.device_cert}")

        # Verify certificate files exist
        self._verify_certificates()

        # Load Command Center's public key from its certificate
        self.command_center_pubkey = self._load_public_key()

        # Load device's signing key
        self.signing_key = self._load_signing_key()

        print(f"Secure Device {device_id} ({device_type}) initialized  ")

    def _verify_certificates(self):
        """Verify that all required certificate files exist"""

        cert_files = [
            (self.ca_cert, "CA Certificate"),
            (self.device_cert, "Device Certificate"),
            (self.device_key, "Device Private Key")
        ]

        for cert_path, cert_name in cert_files:
            if not os.path.exists(cert_path):
                raise FileNotFoundError(f"{cert_name} not found at: {cert_path}")
            
        print("All device certificate files found")      

    def _load_public_key(self):
        """Load public key from Command Center's certificate"""
        with open("command_center.cert.pem", "rb") as f:
            cert = load_pem_x509_certificate(f.read(), default_backend())
            return cert.public_key()  

    def _load_signing_key(self):
        with open(self.device_key, 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
    def _sign_message(self, message):
        signature = self.signing_key.sign(
            json.dumps(message).encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def on_connect(self, client, userdata, flags, rc, properties):
        """Callback when connected to MQTT broker"""

        if rc == 0:
            print(f"Device {self.device_id} connected to MQTT broker securely (TLS)") #Connection status
            self.connected = True
            
            # Subscribe to a topic to receive commands (e.g., "iot/devices/dev001/commands")
            command_topic = f"iot/devices/{self.device_id}/commands"
            client.subscribe(command_topic) # Subscribe to the topic
            print(f"Subscribed to {command_topic}") #Confirmation

            self.status = "online" # Update device status

            # Publish a JSON status message to the broker (e.g., "iot/devices/dev001/status")
            status_msg = {
                "device_id": self.device_id,
                "type": self.device_type,
                "status": self.status,
                "timestamp": time.time() # Current Unix timestamp
            }

            # Add digital signature
            status_msg["signature"] = self._sign_message(status_msg)

            client.publish(f"iot/devices/{self.device_id}/status", json.dumps(status_msg)) # Send message
            print(f"Published online status for device {self.device_id}")
        else:
            print(f"Device {self.device_id} failed to connect. Return code: {rc}")
            self.connected = False        

    def on_message(self, client, userdata, msg):
        """Callback when message is received"""
        print(f"Device {self.device_id} received message on topic {msg.topic}")

        try:
            # ====== NEW VALIDATION CODE ======
            # Extract device ID from topic
            topic_parts = msg.topic.split('/')
            if len(topic_parts) < 4:
                print(f"Invalid topic format: {msg.topic}")
                return
                
            received_device_id = topic_parts[2]
            
            # Validate device ID format
            if not re.match(r'^dev\d{3}$', received_device_id):
                print(f"Invalid device ID format: {received_device_id}")
                return
                
            # Verify message is for this specific device
            if received_device_id != self.device_id:
                print(f"Received command for different device: {received_device_id}")
                return
            # ====== END OF VALIDATION ======

            # Parse incoming JSON payload
            command_data = json.loads(msg.payload.decode())

            # Extract signature
            signature = base64.b64decode(command_data.pop('signature'))

            # Verify signature
            self.command_center_pubkey.verify(
                signature,
                json.dumps(command_data).encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # REPLAY PROTECTION: TIMESTAMP VALIDATION
            command_timestamp = command_data.get("timestamp")
            if not command_timestamp:
                print("Missing timestamp in command")
                return

            current_time = time.time()
            if abs(current_time - command_timestamp) > 300:  # 5-minute window
                print(f"⚠️ Replay attack detected (Δ={current_time-command_timestamp:.1f}s)")
                # Send rejection notification
                result_msg = {
                    "device_id": self.device_id,
                    "command": command_data.get('command', 'unknown'),
                    "result": "REJECTED: Replay attack detected",
                    "timestamp": time.time()
                }
                result_msg["signature"] = self._sign_message(result_msg)
                client.publish(f"iot/devices/{self.device_id}/results", json.dumps(result_msg))
                return

            # future timestamp check
            if command_timestamp > time.time() + 60:  # Allow 1m clock drift
                print(f"Future-dated command rejected (Δ={command_timestamp-time.time():.1f}s)")
                return
            
            command = command_data.get('command') # Extract command field

            if not command: # Handle missing command field
                print("Received message with no command field")
                return
            
            print(f"Processing command: {command}") # Log the command

            # Execute the command (e.g., read a sensor)
            result = self.process_command(command) # Call processing logic

            # Publish the result to a results topic (e.g., "iot/devices/dev001/results")
            result_msg = {
                "device_id": self.device_id,
                "command": command,
                "result": result,
                "timestamp": time.time()
            }

            # Add digital signature
            result_msg["signature"] = self._sign_message(result_msg)

            client.publish(f"iot/devices/{self.device_id}/results", json.dumps(result_msg)) # Send result
            print(f"Published command result for {command}")
        except InvalidSignature:
            print(f"Tampered command rejected: {command_data.get('command')}")
        except KeyError:
            print("Missing signature in command")
        except json.JSONDecodeError: # Invalid JSON
            print(f"Received invalid JSON: {msg.payload.decode()}")
        except Exception as e: # Generic Errors
            print(f"Error processing message: {str(e)}")
    
    def connect(self):
        """Connect to the MQTT broker with TLS"""
        print(f"Device {self.device_id} connecting to secure MQTT broker ...")

        try:
            # Create an MQTT client instance with a unique ID
            client = mqtt.Client(client_id=f"device_{self.device_id}", callback_api_version=mqtt.CallbackAPIVersion.VERSION2)

            # Assign callback functions
            client.on_connect = self.on_connect
            client.on_message = self.on_message

            # Configure TLS/SSL
            print("Configuring TLS certificates...")
            client.tls_set(
                ca_certs=self.ca_cert,
                certfile=self.device_cert,
                keyfile=self.device_key,
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLSv1_2,
                ciphers='ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384'
            )

            # Set TLS options
            client.tls_insecure_set(False)

            # Connect to the broker running on localhost at port 8883
            print("Connecting to broker on port 8883...")
            client.connect("localhost", 8883, 60)

            self.mqtt_client = client # Store the client instance
            
            return client
        except Exception as e:
            print(f"Error setting up TLS connection: {str(e)}")
            return None

    def process_command(self, command):
        """Process a command from the command center"""
        print(f"Device {self.device_id} received command: {command}")

        # Simulate processing time
        time.sleep(1)

        if command not in self.allowed_commands.get(self.device_type, []):
            return {"status": "error", "message": "Unauthorized command"}

        # Simulate different responses based on command type
        if command == "read_temperature":
            # Simulate temperature reading
            temperature = round(random.uniform(18.0, 32.0), 1)
            return {
                "status": "success", 
                "message": f"Temperature reading: {temperature}°C",
                "data": {"temperature": temperature}
            }
        elif command == "activate":
            return {"status": "success", "message": "Device activated successfully"}
        elif command == "deactivate":
            return {"status": "success", "message": "Device deactivated successfully"}
        elif command == "restart":
            return {"status": "success", "message": "Device restarted successfully"}
        else:
            # For unknown commands, simulate 90% success rate
            success = random.random() > 0.1
            if success:
                return {"status": "success", "message": f"Command '{command}' executed successfully"}
            else:
                return {"status": "error", "message": f"Failed to execute command '{command}'"}
        

#Simple test code
if __name__ == "__main__":

    try:
        # Create a test device
        device = IoTDevice("dev001", "temperature_sensor")

        # Connect to MQTT broker and get the client instance
        client = device.connect()

        if client:
            print("Starting device loop...")
            # Start the MQTT loop
            client.loop_forever()
        else:
            print("Failed to conenct to MQTT broker")
    except KeyboardInterrupt:
        print(f"\nShutting down device {device.device_id}...")

        # Publish offline status before disconnecting
        if hasattr(device, 'mqtt_client') and device.mqtt_client:
            status_msg = {
                "device_id": device.device_id,
                "status": "offline",
                "type": device.device_type,
                "timestamp": time.time()
            }

            # Add digital signature
            status_msg["signature"] = device._sign_message(status_msg)

            device.mqtt_client.publish(f"iot/devices/{device.device_id}/status", json.dumps(status_msg))
            time.sleep(1)  # Give time for message to be sent
            device.mqtt_client.disconnect()
            
    except Exception as e:
        print(f"Error starting device: {str(e)}")