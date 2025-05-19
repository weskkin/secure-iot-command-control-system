import json
import time
import paho.mqtt.client as mqtt
import threading
import ssl
import os

class CommandCenterMQTT:
    def __init__(self):
        self.client = None
        self.connected = False
        self.devices = {} # To store device statuses

        # TLS certificate paths
        self.ca_cert = "/home/weskin/Desktop/secure-iot-command-control-system/certificates/ca/certs/ca.cert.pem"
        self.center_cert = "/home/weskin/Desktop/secure-iot-command-control-system/certificates/ca/intermediate/certs/client-chain.cert.pem"
        self.center_key = "/home/weskin/Desktop/secure-iot-command-control-system/certificates/ca/intermediate/private/command_center.key.pem"

        # Verify certificate files exist
        self._verify_certificates()

    def _verify_certificates(self):
        """Verify that all required certificate files exist"""

        cert_files = [
            (self.ca_cert, "CA Certificate"),
            (self.center_cert, "Center Certificate"),
            (self.center_key, "Center Private Key")
        ]

        for cert_path, cert_name in cert_files:
            if not os.path.exists(cert_path):
                raise FileNotFoundError(f"{cert_name} not found at: {cert_path}")
            
        print("All certificate files found")

    def on_connect(self, client, userdata, flags, rc):
        """Callback when connected to MQTT broker"""

        if rc == 0:
            print(f"Command center connected to MQTT broker securely (TLS)")
            self.connected = True

            # Subscribe to device status updates
            client.subscribe("iot/devices/+/status")
            print("Subscribed to device status updates")

            # Subscribe to command results
            client.subscribe("iot/devices/+/results")
            print("Subscribed to command results")
        else:
            print(f"Failed to connect to MQTT broker. Return code: {rc}")
            self.connected = False

    def on_message(self, client, userdata, msg): 
        """Callback when message is received"""

        print(f"Command center received message on topic {msg.topic}")

        try:
            # Parse message from JSON
            message_data = json.loads(msg.payload.decode())

            # Extract device ID from topic
            # Topic format : iot/devices/<device_id>/status or iot/devices/<device_id>/results
            topic_parts = msg.topic.split('/')
            if len(topic_parts) < 4:
                print(f"Invalid topic format: {msg.topic}")
                return
            
            device_id = topic_parts[2]
            message_type = topic_parts[3] # status or results

            if message_type == "status":
                # Update device registry with status (online/offline)
                self.devices[device_id] = {
                    "status": message_data.get("status", "unknown"),
                    "type": message_data.get("type", "unknown"),
                    "last_update": time.time()
                }
                print(f"Updated status for device {device_id}: {message_data.get('status')}")
            elif message_type == "results":
                # Process command result
                command = message_data.get("command")
                result = message_data.get("result")
                print(f"Received result for command {command} on device {device_id}: {result}")
                
        except json.JSONDecodeError:
            print(f"Received invalid JSON: {msg.payload.decode()}")
        except Exception as e:
            print(f"Error processing message: {str(e)}")

    def connect(self):
        """Connect to the MQTT Broker"""
        print("Command center connecting to MQTT broker with TLS ...")

        try:
            # Create MQTT client
            client = mqtt.Client(client_id="command_center")
            client.on_connect = self.on_connect
            client.on_message = self.on_message
            # client.on_disconnect = self.on_disconnect
            # client.on_log = self.on_log

            # Configure TLS/SSL
            print("Configuring TLS certificates ...")

            client.tls_set(
                ca_certs=self.ca_cert,          # CA certificate
                certfile=self.center_cert,      # Center certificate
                keyfile=self.center_key,        # Center private key
                cert_reqs=ssl.CERT_REQUIRED,    # Require certificate verification
                tls_version=ssl.PROTOCOL_TLSv1_2,   # Force TLSv1.2
                ciphers='DEFAULT@SECLEVEL=1'    # Allow wider cipher compatibility
            )

            # Optional: Set additional TLS options
            client.tls_insecure_set(False)  # Verify hostname (set to True for self-signed certs in dev)

            # Connect to broker
            print("Connecting to broker on port 8883 ...")
            client.connect("localhost", 8883, 60)

            self.client = client

            # Start MQTT client in a background thread
            mqtt_thread = threading.Thread(target=client.loop_forever)
            mqtt_thread.daemon = True  # Thread dies when main program exits
            mqtt_thread.start()

            # Wait up to 10 seconds for connection confirmation
            print("Waiting for connection confirmation...")
            count = 0
            while not self.connected and count < 20:
                time.sleep(0.5)
                count += 1

            if self.connected:
                print("Successfully connected to secure MQTT broker!")
            else:
                print("Failed to connect to MQTT broker within timeout period")
            
            return self.connected # True if connected, False otherwise
        
        except Exception as e:
            print(f"Error setting up TLS connection: {str(e)}")
            return False
            
    def send_command(self, device_id, command):
        """Send a command to a device"""

        if not self.client or not self.connected:
            print("MQTT client not connected")
            return False
        
        try:
            # Create JSON command message
            command_msg = json.dumps({
                "command": command,
                "timestamp": time.time(),
                "source": "command_center",
                "message_id": f"cmd_{int(time.time() * 1000000)}"
            })

            # Publish to device's command topic (e.g., iot/devices/dev001/commands)
            topic = f"iot/devices/{device_id}/commands"
            result = self.client.publish(topic, command_msg)

            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                print(f"Sent command {command} to device {device_id}")
                return True
            else:
                print(f"Failed to send command. MQTT error code: {result.rc}")
                return False
        except Exception as e:
            print(f"Error sending command: {str(e)}")
            return False            
    
    def get_device_list(self):
        """Return list of known devices and their statuses"""
        return self.devices  # Dictionary of devices
    
    def disconnect(self):
        """Disconnect from MQTT broker"""

        if self.client and self.connected:
            print("Disconnecting from MQTT broker ...")
            self.client.disconnect()
            self.connected = False        
    

# Simple test code
if __name__ == "__main__":

    try:
        # Create command center MQTT client
        print("Starting Secure Command Center...")
        command_center = CommandCenterMQTT()
        
        # Connect to broker
        if command_center.connect(): 
            print("Command center ready!")

            # Wait 5 seconds for devices to report their status
            print("Waiting for devices to connect ...")
            time.sleep(5)

            # Print discovered devices
            devices = command_center.get_device_list()
            print(f"Discovered {len(devices)} device(s):")
            for device_id, info in devices.items():
                print(f"- {device_id} ({info['type']}): {info['status']}")

            # Send a test command if any device is available
            if devices:
                device_id = list(devices.keys())[0]
                print(f"Sending test command to {device_id}...")
                command_center.send_command(device_id, "read_temperature")

            # Keep the program running
            print("Command center running. Press Ctrl+C to stop...")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("Shutting down command center ...")
                command_center.disconnect()
        else:
            print("Failed to connect to MQTT broker")
    except Exception as e:
        print(f"Error starting command center: {str(e)}")