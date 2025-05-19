from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import json
import time
import threading
import paho.mqtt.client as mqtt
import ssl

# Create Flask Application
app = Flask(__name__)
app.secret_key = 'dev_key_change_this_later'  # We'll make this more secure later

class MQTTIntegratedApp:
    def __init__(self):
        # MQTT connection status and devices
        self.mqtt_connected = False
        self.devices = {}
        self.mqtt_client = None
        self.connection_lock = threading.Lock()
        
        # TLS certificate paths
        self.ca_cert = "/home/weskin/Desktop/secure-iot-command-control-system/certificates/ca/certs/ca.cert.pem"
        self.center_cert = "/home/weskin/Desktop/secure-iot-command-control-system/certificates/ca/intermediate/certs/client-chain.cert.pem"
        self.center_key = "/home/weskin/Desktop/secure-iot-command-control-system/certificates/ca/intermediate/private/command_center.key.pem"
        
        # Verify certificate files exist
        self._verify_certificates()
        
        # Initialize MQTT connection in background
        self._setup_mqtt()

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

    def _setup_mqtt(self):
        """Set up MQTT client and connect in background thread"""
        mqtt_thread = threading.Thread(target=self._connect_mqtt, daemon=True)
        mqtt_thread.start()

    def _connect_mqtt(self):
        """Connect to MQTT broker with TLS"""
        print("Setting up MQTT connection...")
        
        try:
            # Create MQTT client with unique ID
            client = mqtt.Client(client_id="flask_command_center")
            client.on_connect = self._on_connect
            client.on_message = self._on_message
            client.on_disconnect = self._on_disconnect
            
            # Configure TLS/SSL
            print("Configuring TLS certificates...")
            client.tls_set(
                ca_certs=self.ca_cert,
                certfile=self.center_cert,
                keyfile=self.center_key,
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLSv1_2,
                ciphers='DEFAULT@SECLEVEL=1'
            )
            
            # Set TLS options
            client.tls_insecure_set(False)
            
            # Connect to broker
            print("Connecting to MQTT broker on port 8883...")
            client.connect("localhost", 8883, 60)
            
            # Store client reference
            with self.connection_lock:
                self.mqtt_client = client
            
            # Start MQTT loop
            client.loop_forever()
            
        except Exception as e:
            print(f"Error setting up MQTT connection: {str(e)}")
            with self.connection_lock:
                self.mqtt_connected = False

    def _on_connect(self, client, userdata, flags, rc):
        """Callback when connected to MQTT broker"""
        if rc == 0:
            print("Flask app connected to MQTT broker securely")
            with self.connection_lock:
                self.mqtt_connected = True
            
            # Subscribe to device status updates
            client.subscribe("iot/devices/+/status")
            print("Subscribed to device status updates")
            
            # Subscribe to command results
            client.subscribe("iot/devices/+/results")
            print("Subscribed to command results")
        else:
            print(f"Failed to connect to MQTT broker. Return code: {rc}")
            with self.connection_lock:
                self.mqtt_connected = False

    def _on_disconnect(self, client, userdata, rc):
        """Callback when disconnected from MQTT broker"""
        print("Disconnected from MQTT broker")
        with self.connection_lock:
            self.mqtt_connected = False

    def _on_message(self, client, userdata, msg):
        """Callback when message is received"""
        print(f"Received message on topic {msg.topic}")
        
        try:
            # Parse message from JSON
            message_data = json.loads(msg.payload.decode())
            
            # Extract device ID from topic
            topic_parts = msg.topic.split('/')
            if len(topic_parts) < 4:
                print(f"Invalid topic format: {msg.topic}")
                return
            
            device_id = topic_parts[2]
            message_type = topic_parts[3]  # status or results
            
            with self.connection_lock:
                if message_type == "status":
                    # Update device registry with status
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

    def send_command(self, device_id, command):
        """Send a command to a device"""
        with self.connection_lock:
            if not self.mqtt_client or not self.mqtt_connected:
                print("MQTT client not connected")
                return False
        
        try:
            # Create JSON command message
            command_msg = json.dumps({
                "command": command,
                "timestamp": time.time(),
                "source": "flask_command_center",
                "message_id": f"cmd_{int(time.time() * 1000000)}"
            })
            
            # Publish to device's command topic
            topic = f"iot/devices/{device_id}/commands"
            with self.connection_lock:
                result = self.mqtt_client.publish(topic, command_msg)
            
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                print(f"Sent command {command} to device {device_id}")
                return True
            else:
                print(f"Failed to send command. MQTT error code: {result.rc}")
                return False
        except Exception as e:
            print(f"Error sending command: {str(e)}")
            return False

    def get_connection_status(self):
        """Get current MQTT connection status"""
        with self.connection_lock:
            return self.mqtt_connected

    def get_devices(self):
        """Get current device list"""
        with self.connection_lock:
            # Remove devices that haven't updated in 30 seconds
            current_time = time.time()
            active_devices = {}
            for device_id, device_info in self.devices.items():
                if current_time - device_info['last_update'] < 30:
                    active_devices[device_id] = device_info
                else:
                    print(f"Device {device_id} timed out")
            
            self.devices = active_devices
            return self.devices.copy()

# Create global instance
mqtt_app = MQTTIntegratedApp()

# Route handlers
@app.route('/')
def index():
    return render_template('index.html', mqtt_connected=mqtt_app.get_connection_status())

@app.route('/control')
def control():
    return render_template('control.html', devices=mqtt_app.get_devices())

@app.route('/api/send_command', methods=['POST'])
def send_command():
    device_id = request.form.get("device_id")
    command = request.form.get("command")

    if not device_id or not command:
        return jsonify({"status": "error", "message": "Missing device_id or command"}), 400
    
    # Send command via MQTT
    success = mqtt_app.send_command(device_id, command)
    
    if success:
        return jsonify({"status": "success", "message": f"Command '{command}' sent to device {device_id}"})
    else:
        return jsonify({"status": "error", "message": "Failed to send command"}), 500

@app.route('/api/devices')
def get_devices():
    return jsonify({"status": "success", "devices": mqtt_app.get_devices()})

@app.route('/api/status')
def get_status():
    return jsonify({
        "mqtt_connected": mqtt_app.get_connection_status(),
        "device_count": len(mqtt_app.get_devices())
    })

# Start the application
if __name__ == '__main__':
    print("Starting Flask application with integrated MQTT...")
    print("MQTT connection will be established in background")
    print("Access the web interface at http://localhost:5000")
    app.run(debug=True, port=5000, use_reloader=False)  # Disable reloader to prevent MQTT issues