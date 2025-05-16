import json
import time
import paho.mqtt.client as mqtt
import threading

class CommandCenterMQTT:
    def __init__(self):
        self.client = None
        self.connected = False
        self.devices = {} # To store device statuses

    def on_connect(self, client, userdata, flags, rc):
        """Callback when connected to MQTT broker"""
        print(f"Command center connected to MQTT broker with result code {rc}")
        self.connected = True

        # Subscribe to device status updates
        client.subscribe("iot/devices/+/status")

        # Subscribe to command results
        client.subscribe("iot/devices/+/results")

    def on_message(self, client, userdata, msg):  # Fixed parameter name from 'userdaa' to 'userdata'
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
        print("Command center connecting to MQTT broker ...")

        # Create MQTT client
        client = mqtt.Client(client_id="command_center")
        client.on_connect = self.on_connect
        client.on_message = self.on_message

        # Connect to broker
        client.connect("localhost", 1883, 60)

        self.client = client

        # Start MQTT client in a background thread
        mqtt_thread = threading.Thread(target=client.loop_forever)
        mqtt_thread.daemon = True  # Thread dies when main program exits
        mqtt_thread.start()

        # Wait up to 5 seconds for connection confirmation
        count = 0
        while not self.connected and count < 10:
            time.sleep(0.5)
            count += 1
            
        return self.connected # True if connected, False otherwise
    
    def send_command(self, device_id, command):
        """Send a command to a device"""

        if not self.client or not self.connected:
            print("MQTT client not connected")
            return False
        
        # Create JSON command message
        command_msg = json.dumps({
            "command": command,
            "timestamp": time.time()
        })

        # Publish to device's command topic (e.g., iot/devices/dev001/commands)
        topic = f"iot/devices/{device_id}/commands"
        self.client.publish(topic, command_msg)
        print(f"Sent command {command} to device {device_id}")
        
        return True
    
    def get_device_list(self):
        """Return list of known devices and their statuses"""
        return self.devices  # Dictionary of devices
    

# Simple test code
if __name__ == "__main__":
    
    # Create command center MQTT client
    command_center = CommandCenterMQTT()
    command_center.connect() # Connect to broker

    # Wait 5 seconds for devices to report their status
    print("Waiting for devices to connect ...")
    time.sleep(5)

    # Print discovered devices
    devices = command_center.get_device_list()
    print(f"Discovered {len(devices)} device:")
    for device_id, info in devices.items():
        print(f"- {device_id} ({info['type']}): {info['status']}")

    # Send a test command if any device is available
    if devices:
        device_id = list(devices.keys())[0]
        command_center.send_command(device_id, "read_temperature")

    # Keep the program running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down command center ...")