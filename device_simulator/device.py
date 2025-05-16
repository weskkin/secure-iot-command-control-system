import time
import random
import paho.mqtt.client as mqtt 
import json

class IoTDevice:
    def __init__(self, device_id, device_type):
        self.device_id = device_id
        self.device_type = device_type
        self.status = 'offline'
        self.mqtt_client = None # Placeholder for MQTT client instance
        print(f"Device {device_id} ({device_type}) initialized  ")

    def on_connect(self, client, userdata, flags, rc):
        """Callback when connected to MQTT broker"""
        print(f"Device {self.device_id} connected to MQTT broker with result code {rc}") #Connection status

        # Subscribe to a topic to receive commands (e.g., "iot/devices/dev001/commands")
        command_topic = f"iot/devices/{self.device_id}/commands"
        client.subscribe(command_topic) # Subscribe to the topic
        print(f"Subscribed to {command_topic}") #Confirmation

        self.status = "online" # Update device status

        # Publish a JSON status message to the broker (e.g., "iot/devices/dev001/status")
        status_msg = json.dumps({
            "device_id": self.device_id,
            "type": self.device_type,
            "status": self.status,
            "timestamp": time.time() # Current Unix timestamp
        })

        client.publish(f"iot/devices/{self.device_id}/status", status_msg) # Send message

    def on_message(self, client, userdata, msg):
        """Callback when message is received"""
        print(f"Device {self.device_id} received message on topic {msg.topic}")

        try:
            # Parse incoming JSON payload
            command_data = json.loads(msg.payload.decode())
            command = command_data.get('command') # Extract command field

            if not command: # Handle missing command field
                print("Received message with no command field")
                return
            
            print(f"Processing command: {command}") # Log the command

            # Execute the command (e.g., read a sensor)
            result = self.process_command(command) # Call processing logic

            # Publish the result to a results topic (e.g., "iot/devices/dev001/results")
            result_msg = json.dumps({
                "device_id": self.device_id,
                "command": command,
                "result": result,
                "timestamp": time.time()
            })

            client.publish(f"iot/devices/{self.device_id}/results", result_msg) # Send result
        except json.JSONDecodeError: # Invalid JSON
            print(f"Received invalid JSON: {msg.payload.decode()}")
        except Exception as e: # Generic Errors
            print(f"Error processing message: {str(e)}")
    
    def connect(self):
        """Connect to the control system"""
        print(f"Device {self.device_id} connecting to MQTT broker ...")

        # Create an MQTT client instance with a unique ID
        client = mqtt.Client(client_id=f"device_{self.device_id}")
        # Assign callback functions
        client.on_connect = self.on_connect
        client.on_message = self.on_message

        # Connect to the broker running on localhost at port 1883 (default MQTT port)
        client.connect("localhost", 1883, 60)

        self.mqtt_client = client # Store the client instance
        
        return client

    def process_command(self, command):
        """Process a command from the command center"""
        print(f"Device {self.device_id} received command: {command}")

        # Simulate processing time
        time.sleep(1)

        # Simulate 90% success rate (random.random() returns 0.0-1.0)
        success = random.random() > 0.1 #90% success rate

        if success:
            print(f"Device {self.device_id} successfully executed command: {command}")
            return {"status": "success", "message": f"Command {command} executed"}
        else:
            print(f"Device {self.device_id} failed to execute command: {command}")
            return {"status": "error", "message": f"Command execution failed"}
        

#Simple test code
if __name__ == "__main__":
    # Create a test device
    device = IoTDevice("dev001", "temperature_sensor")

    # Connect to MQTT broker and get the client instance
    client = device.connect()

    try: 
        # Start an infinite MQTT loop to listen for messages
        client.loop_forever() # Blocks here until interrupted

    # Handle Ctrl+C (KeyboardInterrupt) for graceful shutdown
    except KeyboardInterrupt:
        print("Shutting down device ...")

        # Publish "offline" status before disconnecting
        status_msg = json.dumps({
            "device_id": device.device_id,
            "status": "offline",
            "type": device.device_type,
            "timestamp": time.time()
        })

        client.publish(f"iot/devices/{device.device_id}/status", status_msg)

        client.disconnect() # Disconnect from the broker