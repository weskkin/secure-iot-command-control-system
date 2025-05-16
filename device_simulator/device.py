import time
import random

class IoTDevice:
    def __init__(self, device_id, device_type):
        self.device_id = device_id
        self.device_type = device_type
        self.status = 'offline'
        print(f"Device {device_id} ({device_type}) initialized  ")

    def connect(self):
        """Connect to the control system"""
        print(f"Device {self.device_id} connecting ...")
        self.status = 'online'
        print(f"Device {self.device_id} connected")

    def process_command(self, command):
        """Process a command from the command center"""
        print(f"Device {self.device_id} received command: {command}")

        # Simulate processing time
        time.sleep(1)

        # Simulate success / failure
        success = random.random() > 0.1 #90% success rate

        if success:
            print(f"Device {self.device_id} successfully executed command: {command}")
            return {"status": "success", "message": f"Command {command} executed"}
        else:
            print(f"Device {self.device_id} failed to execute command: {command}")
            return {"status": "error", "message": f"Command execution failed"}
        

#Simple test code
if __name__ == "__main__":
    #Create a test device
    device = IoTDevice("dev001", "temperature_sensor")
    device.connect()

    #Test some commands
    device.process_command("read_temperature")
    device.process_command("calibrate")