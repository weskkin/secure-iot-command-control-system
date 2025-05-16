from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
from mqtt_client import CommandCenterMQTT

# Create Flask Application
app = Flask(__name__)
app.secret_key = 'dev_key_change_this_later' #We'll make this more secure later

# Create MQTT client
mqtt_client = CommandCenterMQTT()
mqtt_connected = mqtt_client.connect()

# Route for home page
@app.route('/')
def index():
    return render_template('index.html', mqtt_connected=mqtt_connected)

# Route for device control page 
@app.route('/control')
def control():
    devices = mqtt_client.get_device_list()
    return render_template('control.html', devices=devices)

# API route to send command to device
@app.route('/api/send_command', methods=['POST'])
def send_command():
    device_id = request.form.get("device_id")
    command = request.form.get("command")

    if not device_id or not command:
        return jsonify({"status": "error", "message": "Missing device_id or command"}), 400
    
    success = mqtt_client.send_command(device_id, command)

    if success:
        return jsonify({"status": "success", "message": f"Command '{command}' sent to device {device_id}"})
    else:
        return jsonify({"status": "error", "message": "Failed to send command"}), 500

# API route to get device list
@app.route('/api/devices')
def get_devices():
    devices = mqtt_client.get_device_list()
    return jsonify({"status": "success", "devices": devices})

# Start the application
if __name__ == '__main__':
    app.run(debug=True) #Enables auto-reloading and an interactive debugger if errors occur.