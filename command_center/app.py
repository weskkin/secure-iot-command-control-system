from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
import os
import json
import time
import threading
import paho.mqtt.client as mqtt
import ssl
from flask_login import (
    LoginManager, 
    UserMixin, 
    login_user, 
    logout_user, 
    login_required, 
    current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from flask_talisman import Talisman
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
import base64
from functools import wraps 
from datetime import datetime
from flask_wtf.csrf import CSRFProtect
import re

ALLOWED_COMMANDS = {
    "temperature_sensor": ["read_temperature", "restart"],
    "security_camera": ["activate", "deactivate", "restart", "status_check"]
}

# Initialize LoginManager
login_manager = LoginManager()
login_manager.login_view = 'login'

# Create Flask Application
app = Flask(__name__)
app.secret_key = 'dev_key_change_this_later'  # We'll make this more secure later
app.config['WTF_CSRF_COOKIE_NAME'] = 'csrf_token'  # Add this line
csrf = CSRFProtect(app)

talisman = Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    content_security_policy={
        'default-src': "'self'",
        'style-src': ["'self'", "'unsafe-inline'"],
        'script-src': ["'self'", "'unsafe-inline'"]
    },
    referrer_policy='strict-origin-when-cross-origin' 
)

login_manager.init_app(app)

# User model
class User(UserMixin):
    def __init__(self, id, username, role="operator"):
        self.id = id
        self.username = username
        self.role = role

# Database setup (SQLite for simplicity)
# Update all sqlite3.connect() calls to use absolute path
DB_PATH = "/home/weskin/Desktop/secure-iot-command-control-system/command_center/users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                (id INTEGER PRIMARY KEY, 
                 username TEXT UNIQUE, 
                 password_hash TEXT,
                 role TEXT,
                 last_login REAL)''')  # Added last_login column
    
    # Add admin with null last_login
    admin_hash = generate_password_hash("secure_admin_password")
    c.execute("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
             ("admin", admin_hash, "admin"))
    
    conn.commit()
    conn.close()

init_db()  # Run once

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    return User(id=user[0], username=user[1], role=user[3]) if user else None

def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return func(*args, **kwargs)
    return decorated_view

class MQTTIntegratedApp:
    def __init__(self):
        # MQTT connection status and devices
        self.mqtt_connected = False
        self.devices = {}
        self.device_certs = {}  # Cache for device public keys
        self.audit_logs = []
        self.max_log_entries = 1000  # Keep last 1000 entries
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

        # Load existing TLS private key for signing
        self.signing_key = self._load_signing_key()

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

    def _load_signing_key(self):
        """Load existing TLS private key (command_center.key.pem)"""
        with open(self.center_key, 'rb') as f:  # self.center_key is already defined
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
    def _get_device_public_key(self, device_id):
        """Get public key from device certificate"""
        if device_id not in self.device_certs:
            cert_path = f"device_certs/device_001.cert.pem" # later change to {device_id}
            with open(cert_path, "rb") as f:
                cert = load_pem_x509_certificate(f.read(), default_backend())
                self.device_certs[device_id] = cert.public_key()
        return self.device_certs[device_id]
    
    def _connect_mqtt(self):
        """Connect to MQTT broker with TLS"""
        print("Setting up MQTT connection...")
        
        try:
            # Create MQTT client with unique ID
            client = mqtt.Client(client_id="flask_command_center", callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
            # For debugging
            client.on_log = lambda client, userdata, level, buf: print("MQTT LOG:", buf)

            # callbacks
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

    def _on_connect(self, client, userdata, flags, rc, properties):
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

    def _on_disconnect(self, client, userdata, rc, flags=None, properties=None):
        """Callback when disconnected from MQTT broker"""
        print("Disconnected from MQTT broker")
        with self.connection_lock:
            self.mqtt_connected = False

    def _on_message(self, client, userdata, msg):
        """Callback when message is received"""
        print(f"Received message on topic {msg.topic}")
    
        try:

            # Get TLS socket through client's low-level socket
            sock = client._sock
            if not isinstance(sock, ssl.SSLSocket):
                print("Not an SSL connection")
                return

            # Get certificate subject
            cert = sock.getpeercert()
            subject = dict(x[0] for x in cert['subject'])
            common_name = subject.get('commonName', 'unknown')

            # Add debug prints HERE
            print(f"Processing message from {common_name}")
            print(f"Raw message content: {msg.payload[:50]}...")  # First 50 chars
            
            # Parse message from JSON
            message_data = json.loads(msg.payload.decode())
            
            # Extract device ID from topic
            topic_parts = msg.topic.split('/')
            if len(topic_parts) < 4:
                print(f"Invalid topic format: {msg.topic}")
                return
            
            device_id = topic_parts[2]
            message_type = topic_parts[3]  # status or results
            
            # Verify digital signature
            signature = base64.b64decode(message_data.pop('signature'))
            public_key = self._get_device_public_key(device_id)
            public_key.verify(
                signature,
                json.dumps(message_data).encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            with self.connection_lock:
                # REPLAY PROTECTION: TIMESTAMP VALIDATION
                message_timestamp = message_data.get("timestamp")
                if not message_timestamp:
                    log_msg = f"Missing timestamp from {device_id}"
                    self.add_audit_log("SECURITY", log_msg, device_id)
                    return

                current_time = time.time()
                if abs(current_time - message_timestamp) > 300:  # 5-minute window
                    log_msg = f"Replay attack detected from {device_id} (Δ={current_time-message_timestamp:.1f}s)"
                    print(f"⚠️ {log_msg}")
                    self.add_audit_log("SECURITY", log_msg, device_id)
                    return
                
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

                    # Add security log for replay rejections
                    if "REJECTED: Replay attack detected" in result:
                        log_msg = f"Replay attack blocked by {device_id} (command: {command})"
                        print(f"🔴 {log_msg}")
                        self.add_audit_log("SECURITY", log_msg, device_id)

        except InvalidSignature:
            log_msg = f"Tampered message from {device_id}! Rejecting."
            print(f"⚠️ {log_msg}")
            self.add_audit_log("SECURITY", log_msg, device_id)
        except KeyError as e:
            log_msg = f"Missing field in message: {str(e)}"
            print(f"❌ {log_msg}")
            self.add_audit_log("ERROR", log_msg, "MQTT")              
        except json.JSONDecodeError:
            log_msg = f"Invalid JSON: {msg.payload.decode()}"
            print(f"❌ {log_msg}")
            self.add_audit_log("ERROR", log_msg, "MQTT")
        except Exception as e:
            log_msg = f"Error processing message: {str(e)}"
            print(f"🔥 {log_msg}")
            self.add_audit_log("ERROR", log_msg, "SYSTEM")

    def send_command(self, device_id, command):
        """Original method with automatic timestamp"""
        return self._send_command_internal(device_id, command, time.time())

    def send_command_with_timestamp(self, device_id, command, custom_timestamp):
        """New method for testing with custom timestamp"""
        return self._send_command_internal(device_id, command, custom_timestamp)

    def _send_command_internal(self, device_id, command, timestamp):
        """Shared implementation between both methods"""
        with self.connection_lock:
            if not self.mqtt_client or not self.mqtt_connected:
                print("MQTT client not connected")
                return False
        
        try:
            command_msg = {
                "command": command,
                "timestamp": timestamp,
                "source": "command_center",
                "message_id": f"cmd_{int(timestamp * 1000000)}"
            }

            # Generate signature
            signature = self.signing_key.sign(
                json.dumps(command_msg).encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Add signature to message
            command_msg['signature'] = base64.b64encode(signature).decode()

            # Publish to device's command topic
            topic = f"iot/devices/{device_id}/commands"
            with self.connection_lock:
                result = self.mqtt_client.publish(topic, json.dumps(command_msg))
            
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                self.add_audit_log("COMMAND", f"Sent {command} to {device_id}", "COMMAND_CENTER")
                print(f"Sent command {command} to device {device_id}")
                return True
            else:
                print(f"Failed to send command. MQTT error code: {result.rc}")
                self.add_audit_log("ERROR", f"Failed to send {command} to {device_id}", "COMMAND_CENTER")
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
            # Remove devices that haven't updated in 300 seconds
            current_time = time.time()
            active_devices = {}
            for device_id, device_info in self.devices.items():
                if current_time - device_info['last_update'] < 300:
                    active_devices[device_id] = device_info
                else:
                    print(f"Device {device_id} timed out")
            
            self.devices = active_devices
            return self.devices.copy()

    def add_audit_log(self, event_type, details, source):
        """Add an entry to the audit log"""
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # Use datetime instead of time
            "event_type": event_type,
            "details": details,
            "source": source
        }
        self.audit_logs.append(log_entry)
        # Keep log size under limit
        if len(self.audit_logs) > self.max_log_entries:
            self.audit_logs.pop(0)

# Create global instance
mqtt_app = MQTTIntegratedApp()

# Route handlers
@app.route('/')
def index():
    return render_template('index.html', mqtt_connected=mqtt_app.get_connection_status())

@app.route('/control')
@login_required
def control():
    return render_template('control.html', devices=mqtt_app.get_devices())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            user_obj = User(id=user[0], username=user[1], role=user[3])
            login_user(user_obj)
            
            # Update last login time
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE users SET last_login = ? WHERE id = ?",
                     (datetime.now().timestamp(), user[0]))
            conn.commit()
            conn.close()
            
            mqtt_app.add_audit_log("AUTH", f"Successful login from {request.remote_addr}", user[1])
            return redirect(url_for('control'))
        else:
            mqtt_app.add_audit_log("AUTH_FAIL", 
                f"Failed login attempt for {username} from {request.remote_addr}", 
                "AUTH"
            )
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                     (username, password))
            conn.commit()
            conn.close()
            flash('Registration successful!')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@admin_required
def admin_panel():
    # Get active users (users logged in within last 15 minutes)
    active_users = 0
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users WHERE last_login > ?", 
             (datetime.now().timestamp() - 900,))
    active_users = c.fetchone()[0]
    conn.close()

    # Format timestamps for display
    formatted_logs = []
    for log in mqtt_app.audit_logs[-50:]:  # Last 50 entries
        formatted = log.copy()
        formatted["timestamp"] = datetime.strptime(
            log["timestamp"], "%Y-%m-%d %H:%M:%S"
        ).strftime("%H:%M:%S")  # Show only time
        formatted_logs.append(formatted)
    
    return render_template('admin.html',
                         devices=mqtt_app.get_devices(),
                         active_users=active_users,
                         logs=formatted_logs) 

@app.route('/api/send_command', methods=['POST'])
def send_command():
    device_id = request.form.get("device_id")
    command = request.form.get("command")

    if not device_id or not command:
        return jsonify({"status": "error", "message": "Missing device_id or command"}), 400
    
    # Validate device ID format
    if not re.match(r'^dev\d{3}$', device_id):
        mqtt_app.add_audit_log("VALIDATION", 
            f"Invalid device ID format: {device_id}", 
            request.remote_addr)
        return jsonify({"status": "error", "message": "Invalid device ID format"}), 400
    
    # ===== NEW COMMAND VALIDATION =====
    # Get device info from registry
    device_info = mqtt_app.get_devices().get(device_id)
    if not device_info:
        mqtt_app.add_audit_log("VALIDATION",
            f"Unknown device: {device_id}",
            current_user.username if current_user.is_authenticated else "ANONYMOUS")
        return jsonify({"status": "error", "message": "Device not registered"}), 404

    # Validate command against device type
    device_type = device_info.get('type')
    allowed = ALLOWED_COMMANDS.get(device_type, [])
    
    if command not in allowed:
        mqtt_app.add_audit_log("VALIDATION",
            f"Invalid command '{command}' for {device_id} ({device_type})",
            current_user.username if current_user.is_authenticated else "ANONYMOUS")
        return jsonify({"status": "error", "message": "Command not allowed for this device type"}), 400
    # ===== END OF VALIDATION =====

    # Send command via MQTT
    success = mqtt_app.send_command(device_id, command)
    
    if success:
        return jsonify({"status": "success", "message": f"Command '{command}' sent to device {device_id}"})
    else:
        return jsonify({"status": "error", "message": "Failed to send command"}), 500

@app.route('/api/send_replay', methods=['POST'])
@admin_required
def send_replay_command():
    try:
        device_id = request.form.get("device_id")
        command = request.form.get("command")
        timestamp = float(request.form.get("timestamp"))
        
        # Validate device ID format
        if not re.match(r'^dev\d{3}$', device_id):
            mqtt_app.add_audit_log("VALIDATION", 
                f"Invalid device ID format: {device_id}", 
                request.remote_addr)
            return jsonify({"status": "error", "message": "Invalid device ID format"}), 400
        
        success = mqtt_app.send_command_with_timestamp(device_id, command, timestamp)
        
        if success:
            return jsonify({"status": "success", "message": "Replay test command sent"})
        else:
            return jsonify({"status": "error", "message": "Failed to send replay"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    
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

    ssl_context = (
        '/home/weskin/Desktop/secure-iot-command-control-system/certificates/ca/intermediate/certs/flask-web-chain.cert.pem',  # Certificate chain (server + intermediate + root)
        '/home/weskin/Desktop/secure-iot-command-control-system/certificates/ca/intermediate/private/flask-web.key.pem',   # Private key
    )

    print("Starting Flask application with integrated MQTT...")
    print("MQTT connection will be established in background")
    print("Access the web interface at http://localhost:5000")

    app.run(host="localhost", port=5000, debug=True, ssl_context=ssl_context, use_reloader=False)  # Disable reloader to prevent MQTT issues