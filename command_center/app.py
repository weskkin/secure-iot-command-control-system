from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from pathlib import Path
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
from dotenv import load_dotenv
import pyotp
import qrcode
import secrets
from OpenSSL import SSL  
from service_identity import pyopenssl

load_dotenv()  # Load .env file

ALLOWED_COMMANDS = {
    "temperature_sensor": ["read_temperature", "restart"],
    "security_camera": ["activate", "deactivate", "restart", "status_check"]
}

# Initialize LoginManager
login_manager = LoginManager()
login_manager.login_view = 'login'

# Create Flask Application
app = Flask(__name__, 
           static_folder='static',
           template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY')
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

def validate_password(password):
    """Enforce strong password policy
    - 12+ chars
    - 1 uppercase
    - 1 lowercase
    - 1 digit
    - 1 special char
    """
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    if not re.search(r'[A-Z]', password):
        raise ValueError("Password needs at least 1 uppercase letter")
    if not re.search(r'[a-z]', password):
        raise ValueError("Password needs at least 1 lowercase letter")
    if not re.search(r'\d', password):
        raise ValueError("Password needs at least 1 digit")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValueError("Password needs at least 1 special character")
    
# User model
class User(UserMixin):
    def __init__(self, id, username, role, totp_secret=None, 
                 mfa_enabled=False, backup_codes='[]'):
        self.id = id
        self.username = username
        self.role = role
        self.totp_secret = totp_secret
        self.mfa_enabled = mfa_enabled
        self.backup_codes = backup_codes

    def verify_totp(self, code):
        return pyotp.TOTP(self.totp_secret).verify(code, valid_window=1)
    
    def generate_backup_codes(self):
        # Generate 8-character codes (without hyphens)
        raw_codes = [secrets.token_hex(4) for _ in range(5)]  # 4 bytes = 8 chars
        
        # Hash codes for storage
        hashed_codes = [generate_password_hash(code) for code in raw_codes]
        self.backup_codes = json.dumps(hashed_codes)
        
        # Return formatted codes WITH hyphens for user display only
        return [f"{code[:4]}-{code[4:]}" for code in raw_codes]
    
    def check_backup_code(self, code):
        # Remove hyphens and normalize
        sanitized = code.replace("-", "").strip().lower()
        
        # Validate format
        if len(sanitized) != 8 or not re.match(r'^[a-f0-9]{8}$', sanitized):
            return False
        
        # Check against stored HASHES
        try:
            stored_hashes = json.loads(self.backup_codes or '[]')
            return any(check_password_hash(h, sanitized) for h in stored_hashes)
        except:
            return False

# Database setup (SQLite for simplicity)
# Get absolute path to THIS file (app.py)
current_dir = os.path.dirname(os.path.abspath(__file__))

# DB will always be in command_center/
DB_PATH = os.path.join(current_dir, "users.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users 
        (
            id INTEGER PRIMARY KEY, 
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT NOT NULL DEFAULT 'operator',
            last_login REAL,
            totp_secret TEXT DEFAULT '',
            mfa_enabled BOOLEAN DEFAULT 0,
            backup_codes TEXT DEFAULT '[]'
        )
    ''')
    
    # Add admin user if not exists
    admin_hash = generate_password_hash("secure_admin_password")
    c.execute('''
        INSERT OR IGNORE INTO users 
        (username, password_hash, role) 
        VALUES (?, ?, ?)
    ''', ("admin", admin_hash, "admin"))
    
    conn.commit()
    conn.close()

init_db()  # Run once

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, role, totp_secret, mfa_enabled, backup_codes FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return User(
            id=user_data[0],
            username=user_data[1],
            role=user_data[2],
            totp_secret=user_data[3],
            mfa_enabled=bool(user_data[4]),
            backup_codes=user_data[5]
        )
    return None

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
        # Get project root path
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        self.ca_cert = os.path.join(self.project_root, "certificates/ca/intermediate/certs/ca-chain.cert.pem")
        self.center_cert = os.path.join(self.project_root, "certificates/ca/intermediate/certs/client-chain.cert.pem")
        self.center_key = os.path.join(self.project_root, "certificates/ca/intermediate/private/command_center.key.pem")
        self.crl = os.path.join(self.project_root, "certificates/crl/intermediate.crl.pem")

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
            # Path to device simulator certificates
            cert_path = os.path.join(
                self.project_root,
                "device_simulator/device_certs/device_001-chain.cert.pem"
            )
            if not os.path.exists(cert_path):
                raise FileNotFoundError(f"Device certificate not found: {cert_path}")
                
            with open(cert_path, "rb") as f:
                cert = load_pem_x509_certificate(f.read(), default_backend())
                self.device_certs[device_id] = cert.public_key()
        return self.device_certs[device_id]
    
    def _connect_mqtt(self):
        """Connect to MQTT broker with TLS"""
        print("Setting up MQTT connection...")
        
        try:
            # TEMPORARY WORKAROUND - Remove CRL checks
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_verify_locations(self.ca_cert)
            context.load_cert_chain(self.center_cert, self.center_key)

            client = mqtt.Client(client_id="flask_command_center", 
                               callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
            
            # Configure TLS without CRL
            client.tls_set_context(context)
            
            # Keep existing callbacks
            client.on_log = lambda client, userdata, level, buf: print("MQTT LOG:", buf)
            client.on_connect = self._on_connect
            client.on_message = self._on_message
            client.on_disconnect = self._on_disconnect

            print("Connecting to MQTT broker on port 8883 with TLS 1.3 ...")
            client.connect("localhost", 8883, 60)
            
            with self.connection_lock:
                self.mqtt_client = client
            
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
                if abs(current_time - message_timestamp) > 30:  # 30-second window
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
        print(f"Adding audit log: {log_entry}")
        self.audit_logs.append(log_entry)
        # Keep log size under limit
        if len(self.audit_logs) > self.max_log_entries:
            self.audit_logs.pop(0)

    def _verify_callback(self, conn, cert, errnum, depth, ok):
        """Custom certificate verification callback"""
        if not ok:
            print(f"Certificate verification failed: {cert.get_subject()}")
        return ok
    
# Create global instance
mqtt_app = MQTTIntegratedApp()

# Route handlers
@app.route('/')
def index():
    return render_template('index.html', mqtt_connected=mqtt_app.get_connection_status())

@app.route('/control')
@login_required
def control():
    print(f"★ Current User: {current_user.id}, Authenticated: {current_user.is_authenticated}")
    return render_template('control.html', devices=mqtt_app.get_devices())

limiter = Limiter(app=app, key_func=get_remote_address, storage_uri="memory://")

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per 5 minutes")  # 20 attempts every 5 minutes
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # Get ALL user fields needed for User object
        c.execute("""
            SELECT id, username, password_hash, role, 
                   totp_secret, mfa_enabled, backup_codes 
            FROM users WHERE username = ?
        """, (username,))
        user_data = c.fetchone()
        conn.close()
        
        if user_data and check_password_hash(user_data[2], password):
            # Create PROPER User object with all fields
            user_obj = User(
                id=user_data[0],
                username=user_data[1],
                role=user_data[3],
                totp_secret=user_data[4],
                mfa_enabled=bool(user_data[5]),
                backup_codes=user_data[6]
            )
            
            # Check MFA on the User OBJECT
            if user_obj.mfa_enabled:
                session['mfa_pending_user'] = user_obj.id
                return redirect(url_for('verify_login'))
            
            login_user(user_obj)
            
            # Update last login time
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE users SET last_login = ? WHERE id = ?",
                    (datetime.now().timestamp(), user_data[0]))
            conn.commit()
            conn.close()
            
            mqtt_app.add_audit_log("AUTH", f"Successful login from {request.remote_addr}", user_data[1])
            return redirect(url_for('control'))
        else:
            mqtt_app.add_audit_log("AUTH_FAIL", 
                f"Failed login attempt for {username} from {request.remote_addr}", 
                "AUTH"
            )
            flash('Invalid credentials')
    return render_template('login.html')

# Enable MFA Page
@app.route('/enable-mfa')
@login_required
def enable_mfa():
    if not current_user.totp_secret:
        current_user.totp_secret = pyotp.random_base32()
        # Update database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE users SET totp_secret = ? WHERE id = ?",
                 (current_user.totp_secret, current_user.id))
        conn.commit()
        conn.close()
    
    # Generate provisioning URI
    totp_uri = pyotp.totp.TOTP(current_user.totp_secret).provisioning_uri(
        name=current_user.username,
        issuer_name="IoT Command Center"
    )
    
    # Generate QR code
    img = qrcode.make(totp_uri)
    project_root = Path(__file__).parent.absolute()
    static_dir = project_root / "static"
    static_dir.mkdir(exist_ok=True, parents=True)  # Create directory if needed
    qr_path = static_dir / "mfa_qr.png"
    img.save(qr_path)
    
    return render_template('enable_mfa.html')

# Verify MFA Setup
@app.route('/verify-mfa', methods=['POST'])
@login_required
def verify_mfa():
    code = request.form.get('code')
    if current_user.verify_totp(code):
        # Update database to enable MFA
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            UPDATE users 
            SET mfa_enabled = 1 
            WHERE id = ?
        """, (current_user.id,))
        
        # Generate and store backup codes
        backup_codes = current_user.generate_backup_codes()
        c.execute("UPDATE users SET backup_codes = ? WHERE id = ?",
                (current_user.backup_codes, current_user.id))
        conn.commit()
        conn.close()
        
        flash('MFA enabled successfully!')
        return render_template('backup_codes.html', codes=backup_codes)
    
    flash('Invalid verification code')
    return redirect(url_for('enable_mfa'))

# MFA Login Verification
@app.route('/verify-login', methods=['GET', 'POST'])
def verify_login():
    if request.method == 'POST':
        user_id = session.get('mfa_pending_user')
        if not user_id:
            return redirect(url_for('login'))
        
        user = load_user(user_id)
        code = request.form.get('code')
        
        if user.verify_totp(code) or user.verify_backup_code(code):
            login_user(user)
            session.pop('mfa_pending_user')
            return redirect(url_for('control'))
        
        flash('Invalid code')
    return render_template('verify_mfa.html')

@app.route('/recovery', methods=['GET', 'POST'])
@limiter.limit("20 per 10 minutes")
def recovery():
    if request.method == 'POST':
        code = request.form.get('code')
        user_id = session.get('mfa_pending_user')
        
        if not user_id:
            flash('Session expired. Please login again.')
            return redirect(url_for('login'))
        
        # Load user from database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT id, username, role, backup_codes 
            FROM users WHERE id = ?
        """, (user_id,))
        user_data = c.fetchone()
        conn.close()
        
        if user_data:
            user = User(
                id=user_data[0],
                username=user_data[1],
                role=user_data[2],
                backup_codes=user_data[3]
            )
            
            if user.check_backup_code(code):
                login_user(user)
                session.pop('mfa_pending_user', None)
                mqtt_app.add_audit_log("AUTH", "Backup code used", user.username)
                return redirect(url_for('control'))
            
        flash('Invalid backup code')
        return redirect(url_for('recovery'))
    
    # GET request - show backup code entry form
    return render_template('recovery.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        errors = []
        if len(password) < 12:
            errors.append("Password must be at least 12 characters")
        if not re.search(r'[A-Z]', password):
            errors.append("Password needs at least 1 uppercase letter")
        if not re.search(r'[a-z]', password):
            errors.append("Password needs at least 1 lowercase letter")
        if not re.search(r'\d', password):
            errors.append("Password needs at least 1 digit")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password needs at least 1 special character")

        if errors:
            for error in errors:
                flash(error)
            return redirect(url_for('register'))
        
        password_hash = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                     (username, password_hash, "operator"))
            
            conn.commit()

            # Verify insertion
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            print(f"★ Database User: {user}")  # Should show role='operator'   

            # Create user object and log them in
            user_obj = User(id=user[0], username=user[1], role=user[3])
            login_user(user_obj)
            print(f"★ Registered User: ID={user_obj.id}, Role={user_obj.role}")
            
            # Update audit logs
            mqtt_app.add_audit_log("AUTH", f"New registration: {username}", "SYSTEM")
            
            flash('Registration successful!')
            return redirect(url_for('control'))  # Changed from login to control
            
        except sqlite3.IntegrityError:
            flash('Username already exists')
        finally:
            conn.close()
            
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
    if not re.match(r'^device_\d{3}$', device_id):
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
        if not re.match(r'^device_\d{3}$', device_id):
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
    # Get project root path (command_center's parent directory)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Create SSL context for TLS 1.3
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Load certificate chain and key
    ssl_context.load_cert_chain(
        os.path.join(project_root, "certificates/ca/intermediate/certs/flask-web-chain.cert.pem"),
        os.path.join(project_root, "certificates/ca/intermediate/private/flask-web.key.pem")
    )

    print("Starting Flask application with integrated MQTT using TLS 1.3 ...")
    print(f"SSL Context: {ssl_context}")
    app.run(host="localhost", port=5000, debug=True, ssl_context=ssl_context, use_reloader=False)