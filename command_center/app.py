from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os, json, time, threading, ssl, sqlite3, re, hashlib
from pathlib import Path
import paho.mqtt.client as mqtt
from datetime import datetime, timedelta
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash

# Cryptography primitives for signing / verifying messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
import base64, pyotp, qrcode, secrets
from functools import wraps 

# Sets up audit DB
from audit_db import init_audit_db

# Load .env file
from dotenv import load_dotenv
load_dotenv()  

# Define role hierarchy
ROLES = {
    "viewer": 1,
    "operator": 2,
    "admin": 3
}

VALID_ROLES = ["viewer", "operator", "admin"]

ALLOWED_COMMANDS = {
    "temperature_sensor": ["read_temperature", "restart", "status_check"],
    "security_camera": ["activate", "deactivate", "restart", "status_check"]
}

# Initialize LoginManager
login_manager = LoginManager()
login_manager.login_view = 'login'

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Session signing

csrf = CSRFProtect(app)

# Session Security Configuration
app.config.update(
    SESSION_COOKIE_NAME='__Secure-session',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_REFRESH_EACH_REQUEST=True,
    SESSION_COOKIE_REFRESH_EACH_REQUEST=False
)

talisman = Talisman(
    app,
    content_security_policy={
        'default-src': "'self'",
        'style-src': ["'self'", "'unsafe-inline'"],
        'script-src': [
            "'strict-dynamic'",
            "'unsafe-hashes'"  # NEW: Allow hashed event handlers
        ],
        'frame-ancestors': "'none'"
    },
    content_security_policy_nonce_in=['script-src'],
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True,
    frame_options='DENY',
    referrer_policy='strict-origin-when-cross-origin',
    # feature_policy={
    #     'geolocation': "'none'",
    #     'camera': "'none'"
    # }
    permissions_policy={
        'geolocation': '()',
        'camera': '()'
    }
)

# Initialize Flask-Login with secure settings
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"  # Basic/strong/None

@app.after_request
def set_additional_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

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
                 mfa_enabled=False, backup_codes='[]',
                 first_name=None, last_name=None, email=None, sector=None):
        
        # Validate role during initialization
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role: {role}")
        
        self.id = id
        self.username = username
        self.role = role
        self.totp_secret = totp_secret
        self.mfa_enabled = mfa_enabled
        self.backup_codes = backup_codes
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.sector = sector

    def has_permission(self, required_role):
        """Check if user's role meets minimum required level"""
        return ROLES[self.role] >= ROLES[required_role]
    
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
AUDIT_DB_PATH = init_audit_db()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users 
        (
            id INTEGER PRIMARY KEY, 
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            sector TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('viewer', 'operator', 'admin')),
            last_login REAL,
            totp_secret TEXT DEFAULT '',
            mfa_enabled BOOLEAN DEFAULT 0,
            backup_codes TEXT DEFAULT '[]'
        )
    ''')
    
    # Add admin user if not exists
    c.execute('''
        INSERT OR IGNORE INTO users 
        (first_name, last_name, email, username, sector, password_hash, role) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', ("Admin", "Admin", "admin@example.com", "admin", "Administration", 
          generate_password_hash(os.getenv('ADMIN_PWD')), "admin"))
    
    conn.commit()
    conn.close()

init_db()  # Run once

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT id, username, role, totp_secret, mfa_enabled, backup_codes,
               first_name, last_name, email, sector 
        FROM users WHERE id = ?
    """, (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return User(
            id=user_data[0],
            username=user_data[1],
            role=user_data[2],
            totp_secret=user_data[3],
            mfa_enabled=bool(user_data[4]),
            backup_codes=user_data[5],
            first_name=user_data[6],
            last_name=user_data[7],
            email=user_data[8],
            sector=user_data[9]
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

        self.audit_db_path = AUDIT_DB_PATH
        self.log_lock = threading.Lock()

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
                    self.add_audit_log("SECURITY", log_msg, device_id, user_id=None)
                    return

                current_time = time.time()
                if abs(current_time - message_timestamp) > 30:  # 30-second window
                    log_msg = f"Replay attack detected from {device_id} (Δ={current_time-message_timestamp:.1f}s)"
                    print(f"⚠️ {log_msg}")
                    self.add_audit_log("SECURITY", log_msg, device_id, user_id=None)
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
                        self.add_audit_log("SECURITY", log_msg, device_id, user_id=None)

        except InvalidSignature:
            log_msg = f"Tampered message from {device_id}! Rejecting."
            print(f"⚠️ {log_msg}")
            self.add_audit_log("SECURITY", log_msg, device_id, user_id=None)
        except KeyError as e:
            log_msg = f"Missing field in message: {str(e)}"
            print(f"❌ {log_msg}")
            self.add_audit_log("ERROR", log_msg, "MQTT", user_id=None)              
        except json.JSONDecodeError:
            log_msg = f"Invalid JSON: {msg.payload.decode()}"
            print(f"❌ {log_msg}")
            self.add_audit_log("ERROR", log_msg, "MQTT", user_id=None)
        except Exception as e:
            log_msg = f"Error processing message: {str(e)}"
            print(f"🔥 {log_msg}")
            self.add_audit_log("ERROR", log_msg, "SYSTEM", user_id=None)

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
                self.add_audit_log("COMMAND", f"Sent {command} to {device_id}", "COMMAND_CENTER", user_id=None)
                print(f"Sent command {command} to device {device_id}")
                return True
            else:
                print(f"Failed to send command. MQTT error code: {result.rc}")
                self.add_audit_log("ERROR", f"Failed to send {command} to {device_id}", "COMMAND_CENTER", user_id=None)
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

    def add_audit_log(self, event_type, details, source, user_id):
        """Add an entry to the audit log with integrity protection"""
        sanitized_details = details.replace('\n', ' ').strip()[:500]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Create hash for integrity verification
        log_data = f"{timestamp}|{event_type}|{sanitized_details}|{source}|{user_id}"
        log_hash = hashlib.sha256(log_data.encode('utf-8')).hexdigest()

        with self.log_lock:
            try:
                conn = sqlite3.connect(self.audit_db_path)
                c = conn.cursor()
                c.execute('''
                    INSERT INTO audit_logs 
                    (timestamp, event_type, details, source, user_id, log_hash) 
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (timestamp, event_type, sanitized_details, source, user_id, log_hash))
                conn.commit()
            except sqlite3.IntegrityError:
                # Handle hash collision (extremely rare)
                pass
            finally:
                conn.close()
        
        print(f"Adding audit log: {log_data}")

    def rotate_logs(self, max_days=30):
        """Archive logs older than max_days"""
        rotation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cutoff_date = (datetime.now() - timedelta(days=max_days)).strftime("%Y-%m-%d")
        
        with self.log_lock:
            try:
                conn = sqlite3.connect(self.audit_db_path)
                c = conn.cursor()
                
                # Count logs to be archived
                c.execute("SELECT COUNT(*) FROM audit_logs WHERE date(timestamp) < ?", (cutoff_date,))
                count = c.fetchone()[0]
                
                # Archive logs (in real implementation, move to separate DB/backup)
                c.execute("DELETE FROM audit_logs WHERE date(timestamp) < ?", (cutoff_date,))
                
                # Record rotation
                c.execute('''
                    INSERT INTO log_rotation (rotation_time, logs_archived)
                    VALUES (?, ?)
                ''', (rotation_time, count))
                
                conn.commit()
                print(f"Rotated {count} logs older than {cutoff_date}")
            finally:
                conn.close()

    def _verify_callback(self, conn, cert, errnum, depth, ok):
        """Custom certificate verification callback"""
        if not ok:
            print(f"Certificate verification failed: {cert.get_subject()}")
        return ok
    
# Create global instance
mqtt_app = MQTTIntegratedApp()

# Add periodic log rotation
def log_rotation_scheduler():
    while True:
        time.sleep(86400)  # Run daily
        mqtt_app.rotate_logs()

# Start the scheduler in a separate thread
rotation_thread = threading.Thread(target=log_rotation_scheduler, daemon=True)
rotation_thread.start()

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
        identifier = request.form['identifier'].strip()
        password = request.form['password']
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Check if identifier is email or username
        if '@' in identifier:
            c.execute("""
                SELECT id, username, password_hash, role, 
                       totp_secret, mfa_enabled, backup_codes,
                       first_name, last_name, email, sector
                FROM users WHERE email = ?
            """, (identifier,))
        else:
            c.execute("""
                SELECT id, username, password_hash, role, 
                       totp_secret, mfa_enabled, backup_codes,
                       first_name, last_name, email, sector
                FROM users WHERE username = ?
            """, (identifier,))

        user_data = c.fetchone()
        conn.close()
        
        if user_data and check_password_hash(user_data[2], password):
            # Create User object with all fields
            user_obj = User(
                id=user_data[0],
                username=user_data[1],
                role=user_data[3],
                totp_secret=user_data[4],
                mfa_enabled=bool(user_data[5]),
                backup_codes=user_data[6],
                first_name=user_data[7],
                last_name=user_data[8],
                email=user_data[9],
                sector=user_data[10]
            )
            
            # Check MFA
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
            
            mqtt_app.add_audit_log("AUTH", 
                f"Successful login from {request.remote_addr}", 
                user_data[1],
                user_id=user_data[0])
                
            return redirect(url_for('index'))
        else:
            mqtt_app.add_audit_log("AUTH_FAIL", 
                f"Failed login attempt for {identifier} from {request.remote_addr}", 
                "AUTH",
                user_id=None)
            flash('Invalid credentials')
    return render_template('login.html')

# Enable MFA Page
@app.route('/enable-mfa')
@login_required
def enable_mfa():
    try:
        if not current_user.totp_secret:
            current_user.totp_secret = pyotp.random_base32()
            
            # Update database with transaction handling
            conn = sqlite3.connect(DB_PATH)
            try:
                c = conn.cursor()
                c.execute("UPDATE users SET totp_secret = ? WHERE id = ?",
                         (current_user.totp_secret, current_user.id))
                conn.commit()
                # After updating the database
                mqtt_app.add_audit_log("USER", "MFA enabled", current_user.username, user_id=current_user.id)
            except sqlite3.Error as e:
                conn.rollback()
                flash('Error saving MFA configuration')
                return redirect(url_for('index'))
            finally:
                conn.close()
            
            # Reload user from database instead of logout/login
            user = load_user(current_user.id)
            login_user(user)

        # Generate provisioning URI with URL-safe characters
        totp_uri = pyotp.totp.TOTP(current_user.totp_secret).provisioning_uri(
            name=current_user.username.replace(' ', '_'),
            issuer_name="IoT_Command_Center"
        )

        # Generate QR code with error handling
        try:
            img = qrcode.make(totp_uri)
            project_root = Path(__file__).parent.absolute()
            static_dir = project_root / "static"
            static_dir.mkdir(exist_ok=True, parents=True)
            qr_path = static_dir / "mfa_qr.png"
            img.save(qr_path)
        except Exception as e:
            flash('Error generating QR code')
            return redirect(url_for('index'))

        # Force session update before rendering template
        session.modified = True
        return render_template('enable_mfa.html')

    except Exception as e:
        app.logger.error(f'MFA Setup Error: {str(e)}')
        flash('An error occurred during MFA setup')
        return redirect(url_for('index'))

# Verify MFA Setup
@app.route('/verify-mfa', methods=['POST'])
@login_required
def verify_mfa():
    try:
        code = request.form.get('code').strip()
        
        # Validate format first
        if not re.fullmatch(r'\d{6}', code):  # Use fullmatch instead of match
            flash('Invalid MFA code format')
            return redirect(url_for('verify_login'))

        # Then verify code validity
        if not current_user.verify_totp(code):
            flash('Invalid verification code')
            return redirect(url_for('enable_mfa'))

        mqtt_app.add_audit_log("AUTH", "MFA verification successful", current_user.username, user_id=current_user.id)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?", 
                 (current_user.id,))
        
        backup_codes = current_user.generate_backup_codes()
        c.execute("UPDATE users SET backup_codes = ? WHERE id = ?",
                (current_user.backup_codes, current_user.id))
        conn.commit()
        conn.close()

        # Refresh user session without logout
        user = load_user(current_user.id)
        login_user(user)
        session.permanent = True

        return render_template('backup_codes.html', codes=backup_codes)
    except Exception as e:
        flash(f'Error processing MFA setup : {e}')
        return redirect(url_for('enable_mfa'))

# MFA Login Verification
@app.route('/verify-login', methods=['GET', 'POST'])
@limiter.limit("10 per 5 minutes")
def verify_login():
    if request.method == 'POST':
        user_id = session.get('mfa_pending_user')
        if not user_id:
            return redirect(url_for('login'))
        
        user = load_user(user_id)
        code = request.form.get('code')
        
        if user.verify_totp(code) or user.check_backup_code(code):
            login_user(user)
            session.pop('mfa_pending_user')
            return redirect(url_for('index'))
        
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
                mqtt_app.add_audit_log("AUTH", "Backup code used", user.username, user_id=user.id)
                return redirect(url_for('index'))
            
        flash('Invalid backup code')
        return redirect(url_for('recovery'))
    
    # GET request - show backup code entry form
    return render_template('recovery.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        email = request.form['email'].strip().lower()
        username = request.form['username'].strip()
        sector = request.form['sector'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validate all fields
        errors = []
        if not re.match(r'^[a-zA-Z\s-]{2,30}$', first_name):
            errors.append("Invalid first name (2-30 letters only)")
        if not re.match(r'^[a-zA-Z\s-]{2,30}$', last_name):
            errors.append("Invalid last name (2-30 letters only)")
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            errors.append("Invalid email format")
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
            errors.append("Username must be 3-20 characters (letters, numbers, _-)")
        if password != confirm_password:
            errors.append("Passwords do not match")
        
        # Password validation
        try:
            validate_password(password)
        except ValueError as e:
            errors.append(str(e))
        
        if errors:
            for error in errors:
                flash(error)
            return redirect(url_for('register'))
        
        password_hash = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                INSERT INTO users 
                (first_name, last_name, email, username, sector, password_hash, role) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (first_name, last_name, email, username, sector, password_hash, "viewer"))
            
            conn.commit()

            # Get the new user's ID
            c.execute("SELECT id FROM users WHERE username = ?", (username,))
            new_user_id = c.fetchone()[0]
            
            # Create user object and log them in
            user_obj = User(
                id=new_user_id,
                username=username,
                role="viewer",
                first_name=first_name,
                last_name=last_name,
                email=email,
                sector=sector
            )
            login_user(user_obj)
            
            # Audit log
            mqtt_app.add_audit_log("AUTH", f"New registration: {email}", "SYSTEM", user_id=new_user_id)
            
            flash('Registration successful!')
            return redirect(url_for('index'))
            
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed: users.email" in str(e):
                flash('Email already registered')
            elif "UNIQUE constraint failed: users.username" in str(e):
                flash('Username already taken')
            else:
                flash('Registration error')
        except Exception as e:
            app.logger.error(f'Registration error: {str(e)}')
            flash('Registration error')
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    user_id = current_user.id
    logout_user()
    mqtt_app.add_audit_log("AUTH", "User logged out", username, user_id=user_id)
    return redirect(url_for('index'))

@app.route('/admin')
@admin_required
def admin_panel():
    # Get all users with detailed information
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Updated query to include new fields
    c.execute('''
        SELECT id, username, role, last_login, first_name, last_name, email, sector 
        FROM users
        ORDER BY username
    ''')
    
    users = []
    active_users = 0
    current_time = datetime.now().timestamp()
    
    for row in c.fetchall():    
        last_login = datetime.fromtimestamp(row[3]).strftime("%Y-%m-%d %H:%M") if row[3] else "Never"
        is_active = (current_time - row[3]) < 900 if row[3] else False
        
        users.append({
            "id": row[0],
            "username": row[1],
            "role": row[2],
            "last_login": last_login,
            "active": is_active,
            "first_name": row[4],
            "last_name": row[5],
            "email": row[6],
            "sector": row[7]
        })
        
        if is_active:
            active_users += 1
    
    conn.close()

    # Fetch logs from database
    formatted_logs = []
    try:
        conn = sqlite3.connect(mqtt_app.audit_db_path)
        c = conn.cursor()
        c.execute('''
            SELECT timestamp, event_type, details, source 
            FROM audit_logs 
            ORDER BY timestamp DESC 
            LIMIT 50
        ''')
        db_logs = c.fetchall()
        
        for log in db_logs:
            formatted = {
                "timestamp": datetime.strptime(log[0], "%Y-%m-%d %H:%M:%S").strftime("%H:%M:%S"),
                "event_type": log[1],
                "details": log[2],
                "source": log[3]
            }
            formatted_logs.append(formatted)
    except Exception as e:
        print(f"Error fetching logs: {str(e)}")
        formatted_logs = []
    finally:
        conn.close()
    
    # Get security event count
    try:
        conn = sqlite3.connect(mqtt_app.audit_db_path)
        c = conn.cursor()
        c.execute('''
            SELECT COUNT(*) FROM audit_logs 
            WHERE event_type IN ('SECURITY','AUTH_FAIL','AUTHORIZATION','VALIDATION')
        ''')
        security_events = c.fetchone()[0]
    except:
        security_events = 0
    finally:
        conn.close()
    
    return render_template('admin.html',
                         devices=mqtt_app.get_devices(),
                         active_users=active_users,
                         logs=formatted_logs,
                         security_events=security_events,
                         all_users=users,
                         roles=VALID_ROLES)

@app.route('/admin/update_role', methods=['POST'])
@admin_required
def update_user_role():
    target_user = request.form.get('username')
    new_role = request.form.get('role')
    
    if new_role not in VALID_ROLES:
        flash('Invalid role specified')
        return redirect(url_for('admin_panel'))

    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        c.execute('''
            UPDATE users SET role = ? WHERE username = ?
        ''', (new_role, target_user))
        conn.commit()
        flash(f'Updated {target_user} role to {new_role}')
        mqtt_app.add_audit_log("ADMIN", 
            f"Updated {target_user} role to {new_role}", 
            current_user.username,
            user_id=current_user.id
        )
    except sqlite3.Error as e:
        flash(f'Error updating role: {str(e)}')
    finally:
        conn.close()
    
    return redirect(url_for('admin_panel'))

@app.route('/admin/verify_logs')
@admin_required
def verify_logs():
    """Verify integrity of audit logs"""
    invalid_logs = []
    try:
        conn = sqlite3.connect(mqtt_app.audit_db_path)
        c = conn.cursor()
        c.execute("SELECT id, timestamp, event_type, details, source, user_id, log_hash FROM audit_logs")
        
        for log in c.fetchall():
            log_id, timestamp, event_type, details, source, user_id, stored_hash = log
            log_data = f"{timestamp}|{event_type}|{details}|{source}|{user_id}"
            computed_hash = hashlib.sha256(log_data.encode('utf-8')).hexdigest()
            
            if computed_hash != stored_hash:
                invalid_logs.append({
                    "id": log_id,
                    "timestamp": timestamp,
                    "computed_hash": computed_hash,
                    "stored_hash": stored_hash
                })
        
        if invalid_logs:
            flash(f"Found {len(invalid_logs)} tampered log entries!", "error")
            # In real system, trigger security alerts here
        else:
            flash("All log entries verified - no tampering detected", "success")
            
    except Exception as e:
        flash(f"Verification failed: {str(e)}", "error")
    finally:
        conn.close()
    
    return redirect(url_for('admin_panel'))

@app.route('/api/send_command', methods=['POST'])
@login_required
def send_command():
    device_id = request.form.get("device_id")
    command = request.form.get("command").strip().lower()

    if not device_id or not command:
        return jsonify({"status": "error", "message": "Missing device_id or command"}), 400
    
    # Validate device ID format
    if not re.match(r'^device_\d{3}$', device_id):
        mqtt_app.add_audit_log("VALIDATION", 
            f"Invalid device ID format: {device_id}", 
            request.remote_addr,
            user_id=current_user.id if current_user.is_authenticated else None)
        return jsonify({"status": "error", "message": "Invalid device ID format"}), 400
    
    # ===== NEW COMMAND VALIDATION =====
    # Get device info from registry
    device_info = mqtt_app.get_devices().get(device_id)
    if not device_info:
        mqtt_app.add_audit_log("VALIDATION",
            f"Unknown device: {device_id}",
            current_user.username if current_user.is_authenticated else "ANONYMOUS",
            user_id=current_user.id if current_user.is_authenticated else None)
        return jsonify({"status": "error", "message": "Device not registered"}), 404

    # Validate command against device type
    device_type = device_info.get('type')
    allowed = ALLOWED_COMMANDS.get(device_type, [])
    
    if command not in allowed:
        mqtt_app.add_audit_log("VALIDATION",
            f"Invalid command '{command}' for {device_id} ({device_type})",
            current_user.username if current_user.is_authenticated else "ANONYMOUS",
            user_id=current_user.id if current_user.is_authenticated else None)
        return jsonify({"status": "error", "message": "Command not allowed for this device type"}), 400
    # ===== END OF VALIDATION =====

    # ===== AUTHORIZATION CHECKS =====
    # Define critical commands that require admin privileges
    RESTRICTED_COMMANDS = {"restart", "shutdown", "firmware_update"}
    
    # Check if command requires admin privileges
    if command in RESTRICTED_COMMANDS and current_user.role != "admin":
        mqtt_app.add_audit_log("AUTHORIZATION",
            f"Unauthorized attempt to send restricted command '{command}' to {device_id}",
            current_user.username,
            user_id=current_user.id)
        return jsonify({
            "status": "error",
            "message": "Admin privileges required for this command"
        }), 403

    # Additional role-based validation
    if current_user.role == "viewer":
        mqtt_app.add_audit_log("AUTHORIZATION",
            f"Viewer role attempted command '{command}' on {device_id}",
            current_user.username,
            user_id=current_user.id)
        return jsonify({
            "status": "error",
            "message": "Read-only accounts cannot send commands"
        }), 403
    # ===== END OF AUTHORIZATION CHECKS =====

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
                request.remote_addr,
                user_id=current_user.id)
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
        "device_count": len(mqtt_app.get_devices()),
        "timestamp": time.time()  
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