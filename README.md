Secure IoT Command Center: Zero‑trust TLS mutual auth, MFA, RBAC, tamper‑proof logs, CRL automation, MQTT persistence, and replay‑attack detection for critical‑infrastructure IoT

PROJECT OVERVIEW
An end‑to‑end zero‑trust management system comprising a Flask‑based web application and Python device simulators. Enforces:

* Mutual TLS authentication for every connection
* RSA‑PSS command signing with timestamp validation to prevent replay attacks
* Hierarchical role‑based access control (Admin, Operator, Viewer)
* TOTP‑based multi‑factor authentication with backup codes
* Tamper‑proof HMAC‑protected audit logging with automatic rotation
* Real‑time device status monitoring and command issuance
* Administrative functions for user management, certificate revocation, and log‑integrity verification

QUICK START

1. Generate all certificates and CRLs (Root CA, Intermediate CA, command\_center, mqtt\_broker, device\_001) with SAN support:
   ./scripts/cert\_gen\_crl\_script.sh
2. Create the audit‐logs database and enable rotation:
   cd command\_center
   python3 audit\_db.py
3. Start the Mosquitto broker on port 8883 with TLS mutual auth and ACLs:
   ./scripts/start\_broker.sh
4. Launch the Flask web app (command center):
   cd command\_center
   python3 app.py
5. Open your browser to [http://localhost:5000](http://localhost:5000) to view the homepage, which shows:

   * Broker connection status
   * Number of connected devices
   * General system information
6. Click “Login” and authenticate as Admin to access:

   * Device control panel
   * Admin dashboard
7. Observe audit and authentication events in the application terminal and stored in audit.db
8. Enable MFA:

   * Visit [http://localhost:5000/enable-mfa](http://localhost:5000/enable-mfa)
   * Scan the QR code with an authenticator app
   * Enter the generated TOTP code
9. Securely store the provided backup codes
10. On subsequent logins, enter your TOTP code or a backup code
11. In the device control panel, view connected devices and send allowed commands; unsupported commands are rejected with an error message
12. Start the IoT device simulator (e.g., temperature sensor):
    cd device\_simulator
    python3 device.py
    – Simulator connects over MQTT with its device certificate, subscribes to command topics, and publishes its online status
13. Watch the web app update device counts and enable command issuance once a device connects
14. Send commands (read temperature, activate, deactivate, restart, check status, or custom); successful commands confirm, unauthorized ones error
15. Register new users via the “Register” page; passwords are strength‑validated, default role = viewer
16. Admins can upgrade users to Operator in the admin dashboard
17. In the admin dashboard, filter and review audit logs by event type (auth, command, validation, auth\_fail, authorization, security, etc.)
18. Manage registered users: view profiles, change roles, enforce password policy
19. Verify log integrity in the dashboard—any tampering with audit.db is detected via HMAC checks
20. Revoke certificates, update and display CRLs, and perform CRL checks:
    ./scripts/manage\_crl.sh
21. Simulate and verify replay‑attack detection:
    python3 tests/replay\_test.py
    – Both device simulator and command center log replay attempts; blocked events appear in audit.db and the admin dashboard

FEATURES

* End‑to‑End TLS 1.3 encryption with perfect forward secrecy
* Mutual X.509 certificate authentication for users, devices, and broker
* RSA‑PSS command signing with timestamp validation to mitigate replay attacks
* Hierarchical RBAC (Admin, Operator, Viewer)
* TOTP‑based MFA with backup codes
* Tamper‑proof audit logging in SQLite with HMAC integrity and rotation
* Secure HTTP session management: CSRF tokens, secure/HttpOnly/SameSite cookies, rate limiting
* Comprehensive HTTP security headers via Flask‑Talisman
* MQTT broker configured for TLS mutual auth, ACLs, CRL checks, data persistence
* Certificate lifecycle scripts: generation, revocation, CRL publication
* User registration, login, and role management interfaces
* Real‑time dashboard with broker and device status metrics
* Admin dashboard for log auditing, user management, and log‑integrity verification
* Device simulator: signed‐command validation, per‑device whitelists, status reporting
* Replay‑attack test suite to confirm proper blocking and logging of duplicate requests

SYSTEM ARCHITECTURE

1. certificates/ca – Root & Intermediate CA files, certs, private keys, CRLs
2. config/ – mosquitto.conf and ACL definitions in config/acl
3. scripts/ – cert\_gen\_crl\_script.sh, manage\_crl.sh, start\_broker.sh
4. command\_center/ – app.py, audit\_db.py, users.db, audit.db, static assets, HTML templates
5. device\_simulator/ – device.py and device\_certs for simulator testing
6. mosquitto\_persistence/ – persistent MQTT data files
7. tests/replay\_test.py – automated replay‑attack detection scenarios

Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repo
2. Create a feature branch (git checkout -b feature-name)
3. Commit your changes (git commit -m 'Add new feature')
4. Push to your branch (git push origin feature-name)
5. Open a pull request

License

This project is licensed under the MIT License.

Report author: Mohamed Ouail Islam Douar (Student No. 235B5021)&#x20;