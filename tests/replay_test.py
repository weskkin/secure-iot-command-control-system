import requests
import time
from bs4 import BeautifulSoup
import os

requests.packages.urllib3.disable_warnings()

# 1. Get login page and extract CSRF token
session = requests.Session()
login_url = "https://localhost:5000/login"

# Get login page HTML with TLS verification disabled for testing
login_get = session.get(login_url, verify=False)
soup = BeautifulSoup(login_get.text, 'html.parser')
csrf_token = soup.find('input', {'name': 'csrf_token'})['value']

# 2. Perform login with MFA bypass for testing (ensure test user has MFA disabled)
login_response = session.post(
    login_url,
    data={
        "username": "admin",
        "password": os.getenv('ADMIN_PWD', 'Karehtnikarehtni26!'),
        "csrf_token": csrf_token
    },
    headers={"Referer": login_url},
    verify=False
)

# 3. Get new CSRF token for protected endpoints
control_url = "https://localhost:5000/control"
control_page = session.get(control_url, verify=False)

# Verify successful access to control panel
if control_page.status_code != 200:
    print(f"Error: Failed to access control panel (HTTP {control_page.status_code})")
    print("Possible reasons:")
    print("- Not logged in successfully")
    print("- MFA requirement not bypassed")
    exit(1)

soup = BeautifulSoup(control_page.text, 'html.parser')
csrf_meta = soup.find('meta', {'name': 'csrf-token'})

if not csrf_meta or 'content' not in csrf_meta.attrs:
    print("Error: CSRF token meta tag not found in control panel page")
    print("Check if:")
    print("1. User is properly logged in")
    print("2. control.html template contains: <meta name='csrf-token' content='{{ csrf_token() }}'>")
    print("Current page content:")
    print(control_page.text[:500])  # Print first 500 chars for debugging
    exit(1)

new_csrf_token = csrf_meta['content']

# 4. Prepare replay attack parameters
replay_url = "https://localhost:5000/api/send_replay"
device_id = "device_001"  # Must match regex ^device_\d{3}$
command = "status_check"
timestamp = time.time() - 31  # Exceed 30s window by 1 second

# 5. Send replay attempt with proper headers
response = session.post(
    replay_url,
    data={
        "device_id": device_id,
        "command": command,
        "timestamp": timestamp,  # Send as numeric value
        "csrf_token": new_csrf_token
    },
    headers={
        "X-CSRFToken": new_csrf_token,
        "Referer": control_url,
        "Content-Type": "application/x-www-form-urlencoded"
    },
    verify=False
)

# 6. Verify results
print("\n=== Replay Test Results ===")
print(f"Timestamp Delta: {time.time() - timestamp:.1f}s (should be >30)")
print("Status Code:", response.status_code)
print("Expected:", "400 Bad Request or 403 Forbidden")
print("Response:", response.text)

# 7. Verify audit logs (manual check required)
print("\nCheck admin panel audit logs for:")
print("- 'Replay attack detected' entry")
print("- Source IP matching your test machine")