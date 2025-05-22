import requests
import time
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

# 1. Get login page and extract CSRF token
session = requests.Session()
login_url = "https://localhost:5000/login"

# Get login page HTML
login_get = session.get(login_url, verify=False)
soup = BeautifulSoup(login_get.text, 'html.parser')
csrf_token = soup.find('input', {'name': 'csrf_token'})['value']

# 2. Perform login
session.post(
    login_url,
    data={
        "username": "admin",
        "password": "secure_admin_password",
        "csrf_token": csrf_token
    },
    headers={"Referer": login_url},
    verify=False
)

# 3. Get new CSRF token for protected endpoints
protected_page = session.get("https://localhost:5000/control", verify=False)
soup = BeautifulSoup(protected_page.text, 'html.parser')
new_csrf_token = soup.find('meta', {'name': 'csrf-token'})['content']

# 4. Send replay command with proper device ID and timestamp
replay_url = "https://localhost:5000/api/send_replay"
device_id = "device_001"  # Updated device ID format
command = "status_check"
# >= 30 s violation
timestamp = time.time() - 30

response = session.post(
    replay_url,
    data={
        "device_id": device_id,
        "command": command,
        "timestamp": str(timestamp),
        "csrf_token": new_csrf_token
    },
    headers={
        "X-CSRFToken": new_csrf_token,
        "Referer": "https://localhost:5000/control"
    },
    verify=False
)

print("\n=== Replay Test Results ===")
print("Status Code:", response.status_code)
print("Response:", response.text)