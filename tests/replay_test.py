import requests
import time
from bs4 import BeautifulSoup  # Add this import

requests.packages.urllib3.disable_warnings()

# 1. Get login page and extract CSRF token
session = requests.Session()
login_url = "https://localhost:5000/login"

# Get login page HTML
login_get = session.get(login_url, verify=False)
soup = BeautifulSoup(login_get.text, 'html.parser')

# Extract CSRF token from hidden input field
csrf_token = soup.find('input', {'name': 'csrf_token'})['value']

print(f"=== Extracted CSRF Token: {csrf_token} ===")

# 2. Perform login with CSRF token
login_response = session.post(
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

print(f"=== New CSRF Token: {new_csrf_token} ===")

# 4. Send replay command with latest CSRF token
replay_url = "https://localhost:5000/api/send_replay"
timestamp = time.time() - 310

replay_response = session.post(
    replay_url,
    data={
        "device_id": "dev001",
        "command": "status_check",
        "timestamp": str(timestamp),
        "csrf_token": new_csrf_token
    },
    headers={
        "X-CSRFToken": new_csrf_token,
        "Referer": "https://localhost:5000/control"
    },
    verify=False
)

print("\n=== Final Response ===")
print("Status Code:", replay_response.status_code)
print("Response:", replay_response.text)