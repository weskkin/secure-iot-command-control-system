from flask import Flask

# Create Flask Application
app = Flask(__name__)
app.secret_key = 'dev_key_change_this_later' #We'll make this more secure later

# Route for home page
@app.route('/')
def home():
    return "Welcome to the Secure IoT Command Center!"

# Route for device control page (we'll expand it later)
@app.route('/control')
def control():
    return "Device Control Page - Coming Soon"

# Start the application
if __name__ == '__main__':
    app.run(debug=True) #Enables auto-reloading and an interactive debugger if errors occur.