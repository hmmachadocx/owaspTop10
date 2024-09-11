from flask import Flask, request, jsonify
import logging
import os
import requests

app = Flask(__name__)

# Set up basic logging (Security Logging and Monitoring Failures - A09)
logging.basicConfig(filename='app.log', level=logging.INFO)

# === A04: Insecure Design ===
# A simple registration system with insecure design
users = {}

@app.route('/register', methods=['POST'])
def register():
    # Insecure: no validation of username or password complexity
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Insecure: storing password in plaintext (instead of hashing)
    if username in users:
        return jsonify({'error': 'User already exists'}), 400
    
    users[username] = password  # Insecure storage
    return jsonify({'message': 'User registered successfully'})

# Insecure Design (A04): Lack of password complexity, lack of input validation,
# and no encryption leads to design flaws.

# === A08: Software and Data Integrity Failures ===
@app.route('/update_data', methods=['POST'])
def update_data():
    data_url = request.form.get('data_url')

    # Insecure: Downloading data from an untrusted source without verification
    # No integrity checks such as cryptographic signatures or checksums.
    response = requests.get(data_url)
    
    if response.status_code == 200:
        # Assume data is valid and process it without further validation
        data = response.text
        return jsonify({'message': 'Data updated successfully', 'data': data})
    else:
        return jsonify({'error': 'Failed to retrieve data'}), 400

# Insecure: Software supply chain vulnerability where untrusted data is fetched 
# without integrity validation, leaving the system vulnerable to malicious inputs.

# === A09: Security Logging and Monitoring Failures ===
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Insecure: Logging sensitive information (username, password) directly into the log file
    logging.info(f'Login attempt - Username: {username}, Password: {password}')
    
    # Insecure: No monitoring for suspicious login attempts or alerts for failed logins
    if username not in users or users[username] != password:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    return jsonify({'message': 'Login successful'})

# The logging setup does not capture failed login attempts or malicious behavior.
# Sensitive information (password) is being logged in plain text.

if __name__ == '__main__':
    app.run(debug=True)
