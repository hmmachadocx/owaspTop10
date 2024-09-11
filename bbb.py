from flask import Flask, request, jsonify, render_template
import os
import logging

app = Flask(__name__)

# === CWE-256: Unprotected Storage of Credentials ===
# Storing credentials directly in the application in an unprotected manner
DATABASE_USER = "admin"
DATABASE_PASSWORD = "password123"  # Unprotected password

# === CWE-257: Storing Passwords in a Recoverable Format ===
# Insecure storage of password (not using hashing)
users = {
    "admin": "password123",  # Storing password in plaintext
}

# === CWE-73: External Control of File Name or Path ===
@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('file')
    
    # Allowing user to control file paths, leading to path traversal
    return jsonify({"message": f"Downloading {filename}"}), 200

# === CWE-183: Permissive List of Allowed Inputs ===
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'exe'}  # Permissive input
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    
    # Insecure: allowing unsafe file extensions
    if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
        file.save(f'/uploads/{file.filename}')
        return jsonify({'message': 'File uploaded successfully'}), 200
    else:
        return jsonify({'error': 'Invalid file type'}), 400

# === CWE-209: Generation of Error Message Containing Sensitive Information ===
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username not in users:
        return jsonify({'error': f'User {username} not found'}), 404
    elif users[username] != password:
        return jsonify({'error': f'Password {password} is incorrect'}), 401
    return jsonify({'message': 'Logged in successfully'}), 200

# === CWE-213: Exposure of Sensitive Information Due to Incompatible Policies ===
@app.route('/profile', methods=['GET'])
def get_profile():
    username = request.args.get('username')

    # Exposing sensitive user data due to incompatible access policies
    if username in users:
        return jsonify({'username': username, 'password': users[username]}), 200  # Exposing password
    else:
        return jsonify({'error': 'User not found'}), 404

# === CWE-235: Improper Handling of Extra Parameters ===
@app.route('/update_user', methods=['POST'])
def update_user():
    username = request.form.get('username')
    new_password = request.form.get('password')

    # Insecure: accepting and handling extra parameters (e.g., `admin`)
    admin = request.form.get('admin')

    if username in users:
        users[username] = new_password  # Storing password in plaintext
        return jsonify({'message': 'User updated'}), 200
    else:
        return jsonify({'error': 'User not found'}), 404

# === CWE-266: Incorrect Privilege Assignment & CWE-269: Improper Privilege Management ===
@app.route('/admin_panel', methods=['GET'])
def admin_panel():
    # No proper privilege checks, granting admin access without verification
    return jsonify({'message': 'Welcome to the admin panel'}), 200

# === CWE-311: Missing Encryption of Sensitive Data & CWE-419: Unprotected Primary Channel ===
@app.route('/unencrypted_login', methods=['POST'])
def unencrypted_login():
    username = request.form.get('username')
    password = request.form.get('password')

    # No encryption in transit, sending sensitive data in plain text
    if username == DATABASE_USER and password == DATABASE_PASSWORD:
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Login failed'}), 401

# === CWE-312 & CWE-313: Cleartext Storage of Sensitive Information ===
@app.route('/store_sensitive_info', methods=['POST'])
def store_sensitive_info():
    sensitive_info = request.form.get('sensitive_info')
    
    # Storing sensitive data in plaintext in a file
    with open('sensitive_data.txt', 'w') as f:
        f.write(sensitive_info)

    return jsonify({'message': 'Data stored'}), 200

# === CWE-434: Unrestricted Upload of File with Dangerous Type ===
@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    avatar = request.files['avatar']

    # Allowing dangerous file types without validation
    avatar.save(f'/avatars/{avatar.filename}')
    return jsonify({'message': 'Avatar uploaded'}), 200

# === CWE-522: Insufficiently Protected Credentials ===
@app.route('/insufficiently_protected_login', methods=['POST'])
def insufficiently_protected_login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Insecure credential storage and transmission
    if username in users and users[username] == password:
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

# === CWE-646: Reliance on File Name or Extension of Externally-Supplied File ===
@app.route('/process_file', methods=['POST'])
def process_file():
    file = request.files['file']

    # Relying on file extension for trust (instead of checking the file's content)
    if file.filename.endswith('.jpg'):
        return jsonify({'message': 'Processing image'}), 200
    else:
        return jsonify({'error': 'Unsupported file type'}), 400

if __name__ == '__main__':
    app.run(debug=True)
