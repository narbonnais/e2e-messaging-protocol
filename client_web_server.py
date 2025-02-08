# client_web_server.py

from flask import Flask, request, jsonify, send_from_directory
import logging
from pathlib import Path
import os

from client_lib import (generate_keys, import_public_key, send_message,
                        pull_messages)

app = Flask(__name__)

# Serve the client HTML (assume client.html is in the same folder)
@app.route("/")
def serve_root():
    return send_from_directory('.', 'client.html')

@app.route("/api/generate_key", methods=['POST'])
def api_generate_key():
    data = request.json
    identifier = data.get('id')
    if not identifier:
        return "Error: Missing 'id'", 400
    try:
        generate_keys(identifier)
        return "Keys generated successfully"
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route("/api/import_key", methods=['POST'])
def api_import_key():
    data = request.json
    identifier = data.get('id')
    public_key_pem = data.get('publicKeyPem')
    if not identifier or not public_key_pem:
        return "Error: Missing fields", 400

    # Write to temp file
    temp_file = f"temp_{identifier}_pub.pem"
    with open(temp_file, "w") as f:
        f.write(public_key_pem)
    try:
        import_public_key(identifier, temp_file)
    finally:
        os.unlink(temp_file)
    return "Public key imported successfully"

@app.route("/api/send_message", methods=['POST'])
def api_send_message():
    data = request.json
    sender = data.get('sender')
    recipient = data.get('recipient')
    message = data.get('message')
    if not all([sender, recipient, message]):
        return "Error: Missing fields", 400
    resp = send_message("127.0.0.1", 50000, sender, recipient, message)
    return resp

@app.route("/api/pull_messages", methods=['POST'])
def api_pull_messages():
    data = request.json
    identifier = data.get('id')
    if not identifier:
        return "Error: Missing 'id'", 400
    resp = pull_messages("127.0.0.1", 50000, identifier)
    return resp

def main():
    logging.basicConfig(level=logging.INFO)
    app.run(host="127.0.0.1", port=8000, debug=False)

if __name__ == "__main__":
    main()
