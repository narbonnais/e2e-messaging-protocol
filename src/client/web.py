from flask import Flask, request, jsonify, send_from_directory
import logging
from pathlib import Path
import os

from .lib import (generate_keys, import_public_key, send_message,
                        pull_messages, get_client_db_path, get_messages, init_client_db,
                        get_contacts, get_id_from_pubkey)

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
    identifier = data.get('id')  # Contact's ID
    public_key_pem = data.get('publicKeyPem')
    user_id = data.get('userId')  # Local user's ID
    
    if not all([identifier, public_key_pem]):
        return "Error: Missing fields", 400

    # Write to temp file
    temp_file = f"temp_{identifier}_pub.pem"
    try:
        with open(temp_file, "w") as f:
            f.write(public_key_pem)
        
        db_path = get_client_db_path(user_id) if user_id else None
        import_public_key(identifier, temp_file, db_path)
        return "Public key imported successfully"
    except Exception as e:
        return f"Error: {str(e)}", 500
    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)

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

@app.route("/api/stored_messages", methods=['POST'])
def api_stored_messages():
    data = request.json
    identifier = data.get('id')
    if not identifier:
        return "Error: Missing 'id'", 400
    
    try:
        db_path = get_client_db_path(identifier)
        init_client_db(db_path)  # Ensure DB exists
        messages = get_messages(db_path)
        
        # Convert messages to include IDs where possible
        formatted_messages = []
        for sender_pub, recipient_pub, message, timestamp in messages:
            sender_id = get_id_from_pubkey(sender_pub.encode('utf-8')) or "unknown"
            recipient_id = get_id_from_pubkey(recipient_pub.encode('utf-8')) or "unknown"
            formatted_messages.append({
                'sender': sender_id,
                'recipient': recipient_id,
                'message': message,
                'timestamp': timestamp,
                'sender_pubkey': sender_pub,
                'recipient_pubkey': recipient_pub
            })
            
        return jsonify(formatted_messages)
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/api/list_local_ids')
def api_list_local_ids():
    data_dir = Path(".data")
    if not data_dir.exists():
        return jsonify([])
    dirs = [d.name for d in data_dir.iterdir() if d.is_dir()]
    return jsonify(dirs)

@app.route("/api/list_contacts", methods=['GET'])
def api_list_contacts():
    identifier = request.args.get('identifier')
    if not identifier:
        return "Error: Missing identifier", 400
    try:
        db_path = get_client_db_path(identifier)
        contacts = get_contacts(db_path)
        return jsonify(contacts)
    except Exception as e:
        return f"Error: {str(e)}", 500

def main():
    logging.basicConfig(level=logging.INFO)
    app.run(host="127.0.0.1", port=8000, debug=False)

if __name__ == "__main__":
    main()
