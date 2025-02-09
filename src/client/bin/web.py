from flask import Flask, request, jsonify, send_from_directory
import logging
from pathlib import Path
import os
import yaml
import shutil
import sqlite3

from ..client import (generate_keys, import_public_key, send_message,
                        pull_messages, get_client_db_path, get_messages, init_client_db,
                        get_contacts, get_id_from_pubkey, get_server_config, update_server_config,
                        db_lock)

app = Flask(__name__)

def load_config(config_path: str = None) -> dict:
    """Load client configuration from YAML file"""
    default_config = Path("config/client_default.yaml")
    
    if not default_config.exists():
        raise FileNotFoundError(f"Default config not found at {default_config}")
        
    with open(default_config) as f:
        config = yaml.safe_load(f)
    
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            custom_config = yaml.safe_load(f)
            config.update(custom_config)
            
    return config

config = load_config()

# Serve the client HTML (assume client.html is in the same folder)
@app.route("/")
def serve_root():
    return send_from_directory('../public', 'client.html')

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
    
    db_path = get_client_db_path(sender)
    init_client_db(db_path)  # Ensure DB exists and is initialized
    host, port = get_server_config(db_path)
    resp = send_message(host, port, sender, recipient, message)
    return resp

@app.route("/api/pull_messages", methods=['POST'])
def api_pull_messages():
    data = request.json
    identifier = data.get('id')
    if not identifier:
        return "Error: Missing 'id'", 400
    
    db_path = get_client_db_path(identifier)
    init_client_db(db_path)  # Ensure DB exists and is initialized
    host, port = get_server_config(db_path)
    resp = pull_messages(host, port, identifier)
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
    data_dir = Path(config['data_dir'])
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

@app.route('/api/get_public_key')
def get_public_key():
    identifier = request.args.get('id')
    if not identifier:
        return 'Missing id parameter', 400
        
    try:
        # Read the public key file
        key_path = os.path.join(config['data_dir'], identifier, 'public_key.pem')
        if not os.path.exists(key_path):
            return f'No public key found for {identifier}', 404
            
        with open(key_path, 'r') as f:
            return f.read()
            
    except Exception as e:
        print(f"Error reading public key: {e}")
        return 'Error reading public key', 500

@app.route("/api/server_config", methods=['GET'])
def api_get_server_config():
    identifier = request.args.get('id')
    if not identifier:
        return "Error: Missing identifier", 400
    try:
        db_path = get_client_db_path(identifier)
        init_client_db(db_path)  # Ensure DB exists and is initialized
        host, port = get_server_config(db_path)
        return jsonify({"host": host, "port": port})
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route("/api/server_config", methods=['POST'])
def api_update_server_config():
    data = request.json
    identifier = data.get('id')
    host = data.get('host')
    port = data.get('port')
    
    if not all([identifier, host, port]):
        return "Error: Missing required fields", 400
        
    try:
        port = int(port)
        if port < 1 or port > 65535:
            return "Error: Invalid port number", 400
            
        db_path = get_client_db_path(identifier)
        init_client_db(db_path)  # Ensure DB exists and is initialized
        if update_server_config(db_path, host, port):
            return "Server configuration updated successfully"
        return "Error updating server configuration", 500
    except ValueError:
        return "Error: Port must be a number", 400
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route("/api/delete_local_id", methods=['POST'])
def api_delete_local_id():
    data = request.json
    identifier = data.get('id')
    if not identifier:
        return "Error: Missing identifier", 400
    try:
        user_dir = Path(config['data_dir']) / identifier
        if not user_dir.exists():
            return f"Error: ID {identifier} not found", 404
        shutil.rmtree(user_dir)
        return "Local ID deleted successfully"
    except Exception as e:
        return f"Error deleting local ID: {str(e)}", 500

@app.route("/api/delete_contact", methods=['POST'])
def api_delete_contact():
    data = request.json
    user_id = data.get('userId')
    contact_id = data.get('contactId')
    if not all([user_id, contact_id]):
        return "Error: Missing required fields", 400
    try:
        db_path = get_client_db_path(user_id)
        with db_lock, sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
            conn.commit()
        return "Contact deleted successfully"
    except Exception as e:
        return f"Error deleting contact: {str(e)}", 500

def main():
    logging.basicConfig(level=logging.INFO)
    
    # Ensure data directory exists
    data_dir = Path(config['data_dir'])
    data_dir.mkdir(parents=True, exist_ok=True)
    
    web_config = config['web']
    app.run(host=web_config['host'], 
            port=web_config['port'], 
            debug=False)

if __name__ == "__main__":
    main()
