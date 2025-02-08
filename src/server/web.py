# server_web_server.py

from flask import Flask, jsonify, send_from_directory
import logging
import sqlite3
from datetime import datetime
import os

from src.common.lib import db_lock, DB_PATH, cleanup_old_pulled_messages, init_db

app = Flask(__name__)

@app.route("/")
def serve_root():
    return send_from_directory('.', 'server.html')

@app.route("/api/metrics", methods=['GET'])
def api_metrics():
    try:
        init_db(DB_PATH)  # ensure DB
        with db_lock, sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM messages")
            messages_count = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM pulled_messages")
            pulled_count = c.fetchone()[0]

        last_cleanup = getattr(cleanup_old_pulled_messages, 'last_run', 'Never')
        return jsonify({
            "messagesCount": messages_count,
            "pulledCount": pulled_count,
            "lastCleanup": str(last_cleanup)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/log", methods=['GET'])
def api_log():
    logfile = "server.log"
    if not os.path.exists(logfile):
        return "(No log yet)"
    try:
        with open(logfile, "r") as f:
            # Return last 1000 lines
            lines = f.readlines()[-1000:]
        return "".join(lines)
    except Exception as e:
        return f"Error reading log: {str(e)}", 500

def main():
    logging.basicConfig(level=logging.INFO)
    init_db(DB_PATH)
    app.run(host="127.0.0.1", port=8001, debug=False)

if __name__ == "__main__":
    main()
