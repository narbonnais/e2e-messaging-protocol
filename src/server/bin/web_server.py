# server_web_server.py

from flask import Flask, jsonify, send_from_directory
import logging
import sqlite3
from datetime import datetime
import os
import yaml
from pathlib import Path

from ..main import db_lock, DB_PATH, cleanup_old_pulled_messages, init_db

app = Flask(__name__)


@app.route("/")
def serve_root():
    return send_from_directory('../public', 'server.html')


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

        last_cleanup = getattr(
            cleanup_old_pulled_messages, 'last_run', 'Never')
        return jsonify({
            "messagesCount": messages_count,
            "pulledCount": pulled_count,
            "lastCleanup": str(last_cleanup)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/log", methods=['GET'])
def api_log():
    logfile = os.path.join(".data/server", "server.log")
    if not os.path.exists(logfile):
        return "(No log yet)"
    try:
        with open(logfile, "r") as f:
            # Return last 1000 lines
            lines = f.readlines()[-1000:]
        return "".join(lines)
    except Exception as e:
        return f"Error reading log: {str(e)}", 500


def load_config(config_path: str = None) -> dict:
    """Load server configuration from YAML file"""
    default_config = Path("config/server_default.yaml")

    if not default_config.exists():
        raise FileNotFoundError(
            f"Default config not found at {default_config}")

    with open(default_config) as f:
        config = yaml.safe_load(f)

    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            custom_config = yaml.safe_load(f)
            config.update(custom_config)

    return config


config = load_config()


def main():
    logging.basicConfig(level=logging.INFO)

    # Ensure server data directory exists
    server_dir = Path(".data/server")
    server_dir.mkdir(parents=True, exist_ok=True)

    web_config = config['web_server']
    init_db(config['database']['path'])
    app.run(host=web_config['host'],
            port=web_config['port'],
            debug=False)


if __name__ == "__main__":
    main()
