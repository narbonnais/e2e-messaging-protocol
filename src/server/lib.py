import logging
import socket
import threading
from src.common.lib import (store_message, pull_and_move_messages,
                        verify_signature, cleanup_old_pulled_messages,
                        init_db, db_lock, DB_PATH)

import base64
import time

from cryptography.exceptions import InvalidSignature

def handle_send(data_tokens):
    """
    data_tokens: ["SEND", <recipient_pub>, <ciphertext>, <signature>,
                  <sender_pub>, <nonce>]
    """
    if len(data_tokens) != 6:
        logging.error(f"Invalid SEND command format. Got {len(data_tokens)} tokens.")
        return b"ERROR: Invalid SEND command format\n"

    _, b64_recipient_pub, b64_ciphertext, b64_signature, b64_sender_pub, b64_nonce = data_tokens
    try:
        recipient_pub = base64.b64decode(b64_recipient_pub)
        ciphertext    = base64.b64decode(b64_ciphertext)
        signature     = base64.b64decode(b64_signature)
        sender_pub    = base64.b64decode(b64_sender_pub)
        nonce         = base64.b64decode(b64_nonce)
    except Exception as e:
        logging.error(f"Base64 decode failed in SEND: {str(e)}")
        return b"ERROR: Base64 decode failed\n"

    # Verify signature
    try:
        message_for_sig = recipient_pub + ciphertext + nonce
        verify_signature(sender_pub, signature, message_for_sig)
    except InvalidSignature:
        logging.warning(f"Invalid signature in SEND from {sender_pub[:20]}...")
        return b"ERROR: Invalid signature\n"
    except Exception as e:
        logging.error(f"Signature verification error in SEND: {str(e)}")
        return f"ERROR: Signature verification failed: {str(e)}\n".encode('utf-8')

    # Store
    store_message(recipient_pub, ciphertext, sender_pub, signature, nonce, DB_PATH)
    logging.info(f"Stored message for {recipient_pub[:20]} from {sender_pub[:20]}...")
    return b"OK: Message stored\n"

def handle_pull(data_tokens):
    """
    data_tokens: ["PULL", <requester_pub>, <signature>]
    """
    if len(data_tokens) != 3:
        logging.error("Invalid PULL command format.")
        return b"ERROR: Invalid PULL command format\n"

    _, b64_requester_pub, b64_signature = data_tokens
    try:
        requester_pub = base64.b64decode(b64_requester_pub)
        signature     = base64.b64decode(b64_signature)
    except Exception as e:
        logging.error(f"Base64 decode failed in PULL: {str(e)}")
        return b"ERROR: Base64 decode failed\n"

    # Verify signature
    try:
        verify_signature(requester_pub, signature, requester_pub)
    except InvalidSignature:
        logging.warning(f"Invalid signature in PULL from {requester_pub[:20]}...")
        return b"ERROR: Invalid signature\n"
    except Exception as e:
        logging.error(f"Signature verification error in PULL: {str(e)}")
        return f"ERROR: Signature verification failed: {str(e)}\n".encode('utf-8')

    # Pull
    rows = pull_and_move_messages(requester_pub, DB_PATH)
    if not rows:
        return b"OK: No messages\n"

    lines = []
    for row in rows:
        msg_id, ciphertext, sender_pub_data, sig, nonce, ts = row
        ciph_b64 = base64.b64encode(ciphertext).decode('utf-8')
        spub_b64 = base64.b64encode(sender_pub_data).decode('utf-8')
        lines.append(ciph_b64 + "::" + spub_b64)

    logging.info(f"Delivered {len(rows)} messages to {requester_pub[:20]}...")
    resp = "MESSAGES:\n" + "\n".join(lines) + "\n"
    return resp.encode('utf-8')

def _read_line(conn):
    data_chunks = []
    while True:
        chunk = conn.recv(1024)
        if not chunk:
            break
        data_chunks.append(chunk)
        if b'\n' in chunk:
            break
    data = b''.join(data_chunks)
    return data.decode('utf-8', errors='ignore').strip()

def client_handler(conn: socket.socket, addr: tuple):
    try:
        conn.settimeout(30)  # 30s timeout
        logging.info(f"New connection from {addr}")
        data = _read_line(conn)
        if not data:
            logging.warning(f"Empty data from {addr}")
            conn.sendall(b"ERROR: Empty request\n")
            return

        logging.info(f"Raw data: {data!r}")
        tokens = data.split()
        if not tokens:
            conn.sendall(b"ERROR: No command\n")
            return

        cmd = tokens[0].upper()
        if cmd == "SEND":
            resp = handle_send(tokens)
        elif cmd == "PULL":
            resp = handle_pull(tokens)
        else:
            logging.warning(f"Unknown command {cmd} from {addr}")
            resp = b"ERROR: Unknown command\n"

        conn.sendall(resp)

    except socket.timeout:
        logging.error(f"Connection timeout from {addr}")
        conn.sendall(b"ERROR: Connection timeout\n")
    except Exception as e:
        logging.error(f"Error handling client {addr}: {str(e)}")
        msg = f"ERROR: Exception: {str(e)}\n".encode('utf-8')
        conn.sendall(msg)
    finally:
        conn.close()
        logging.info(f"Closed connection from {addr}")

def run_server(host: str, port: int):
    logging.info(f"Starting raw TCP server on {host}:{port}")
    init_db(DB_PATH)  # Make sure DB is ready

    shutdown_event = threading.Event()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print(f"Server listening on {host}:{port}...")

    # Start cleanup thread
    def cleanup_loop():
        while not shutdown_event.is_set():
            time.sleep(3600)
            try:
                cleanup_old_pulled_messages(DB_PATH)
            except Exception as e:
                logging.error(f"Error in cleanup: {str(e)}")

    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()
    logging.info("Started cleanup thread")

    try:
        while not shutdown_event.is_set():
            conn, addr = s.accept()
            t = threading.Thread(target=client_handler, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        logging.info("Shutdown signal received")
        shutdown_event.set()
    except Exception as e:
        logging.critical(f"Fatal server error: {str(e)}")
        raise
    finally:
        logging.info("Shutting down server")
        s.close()
