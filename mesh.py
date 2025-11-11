# mesh.py
# Mesh / UDP discovery + reliable queue module
# Save as mesh.py and import into your app.py

import os
import json
import sqlite3
import socket
import threading
import time
from threading import Event, Lock
from flask import Blueprint, jsonify, current_app

# Configuration (can be overridden by environment variables)
DB_PATH = os.environ.get("APP_DB_PATH", "ethos.db")
UDP_PORT = int(os.environ.get("UDP_PORT", "5006"))
BROADCAST_ADDR = os.environ.get("BROADCAST_ADDR", "255.255.255.255")
# If your network blocks 255.255.255.255 use e.g. "192.168.1.255"

mesh_bp = Blueprint("mesh", __name__)

# In-memory known devices
KNOWN_DEVICES = {}
KNOWN_DEVICES_LOCK = Lock()

UDP_QUEUE_TABLE = "udp_queue"

# Worker control
_UDP_STOP_EVENT = None
_UDP_QUEUE_THREAD = None
_UDP_LISTENER_THREAD = None


# -------------------------
# DB migration / utilities
# -------------------------
def _ensure_udp_table_and_columns():
    """
    Ensure the udp_queue table exists and contains the columns we need.
    If the table exists but lacks columns (older schema), add them via ALTER TABLE ADD COLUMN.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()
    # create table if not exists with full schema
    c.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {UDP_QUEUE_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT NOT NULL,
            target_port INTEGER NOT NULL DEFAULT {UDP_PORT},
            payload TEXT NOT NULL,
            retries INTEGER DEFAULT 0,
            last_sent REAL DEFAULT 0
        )
        """
    )
    conn.commit()

    # Check actual columns in table
    c.execute(f"PRAGMA table_info({UDP_QUEUE_TABLE})")
    cols = [r[1] for r in c.fetchall()]
    # Add missing columns if any
    if "target_port" not in cols:
        try:
            c.execute(f"ALTER TABLE {UDP_QUEUE_TABLE} ADD COLUMN target_port INTEGER DEFAULT {UDP_PORT}")
            conn.commit()
        except Exception:
            pass
    if "payload" not in cols:
        try:
            c.execute(f"ALTER TABLE {UDP_QUEUE_TABLE} ADD COLUMN payload TEXT DEFAULT ''")
            conn.commit()
        except Exception:
            pass
    if "retries" not in cols:
        try:
            c.execute(f"ALTER TABLE {UDP_QUEUE_TABLE} ADD COLUMN retries INTEGER DEFAULT 0")
            conn.commit()
        except Exception:
            pass
    if "last_sent" not in cols:
        try:
            c.execute(f"ALTER TABLE {UDP_QUEUE_TABLE} ADD COLUMN last_sent REAL DEFAULT 0")
            conn.commit()
        except Exception:
            pass

    conn.close()


# -------------------------
# Network helpers
# -------------------------
def get_self_ip():
    """Best-effort LAN IP (does not make network changes)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _make_send_socket(timeout=2.0, use_broadcast=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if use_broadcast:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception:
            pass
    s.settimeout(timeout)
    return s


def send_udp_json(ip, port, payload, use_broadcast=False):
    """
    Sends JSON payload via UDP to ip:port.
    Returns True on success, False on exception (caller can queue).
    """
    try:
        s = _make_send_socket(use_broadcast=use_broadcast)
        data = json.dumps(payload).encode("utf-8")
        s.sendto(data, (ip, int(port)))
        s.close()
        return True
    except Exception as e:
        # Log to app logger if available
        try:
            current_app.logger.debug(f"[mesh][send_udp_json] send error to {ip}:{port} -> {e}")
        except Exception:
            print(f"[mesh][send_udp_json] send error to {ip}:{port} -> {e}")
        return False


def queue_udp_message(ip, port, payload):
    """
    Persist a message to the sqlite queue table for later retries.
    This is robust to older schema (migration ran at module init).
    """
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        # Ensure table and columns exist
        _ensure_udp_table_and_columns()
        c.execute(
            f"INSERT INTO {UDP_QUEUE_TABLE} (target_ip, target_port, payload) VALUES (?, ?, ?)",
            (ip, int(port), json.dumps(payload)),
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        try:
            current_app.logger.error(f"[mesh][queue_udp_message] queue insert error: {e}")
        except Exception:
            print(f"[mesh][queue_udp_message] queue insert error: {e}")
        return False


# -------------------------
# Background workers
# -------------------------
def _udp_queue_worker(stop_event: Event):
    """
    Drains the queue and retries sends.
    This worker fetches pending rows and tries to send them. On success deletes the row.
    """
    _ensure_udp_table_and_columns()
    while not stop_event.is_set():
        try:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            # fetch a small batch
            c.execute(f"SELECT id,target_ip,target_port,payload,retries FROM {UDP_QUEUE_TABLE} ORDER BY id LIMIT 20")
            rows = c.fetchall()
            for ident, ip, port, payload_text, retries in rows:
                try:
                    payload = json.loads(payload_text)
                except Exception:
                    payload = None
                ok = False
                # try sending; use broadcast flag if the target ip looks like a broadcast address
                use_broadcast = ip.endswith(".255") or ip == "255.255.255.255"
                if payload is not None:
                    ok = send_udp_json(ip, port, payload, use_broadcast=use_broadcast)
                if ok:
                    c.execute(f"DELETE FROM {UDP_QUEUE_TABLE} WHERE id = ?", (ident,))
                else:
                    c.execute(
                        f"UPDATE {UDP_QUEUE_TABLE} SET retries = retries + 1, last_sent = ? WHERE id = ?",
                        (time.time(), ident),
                    )
            conn.commit()
            conn.close()
        except Exception as e:
            try:
                current_app.logger.error(f"[mesh][_udp_queue_worker] error: {e}")
            except Exception:
                print(f"[mesh][_udp_queue_worker] error: {e}")
        # sleep small amount
        stop_event.wait(1.0)


def _udp_listener_worker(stop_event: Event):
    """
    Listen for UDP messages on UDP_PORT. Handles 'discover' and 'discover_ack' messages and
    forwards other payloads to the application's handler via a callback (if provided).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    try:
        s.bind(("", UDP_PORT))
    except Exception as e:
        try:
            current_app.logger.error(f"[mesh][_udp_listener_worker] bind error: {e}")
        except Exception:
            print(f"[mesh][_udp_listener_worker] bind error: {e}")
        return

    s.settimeout(1.0)
    while not stop_event.is_set():
        try:
            data, addr = s.recvfrom(65536)
            ip = addr[0]
            try:
                payload = json.loads(data.decode("utf-8"))
            except Exception:
                payload = None
            if payload and isinstance(payload, dict):
                typ = payload.get("type")
                if typ == "discover":
                    with KNOWN_DEVICES_LOCK:
                        KNOWN_DEVICES[ip] = {"last_seen": time.time(), "info": payload.get("info")}
                    # send ack
                    resp = {"type": "discover_ack", "from": get_self_ip(), "info": payload.get("info")}
                    send_udp_json(ip, UDP_PORT, resp)
                elif typ == "discover_ack":
                    with KNOWN_DEVICES_LOCK:
                        KNOWN_DEVICES[ip] = {"last_seen": time.time(), "info": payload.get("info")}
                else:
                    # application-level payload: call optional handler if app set it
                    handler = getattr(current_app, "mesh_incoming_handler", None)
                    if callable(handler):
                        try:
                            handler(payload, ip)
                        except Exception as e:
                            try:
                                current_app.logger.error(f"[mesh] incoming handler error: {e}")
                            except Exception:
                                print(f"[mesh] incoming handler error: {e}")
        except socket.timeout:
            continue
        except Exception as e:
            try:
                current_app.logger.error(f"[mesh][_udp_listener_worker] error: {e}")
            except Exception:
                print(f"[mesh][_udp_listener_worker] error: {e}")
    try:
        s.close()
    except Exception:
        pass


# -------------------------
# Public control/utility
# -------------------------
def start_mesh(app=None):
    """
    Start mesh worker threads. Call once during app startup.
    Example in app.py:
        from mesh import start_mesh
        start_mesh(app)
    """
    global _UDP_STOP_EVENT, _UDP_QUEUE_THREAD, _UDP_LISTENER_THREAD
    if _UDP_STOP_EVENT is not None:
        # already started
        return
    _UDP_STOP_EVENT = Event()
    # threads must receive the stop_event
    _UDP_QUEUE_THREAD = threading.Thread(target=_udp_queue_worker, args=(_UDP_STOP_EVENT,), daemon=True, name="udp-queue")
    _UDP_LISTENER_THREAD = threading.Thread(
        target=_udp_listener_worker, args=(_UDP_STOP_EVENT,), daemon=True, name="udp-listener"
    )
    _UDP_QUEUE_THREAD.start()
    _UDP_LISTENER_THREAD.start()
    # attach blueprint to app if provided
    if app is not None:
        app.register_blueprint(mesh_bp)


def stop_mesh():
    """
    Stop background threads cleanly.
    """
    global _UDP_STOP_EVENT, _UDP_QUEUE_THREAD, _UDP_LISTENER_THREAD
    if _UDP_STOP_EVENT is None:
        return
    _UDP_STOP_EVENT.set()
    # join threads with timeout
    if _UDP_QUEUE_THREAD is not None:
        _UDP_QUEUE_THREAD.join(timeout=2.0)
    if _UDP_LISTENER_THREAD is not None:
        _UDP_LISTENER_THREAD.join(timeout=2.0)
    _UDP_STOP_EVENT = None
    _UDP_QUEUE_THREAD = None
    _UDP_LISTENER_THREAD = None


# -------------------------
# Flask endpoints for debug / control (blueprint)
# -------------------------
@mesh_bp.route("/api/discover_now", methods=["GET", "POST"])
def api_discover_now():
    payload = {"type": "discover", "from": get_self_ip(), "info": {"name": socket.gethostname()}}
    ok = send_udp_json(BROADCAST_ADDR, UDP_PORT, payload, use_broadcast=True)
    if not ok:
        # queue for reliability
        queue_udp_message(BROADCAST_ADDR, UDP_PORT, payload)
    return jsonify({"success": True})


@mesh_bp.route("/api/devices", methods=["GET"])
def api_devices():
    with KNOWN_DEVICES_LOCK:
        devices = {k: v for k, v in KNOWN_DEVICES.items()}
    return jsonify(devices)


@mesh_bp.route("/api/udp_status", methods=["GET"])
def api_udp_status():
    with KNOWN_DEVICES_LOCK:
        devices = [{"ip": ip, "last_seen": info["last_seen"], "info": info.get("info")} for ip, info in KNOWN_DEVICES.items()]
    qcount = None
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute(f"SELECT count(*) FROM {UDP_QUEUE_TABLE}")
        qcount = c.fetchone()[0]
        conn.close()
    except Exception:
        qcount = None
    return jsonify({"devices": devices, "udp_queue_count": qcount})


# -------------------------
# Module init: attempt to create table / columns early (safe no-op if DB locked)
# -------------------------
try:
    _ensure_udp_table_and_columns()
except Exception:
    # ignore init errors; the functions will call ensure before operations as well
    pass
