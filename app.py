import os
import io
import glob
import sqlite3
from sqlite3 import OperationalError
import threading
import time
import subprocess
import hashlib
import cv2
import numpy as np
import base64
import concurrent.futures
import json
import zipfile
from datetime import datetime, date, timedelta
from threading import Event, Lock
import qrcode
import pandas as pd  # XLSX import/export

from flask import (
    Flask,
    render_template,
    render_template_string,
    request,
    jsonify,
    Response,
    send_from_directory,
    send_file,
    abort,
    session,
    redirect,
    url_for,
)

from werkzeug.utils import secure_filename

import psycopg2
import psycopg2.extras

import inspect
import uuid
import re
import socket
from pathlib import Path

# --- Optional Pi camera (falls back to OpenCV if not available) ---
try:
    from picamera2 import Picamera2
except Exception:
    Picamera2 = None


from flask import Flask, render_template_string, request, jsonify
from gpiozero import OutputDevice
import os

# ====== CONFIGURE THESE ======
RELAY_GPIO = 26          
LOW_LEVEL_TRIGGER = True # Set True if your relay triggers on LOW; False if HIGH-trigger.

# gpiozero OutputDevice: active_high controls logic inversion in software
relay = OutputDevice(RELAY_GPIO, active_high=(not LOW_LEVEL_TRIGGER), initial_value=False)


# --- Local modules ---
from face_recognizer import FaceRecognizer
from fingerprint import Fingerprint
import rfid
from fingerprint import print_user_id_and_cut, led_blink

# lightweight replacement for mesh/TCP helper: provide device IP
# (original mesh code was removed per your request)
def get_self_ip():
    """Return a sensible local IP address (fallback to 127.0.0.1)."""
    try:
        # This attempts to find an outward-facing IP without sending packets.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # connect to a public DNS (no packet is actually sent)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            # fallback to hostname resolution
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def run_parallel(*targets):
    for fn in targets:
        t = threading.Thread(target=fn, daemon=True)
        t.start()


# -----------------------------------------------------------------------------
# Flask app setup
# -----------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = "supersecret"  # required for session

# --- UDP / mesh constants (must be defined before DB init that creates udp_queue) ---
UDP_PORT = int(os.environ.get("UDP_PORT", "5006"))  # choose same port for all devices
UDP_CHUNK_SIZE = int(os.environ.get("UDP_CHUNK_SIZE", "1200"))  # safe payload chunk size
UDP_ACK_TIMEOUT = float(os.environ.get("UDP_ACK_TIMEOUT", "2.0"))
UDP_MAX_RETRIES = int(os.environ.get("UDP_MAX_RETRIES", "6"))

# Branding (used in templates)
app.config.update(
    BRAND_NAME=os.environ.get("BRAND_NAME", "Canteen Kiosk"),
    BRAND_LOGO=os.environ.get("BRAND_LOGO", "/static/img/logo.png"),  # put your logo file here
    PUBLIC_BASE_URL=os.environ.get("PUBLIC_BASE_URL", ""),            # optional fixed base URL for phone
    APP_PORT=int(os.environ.get("APP_PORT", "5000")),
)

# Handoff / QR Import-Export
HANDOFF_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", str(10 * 60)))  # 10m
HANDOFF_UPLOAD_DIR = os.path.join(os.getcwd(), "handoff_uploads")
os.makedirs(HANDOFF_UPLOAD_DIR, exist_ok=True)

@app.context_processor
def inject_brand():
    return {
        "BRAND_NAME": app.config.get("BRAND_NAME"),
        "BRAND_LOGO": app.config.get("BRAND_LOGO"),
    }

# Optional favicon passthrough from /static
@app.route("/favicon.ico")
def favicon():
    fav_path = os.path.join(app.static_folder or "static", "favicon.ico")
    if os.path.exists(fav_path):
        return send_from_directory(app.static_folder, "favicon.ico")
    return ("", 204)


# -----------------------------------------------------------------------------
# Thank-you events (anti-queue)
# -----------------------------------------------------------------------------
from collections import deque
from threading import Lock as _Lock

_THANKYOU_SEQ = 0
_THANKYOU_EVENTS = deque(maxlen=50)
_THANKYOU_LOCK = _Lock()
_TY_TTL_MS = 1500  # Only show events that are this recent to avoid queued popups

def _emit_thankyou(emp_id: str | None, name: str | None, medium: str):
    """Record a thank_you event and bump a global sequence counter."""
    global _THANKYOU_SEQ
    with _THANKYOU_LOCK:
        _THANKYOU_SEQ += 1
        _THANKYOU_EVENTS.append({
            "seq": _THANKYOU_SEQ,
            "ts": datetime.now().isoformat(timespec="seconds"),
            "ts_ms": int(time.time() * 1000),
            "emp_id": (emp_id or ""),
            "name": (name or ""),
            "medium": medium,
        })

# Streaming endpoint used by user.html thank-you watcher
@app.route("/api/thankyou_events")
def api_thankyou_events():
    """
    Client polls with /api/thankyou_events?since=<seq>
    Returns only the freshest recent event (TTL) and the latest global seq.
    """
    try:
        since = int(request.args.get("since", 0))
    except Exception:
        since = 0
    now_ms = int(time.time() * 1000)
    with _THANKYOU_LOCK:
        recent = [e for e in list(_THANKYOU_EVENTS)
                  if e["seq"] > since and (now_ms - e.get("ts_ms", now_ms)) <= _TY_TTL_MS]
        latest_seq = _THANKYOU_SEQ
    events = recent[-1:] if recent else []
    return jsonify({"events": events, "latest_seq": latest_seq})


# -----------------------------------------------------------------------------
# Admin / DB constants
# -----------------------------------------------------------------------------
ADMIN_PW_FILE = "admin_pw.txt"
DB_PATH = "users.db"

# --- Prevent client/proxy caching for all JSON endpoints and streams ---
@app.after_request
def add_no_cache_headers(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


# -----------------------------------------------------------------------------
# DB initialization and schema
# -----------------------------------------------------------------------------
def create_users_table():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # core users + related tables
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        emp_id TEXT PRIMARY KEY,
        name TEXT,
        display_image BLOB,
        face_encoding BLOB,
        rfid_cards TEXT,
        role TEXT DEFAULT 'User',
        birthdate TEXT,
        template_id INTEGER
    )
    """)
    c.execute('''CREATE TABLE IF NOT EXISTS shifts (
        shift_code TEXT PRIMARY KEY,
        shift_name TEXT NOT NULL,
        from_time TEXT NOT NULL,
        to_time TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS time_slots (
        slot_code TEXT PRIMARY KEY,
        shift_code TEXT NOT NULL,
        slot_name TEXT NOT NULL,
        from_time TEXT NOT NULL,
        to_time TEXT NOT NULL,
        FOREIGN KEY (shift_code) REFERENCES shifts(shift_code) ON DELETE CASCADE
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS menu_codes (
        menu_code TEXT PRIMARY KEY,
        slot_code TEXT NOT NULL,
        menu_name TEXT NOT NULL,
        FOREIGN KEY (slot_code) REFERENCES time_slots(slot_code) ON DELETE CASCADE
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS items (
        item_code TEXT PRIMARY KEY,
        menu_code TEXT NOT NULL,
        item_name TEXT NOT NULL,
        FOREIGN KEY (menu_code) REFERENCES menu_codes(menu_code) ON DELETE CASCADE
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS item_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        item_name TEXT NOT NULL,
        item_limit INTEGER NOT NULL
    )''')

    # fingerprints table (unified)
    c.execute('''CREATE TABLE IF NOT EXISTS fingerprints (
        id INTEGER PRIMARY KEY,
        username TEXT,
        template BLOB NOT NULL
    )''')

    # local queue for PG events (offline-first)
    c.execute("""
    CREATE TABLE IF NOT EXISTS pg_event_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_time TEXT NOT NULL,
        device_ip TEXT,
        emp_id TEXT,
        name TEXT,
        role TEXT,
        medium TEXT NOT NULL,
        success INTEGER NOT NULL,
        payload TEXT
    )
    """)

    # simple app settings key-value store
    c.execute("""
    CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)

    # Orders table (for kiosk orders)
    c.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id TEXT UNIQUE NOT NULL,
        emp_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        shift_code TEXT,
        slot_code TEXT,
        category TEXT NOT NULL,
        item_code TEXT NOT NULL,
        item_name TEXT NOT NULL,
        qty INTEGER NOT NULL DEFAULT 1,
        order_time TEXT NOT NULL
    )
    """)

    # slot-limit tables
    c.execute("""
    CREATE TABLE IF NOT EXISTS user_slot_limits (
        emp_id          TEXT NOT NULL,
        slot_code       TEXT NOT NULL,
        per_item_max    INTEGER,
        slot_total_max  INTEGER,
        daily_total_max INTEGER,
        PRIMARY KEY(emp_id, slot_code)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS default_slot_limits (
        slot_code       TEXT PRIMARY KEY,
        per_item_max    INTEGER,
        slot_total_max  INTEGER,
        daily_total_max INTEGER
    )
    """)

    c.execute("CREATE INDEX IF NOT EXISTS idx_orders_emp_cat_time ON orders(emp_id, category, order_time)")

    # mapping table (emp_id -> template_id)
    c.execute("""
    CREATE TABLE IF NOT EXISTS user_finger_map (
        emp_id      TEXT PRIMARY KEY,
        template_id INTEGER UNIQUE
    )
    """)

    # canonical fingerprint_map table
    c.execute("""
    CREATE TABLE IF NOT EXISTS fingerprint_map(
        emp_id TEXT PRIMARY KEY,
        template_id INTEGER UNIQUE NOT NULL,
        name TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )
    """)

    # mesh devices table (needed by enqueue_sync_to_all_devices)
    c.execute("""
    CREATE TABLE IF NOT EXISTS mesh_devices (
        ip TEXT PRIMARY KEY,
        device_id TEXT,
        name TEXT,
        port INTEGER
    )
    """)

    # udp_queue (store outgoing reliable UDP messages)
    c.execute(f"""
    CREATE TABLE IF NOT EXISTS udp_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        device_ip TEXT NOT NULL,
        device_port INTEGER NOT NULL DEFAULT {UDP_PORT},
        message_id TEXT NOT NULL,
        message_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0,
        last_attempt TEXT,
        last_error TEXT
    )
    """)

    conn.commit()
    conn.close()


def ensure_logs_table():
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            device_ip TEXT,
            emp_id TEXT,
            name TEXT,
            role TEXT,
            medium TEXT,
            success INTEGER,
            payload TEXT
        )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        print("[DB] ensure_logs_table error:", e)



# create tables and ensure optional helper tables exist



def has_column(table: str, column: str) -> bool:
    conn = get_db_connection()
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        cols = {r[1] for r in rows}  # (cid, name, type, ...)
        return column in cols
    finally:
        conn.close()

def ensure_schema_migrations():
    """
    Make sure required columns/tables exist:
    - users.template_id INTEGER
    - user_finger_map(emp_id, template_id)
    - fingerprint_map(emp_id, template_id, name, created_at)
    """
    conn = get_db_connection()
    try:
        # users.template_id
        if not has_column("users", "template_id"):
            conn.execute("ALTER TABLE users ADD COLUMN template_id INTEGER")
            conn.commit()

        # users.birthdate (your schema has it; keep this guard for older DBs)
        if not has_column("users", "birthdate"):
            conn.execute("ALTER TABLE users ADD COLUMN birthdate TEXT")
            conn.commit()

        # user_finger_map
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_finger_map(
                emp_id      TEXT PRIMARY KEY,
                template_id INTEGER UNIQUE
            )
        """)

        # fingerprint_map (canonical)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS fingerprint_map(
                emp_id      TEXT PRIMARY KEY,
                template_id INTEGER UNIQUE NOT NULL,
                name        TEXT,
                created_at  TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.commit()
    finally:
        conn.close()



def _safe_sqlite_alter(conn, sql):
    try:
        conn.execute(sql)
        conn.commit()
    except Exception:
        pass

def migrate_sqlite_schema():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    _safe_sqlite_alter(conn, "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'User'")
    _safe_sqlite_alter(conn, "ALTER TABLE pg_event_queue ADD COLUMN role TEXT")
    _safe_sqlite_alter(conn, "ALTER TABLE users ADD COLUMN birthdate TEXT")
    conn.close()

migrate_sqlite_schema()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


# --- Mesh discovery helpers (place after get_db_connection and schema setup) ---
import math, uuid, socket

UDP_PORT = 5006              # choose same port for all devices
UDP_CHUNK_SIZE = 1200        # safe payload chunk size
UDP_ACK_TIMEOUT = 2.0
UDP_MAX_RETRIES = 6

def discovery_broadcast_once(bcast_ip='<broadcast>', port=UDP_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    pkt = {
        "type": "discover",
        "device_id": get_setting("device_id", f"CANT_{uuid.uuid4().hex[:6]}"),
        "name": get_setting("device_name", None),
        "port": port,
        "ts": _now_iso()
    }
    try:
        s.sendto(json.dumps(pkt).encode('utf-8'), (bcast_ip, port))
    finally:
        s.close()

def discovery_listener(stop_evt, bind_ip='0.0.0.0', port=UDP_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port))
    s.settimeout(1.0)
    while not stop_evt.is_set():
        try:
            data, addr = s.recvfrom(65536)
            ip = addr[0]
            try:
                j = json.loads(data.decode('utf-8', errors='ignore'))
            except Exception:
                continue
            if j.get("type") == "discover":
                # reply hello
                hello = {"type":"device_hello", "device_id": get_setting("device_id", f"CANT_{uuid.uuid4().hex[:6]}"),
                         "name": get_setting("device_name","CanteenDevice"), "port": port, "ts": _now_iso()}
                s.sendto(json.dumps(hello).encode('utf-8'), addr)
            elif j.get("type") == "device_hello":
                device_id = j.get("device_id")
                name = j.get("name") or device_id
                conn = get_db_connection()
                try:
                    conn.execute("INSERT OR REPLACE INTO mesh_devices (ip, device_id, name, port) VALUES (?, ?, ?, ?)",
                                 (ip, device_id, name, int(j.get("port", port))))
                    conn.commit()
                finally:
                    conn.close()
        except socket.timeout:
            continue
        except Exception:
            time.sleep(0.05)
    try: s.close()
    except Exception: pass


# --- Reliable-enqueue (high level) ---
def reliable_udp_send_to(ip: str, port: int, payload: dict, message_type: str="generic"):
    """
    Persist a message into udp_queue (so worker can send reliably).
    Returns message_id.
    """
    mid = str(uuid.uuid4())
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO udp_queue (created_at, device_ip, device_port, message_id, message_type, payload, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_now_iso(), ip, port, mid, message_type, json.dumps(payload), 'pending')
        )
        conn.commit()
    finally:
        conn.close()
    return mid

def enqueue_sync_to_all_devices(message_type: str, payload: dict):
    """
    Enqueue this payload to all devices currently in mesh_devices table.
    Call this after DB commit in registration/edit/delete endpoints.
    """
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT ip, port FROM mesh_devices").fetchall()
        for r in rows:
            try:
                reliable_udp_send_to(r["ip"], int(r["port"] or UDP_PORT), payload, message_type)
            except Exception as e:
                print("[ENQUEUE] failed for", r["ip"], e)
    finally:
        conn.close()


# --- UDP queue worker: chunk + send + wait for ACK ---
def _build_chunks(message_id: str, payload_bytes: bytes):
    total = math.ceil(len(payload_bytes) / UDP_CHUNK_SIZE) or 1
    chunks = []
    for i in range(total):
        start = i * UDP_CHUNK_SIZE
        chunk_payload = payload_bytes[start:start + UDP_CHUNK_SIZE]
        header = json.dumps({"type":"chunk","message_id":message_id,"chunk_index":i,"total_chunks":total}).encode('utf-8') + b"\n"
        chunks.append(header + chunk_payload)
    return chunks

def udp_queue_worker(stop_evt, poll_interval=1.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.6)
    while not stop_evt.is_set():
        try:
            conn = get_db_connection()
            rows = conn.execute("SELECT id, device_ip, device_port, message_id, message_type, payload, attempts FROM udp_queue WHERE status IN ('pending','sending') ORDER BY id ASC LIMIT 20").fetchall()
            conn.close()
            if not rows:
                time.sleep(poll_interval); continue
            for r in rows:
                qid = r["id"]; ip = r["device_ip"]; port = int(r["device_port"]); mid = r["message_id"]
                attempts = int(r["attempts"] or 0)
                if attempts >= UDP_MAX_RETRIES:
                    conn = get_db_connection()
                    try:
                        conn.execute("UPDATE udp_queue SET status=?, last_attempt=?, last_error=? WHERE id=?", ('failed', _now_iso(), f"max_retries({attempts})", qid))
                        conn.commit()
                    finally:
                        conn.close()
                    continue
                # mark sending
                conn = get_db_connection()
                try:
                    conn.execute("UPDATE udp_queue SET status=?, attempts=?, last_attempt=? WHERE id=?", ('sending', attempts+1, _now_iso(), qid))
                    conn.commit()
                finally:
                    conn.close()
                payload = json.loads(r["payload"])
                envelope = {"message_id": mid, "type": r["message_type"], "created_at": _now_iso(), "payload": payload}
                env_bytes = json.dumps(envelope, separators=(',',':')).encode('utf-8')
                chunks = _build_chunks(mid, env_bytes)
                try:
                    for c in chunks:
                        try: sock.sendto(c, (ip, port))
                        except Exception: pass
                        time.sleep(0.03)
                    # wait for ack
                    acked = False
                    tstart = time.time()
                    while time.time() - tstart < UDP_ACK_TIMEOUT * 2:
                        try:
                            data, addr = sock.recvfrom(4096)
                            try: j = json.loads(data.decode('utf-8', errors='ignore'))
                            except Exception: continue
                            if j.get("type") == "ack" and j.get("message_id") == mid:
                                acked = True; break
                        except socket.timeout:
                            pass
                    if acked:
                        conn = get_db_connection()
                        try:
                            conn.execute("UPDATE udp_queue SET status=?, last_attempt=? WHERE id=?", ('acked', _now_iso(), qid))
                            conn.commit()
                        finally:
                            conn.close()
                    else:
                        conn = get_db_connection()
                        try:
                            conn.execute("UPDATE udp_queue SET status=?, last_attempt=? WHERE id=?", ('pending', _now_iso(), qid))
                            conn.commit()
                        finally:
                            conn.close()
                except Exception as e:
                    conn = get_db_connection()
                    try:
                        conn.execute("UPDATE udp_queue SET status=?, last_attempt=?, last_error=? WHERE id=?", ('pending', _now_iso(), str(e), qid))
                        conn.commit()
                    finally:
                        conn.close()
        except Exception:
            time.sleep(0.5)
    try: sock.close()
    except Exception: pass



# ========= NEW: ensure logs table =========
def ensure_logs_table():
    try:
        conn = get_db_connection()
        try:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                emp_id TEXT,
                name TEXT,
                device_id TEXT,
                mode TEXT,
                ts TEXT NOT NULL
            )
            """)
            # Helpful indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_emp_ts ON logs(emp_id, ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_emp ON logs(emp_id)")
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print("[init] ensure_logs_table failed:", e)


def get_setting(key, default=None):
    conn = get_db_connection()
    row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    conn.close()
    if row and row["value"] is not None:
        return row["value"]
    return default


def set_setting(key, value):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO app_settings(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value)
    )
    conn.commit()
    conn.close()


create_users_table()
ensure_logs_table()
migrate_sqlite_schema()
ensure_schema_migrations()


# -----------------------------------------------------------------------------
# Postgres configuration and helpers
# -----------------------------------------------------------------------------
PGCFG = {}  # will be filled by load_pgcfg_from_settings()
PG_CONNECT_TIMEOUT = 3  # seconds

def load_pgcfg_from_settings():
    """Load DB creds from SQLite settings; set sane defaults if missing."""
    host = get_setting("pg_host", "192.168.1.3")
    port = int(get_setting("pg_port", "5432") or "5432")
    dbname = get_setting("pg_dbname", "postgres")
    user = get_setting("pg_user", "postgres")
    password = get_setting("pg_password", "postgres")
    global PGCFG
    PGCFG = {
        "host": host,
        "port": port,
        "dbname": dbname,
        "user": user,
        "password": password,
    }

@app.route("/modes")
def modes_page():
    return render_template("modes.html")

def _bool_from_setting(val, default=True):
    if val is None:
        return bool(default)
    s = str(val).strip().lower()
    return s in ("1", "true", "yes", "on")

@app.route("/api/modes_get")
def modes_get():
    data = {
        "conn_wifi":     _bool_from_setting(get_setting("conn_wifi", "1"),     True),
        "conn_mesh":     _bool_from_setting(get_setting("conn_mesh", "1"),     True),
        "conn_postgres": _bool_from_setting(get_setting("conn_postgres", "1"), True),
        "auth_face":     _bool_from_setting(get_setting("auth_face", "1"),     True),
        "auth_finger":   _bool_from_setting(get_setting("auth_finger", "1"),   True),
        "auth_rfid":     _bool_from_setting(get_setting("auth_rfid", "1"),     True),
    }
    return jsonify(data)

@app.route("/api/modes_set", methods=["POST"])
def modes_set():
    payload = request.get_json(force=True) or {}
    def to_store_bool(v, default=True):
        if isinstance(v, bool):
            return "1" if v else "0"
        if v is None:
            return "1" if default else "0"
        s = str(v).strip().lower()
        truthy = s in ("1", "true", "yes", "on")
        falsy  = s in ("0", "false", "no", "off")
        if truthy:
            return "1"
        if falsy:
            return "0"
        return "1" if default else "0"

    set_setting("conn_wifi",     to_store_bool(payload.get("conn_wifi"),     True))
    set_setting("conn_mesh",     to_store_bool(payload.get("conn_mesh"),     True))
    set_setting("conn_postgres", to_store_bool(payload.get("conn_postgres"), True))
    set_setting("auth_face",     to_store_bool(payload.get("auth_face"),     True))
    set_setting("auth_finger",   to_store_bool(payload.get("auth_finger"),   True))
    set_setting("auth_rfid",     to_store_bool(payload.get("auth_rfid"),     True))
    return jsonify({"success": True})

def pg_connect():
    return psycopg2.connect(
        host=PGCFG["host"],
        port=PGCFG["port"],
        dbname=PGCFG["dbname"],
        user=PGCFG["user"],
        password=PGCFG["password"],
        connect_timeout=PG_CONNECT_TIMEOUT,
    )

def ensure_pg_table():
    try:
        conn = pg_connect()
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS login_events (
                    id BIGSERIAL PRIMARY KEY,
                    event_time TIMESTAMPTZ NOT NULL DEFAULT now(),
                    device_ip INET,
                    emp_id TEXT,
                    name TEXT,
                    role TEXT,
                    medium TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    payload JSONB
                );
                """
            )
            cur.execute("ALTER TABLE login_events ADD COLUMN IF NOT EXISTS role TEXT;")
        conn.close()
    except Exception as e:
        print(f"[PG] ensure_pg_table error: {e}")

def pg_is_available() -> bool:
    try:
        conn = pg_connect()
        conn.close()
        return True
    except Exception:
        return False

def get_user_role(emp_id: str) -> str:
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT role FROM users WHERE emp_id=?", (str(emp_id),)).fetchone()
        conn.close()
        if row and row["role"]:
            return row["role"]
    except Exception:
        pass
    return "User"

def pg_log_event_or_queue(emp_id, name, medium, success, payload: dict):
    role = get_user_role(emp_id) if emp_id else None
    try:
        conn = pg_connect()
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS login_events (
                    id BIGSERIAL PRIMARY KEY,
                    event_time TIMESTAMPTZ NOT NULL DEFAULT now(),
                    device_ip INET,
                    emp_id TEXT,
                    name TEXT,
                    role TEXT,
                    medium TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    payload JSONB
                );
                """
            )
            cur.execute(
                """
                INSERT INTO login_events (device_ip, emp_id, name, role, medium, success, payload)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb);
                """,
                (
                    get_self_ip(),
                    str(emp_id) if emp_id is not None else None,
                    name,
                    role,
                    medium,
                    bool(success),
                    json.dumps(payload or {}),
                ),
            )
        conn.close()
        return True
    except Exception:
        try:
            conn = get_db_connection()
            conn.execute(
                """
                INSERT INTO pg_event_queue
                (event_time, device_ip, emp_id, name, role, medium, success, payload)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    datetime.now().isoformat(timespec="seconds"),
                    get_self_ip(),
                    str(emp_id) if emp_id is not None else None,
                    name,
                    role,
                    medium,
                    1 if success else 0,
                    json.dumps(payload or {}),
                ),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[PG] enqueue failed (ignored): {e}")
        return False


# -----------------------------------------------------------------------------
# Background PG Sync
# -----------------------------------------------------------------------------
_last_sync_info = {"last_ok": None, "last_err": None}

def drain_pg_queue_once(max_batch=200):
    if not pg_is_available():
        raise RuntimeError("PG not available")
    ensure_pg_table()
    conn_local = get_db_connection()
    rows = conn_local.execute(
        "SELECT id, event_time, device_ip, emp_id, name, role, medium, success, payload "
        "FROM pg_event_queue ORDER BY id ASC LIMIT ?", (max_batch,)
    ).fetchall()
    if not rows:
        conn_local.close()
        return 0
    conn_pg = pg_connect()
    conn_pg.autocommit = True
    cur = conn_pg.cursor()
    inserted_ids = []
    try:
        for r in rows:
            cur.execute(
                """
                INSERT INTO login_events (event_time, device_ip, emp_id, name, role, medium, success, payload)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb);
                """,
                (
                    r["event_time"], r["device_ip"], r["emp_id"], r["name"], r["role"],
                    r["medium"], bool(r["success"]), r["payload"] or "{}",
                ),
            )
            inserted_ids.append(r["id"])
    finally:
        cur.close()
        conn_pg.close()
    if inserted_ids:
        conn_local.executemany(
            "DELETE FROM pg_event_queue WHERE id = ?",
            [(rid,) for rid in inserted_ids]
        )
        conn_local.commit()
    conn_local.close()
    return len(inserted_ids)

def pg_sync_worker(stop_evt: Event, poll_ok=5, poll_empty=10, poll_fail=20):
    while not stop_evt.is_set():
        try:
            count = drain_pg_queue_once()
            if count > 0:
                _last_sync_info["last_ok"] = f"{datetime.now().isoformat(timespec='seconds')} (drained {count})"
                time.sleep(poll_ok)
            else:
                _last_sync_info["last_ok"] = f"{datetime.now().isoformat(timespec='seconds')} (empty)"
                time.sleep(poll_empty)
        except Exception as e:
            _last_sync_info["last_err"] = f"{datetime.now().isoformat(timespec='seconds')}: {e}"
            time.sleep(poll_fail)


# -----------------------------------------------------------------------------
# Admin password helpers
# -----------------------------------------------------------------------------
def get_admin_password():
    if not os.path.exists(ADMIN_PW_FILE):
        with open(ADMIN_PW_FILE, "w") as f:
            f.write(hashlib.sha256("admin".encode()).hexdigest())
        return hashlib.sha256("admin".encode()).hexdigest()
    with open(ADMIN_PW_FILE, "r") as f:
        return f.read().strip()

def set_admin_password(new_pw):
    with open(ADMIN_PW_FILE, "w") as f:
        f.write(hashlib.sha256(new_pw.encode()).hexdigest())

def check_admin_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest() == get_admin_password()


# Load DB config from settings BEFORE anything touches PG
load_pgcfg_from_settings()

# -----------------------------------------------------------------------------
# Fingerprint DB (unified in users.db)
# -----------------------------------------------------------------------------
def get_finger_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)  # unified DB
    db.row_factory = sqlite3.Row
    db.execute('''CREATE TABLE IF NOT EXISTS fingerprints (
        id INTEGER PRIMARY KEY,
        username TEXT,
        template BLOB NOT NULL
    )''')
    return db

# ---------- Template-ID allocation helpers ----------
def _first_free_template_id(conn) -> int:
    used = set()
    for r in conn.execute("SELECT id FROM fingerprints"):
        try:
            used.add(int(r["id"]))
        except Exception:
            pass
    for r in conn.execute("SELECT template_id FROM user_finger_map WHERE template_id IS NOT NULL"):
        try:
            used.add(int(r["template_id"]))
        except Exception:
            pass

    tid = 1
    while tid in used:
        tid += 1
    return tid

def get_or_reserve_template_id(emp_id: str) -> tuple[int, bool]:
    emp_id = str(emp_id).strip()
    if not emp_id:
        raise ValueError("emp_id required")

    conn = get_db_connection()
    try:
        r = conn.execute("SELECT template_id FROM user_finger_map WHERE emp_id=?", (emp_id,)).fetchone()
        if r and r["template_id"] is not None:
            return int(r["template_id"]), False

        tid = _first_free_template_id(conn)
        conn.execute(
            "INSERT INTO user_finger_map(emp_id, template_id) VALUES (?, ?) "
            "ON CONFLICT(emp_id) DO UPDATE SET template_id=excluded.template_id",
            (emp_id, tid)
        )
        conn.commit()
        return tid, True
    finally:
        conn.close()

def get_template_id_if_any(emp_id: str) -> int | None:
    emp_id = str(emp_id).strip()
    if not emp_id:
        return None
    conn = get_db_connection()
    try:
        r = conn.execute("SELECT template_id FROM user_finger_map WHERE emp_id=?", (emp_id,)).fetchone()
        return int(r["template_id"]) if r and r["template_id"] is not None else None
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Start PG sync background worker and ensure PG table at boot
# -----------------------------------------------------------------------------
_pg_stop_event = Event()
threading.Thread(target=pg_sync_worker, args=(_pg_stop_event,), daemon=True).start()

if pg_is_available():
    ensure_pg_table()


# -----------------------------------------------------------------------------
# Canteen open/close logic
# -----------------------------------------------------------------------------
def get_current_time_ui():
    return datetime.now().strftime('%H:%M')

def is_canteen_open_ui():
    db = get_db_connection()
    now = get_current_time_ui()
    row = db.execute("SELECT * FROM time_slots WHERE from_time <= ? AND to_time >= ?", (now, now)).fetchone()
    db.close()
    return bool(row)

def get_next_opening_ui():
    db = get_db_connection()
    now = get_current_time_ui()
    row = db.execute("SELECT from_time FROM time_slots WHERE from_time > ? ORDER BY from_time ASC LIMIT 1", (now,)).fetchone()
    db.close()
    return row[0] if row else None


# -----------------------------------------------------------------------------
# Slot-aware helpers, limits, device ID, and ordering
# -----------------------------------------------------------------------------
def get_device_id():
    val = get_setting("device_id", "CANT_A_001")
    return (val or "CANT_A_001").strip().upper()

def set_device_id_safe(value: str):
    if not re.fullmatch(r"CANT_[A-Z]_[0-9]{3}", (value or "").strip().upper()):
        raise ValueError("Device ID must look like CANT_A_001")
    set_setting("device_id", value.strip().upper())

def _now_iso():
    return datetime.now().isoformat(timespec="seconds")

def get_current_slot_row():
    db = get_db_connection()
    now = get_current_time_ui()
    row = db.execute("""
        SELECT ts.*, sh.shift_name
        FROM time_slots ts
        JOIN shifts sh ON sh.shift_code = ts.shift_code
        WHERE ts.from_time <= ? AND ts.to_time >= ?
        ORDER BY ts.from_time LIMIT 1
    """, (now, now)).fetchone()
    db.close()
    return row

def generate_order_id():
    return f"ORD-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"

def _get_category_limit(db, category: str, item_name: str):
    r = db.execute("SELECT item_limit FROM item_limits WHERE category=? AND item_name=? LIMIT 1",
                   (category, item_name)).fetchone()
    if r: return int(r["item_limit"])
    r = db.execute("SELECT item_limit FROM item_limits WHERE category=? AND item_name='*' LIMIT 1",
                   (category,)).fetchone()
    return int(r["item_limit"]) if r else 1

def _count_taken_today(db, emp_id: str, category: str):
    return db.execute("""
        SELECT COUNT(*) AS c
        FROM orders
        WHERE emp_id=? AND category=? AND DATE(order_time)=DATE('now','localtime')
    """, (emp_id, category)).fetchone()["c"]

def print_order_receipt(order_id, emp_id, item_name, category, slot_name, shift_name):
    text = (
        f"CANTEEN ORDER\n"
        f"{'-'*28}\n"
        f"Device : {get_device_id()}\n"
        f"Order  : {order_id}\n"
        f"Emp ID : {emp_id}\n"
        f"Item   : {item_name}\n"
        f"Cat    : {category}\n"
        f"Shift  : {shift_name or ''}\n"
        f"Slot   : {slot_name or ''}\n"
        f"Time   : {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}\n"
    )
    try:
        print_user_id_and_cut(text)  # prints text and auto-cuts
    except Exception as e:
        print(f"[Printer] order slip error: {e}")

def _today_datestr():
    return date.today().isoformat()

def get_active_slot_code():
    slot = get_current_slot_row()
    return (slot["slot_code"] if slot else None, slot)

def get_slot_limits(conn, emp_id: str, slot_code: str):
    row = conn.execute("""
        SELECT per_item_max, slot_total_max, daily_total_max
        FROM user_slot_limits
        WHERE emp_id=? AND slot_code=?
        LIMIT 1
    """, (emp_id, slot_code)).fetchone()
    if row:
        return dict(row)
    row = conn.execute("""
        SELECT per_item_max, slot_total_max, daily_total_max
        FROM default_slot_limits
        WHERE slot_code=?
        LIMIT 1
    """, (slot_code,)).fetchone()
    return (dict(row) if row else {"per_item_max": None, "slot_total_max": None, "daily_total_max": None})

def get_usage_today(conn, emp_id: str, slot_code: str):
    r = conn.execute("""
        SELECT COALESCE(SUM(qty),0) AS total
        FROM orders
        WHERE emp_id=? AND slot_code=? AND DATE(order_time)=DATE('now','localtime')
    """, (emp_id, slot_code)).fetchone()
    slot_total_today = int(r["total"])
    r = conn.execute("""
        SELECT COALESCE(SUM(qty),0) AS total
        FROM orders
        WHERE emp_id=? AND DATE(order_time)=DATE('now','localtime')
    """, (emp_id,)).fetchone()
    day_total_today = int(r["total"])
    rows = conn.execute("""
        SELECT item_code, COALESCE(SUM(qty),0) AS qty
        FROM orders
        WHERE emp_id=? AND slot_code=? AND DATE(order_time)=DATE('now','localtime')
        GROUP BY item_code
    """, (emp_id, slot_code)).fetchall()
    per_item_today = {str(rr["item_code"]): int(rr["qty"]) for rr in rows} if rows else {}
    return {
        "slot_total_today": slot_total_today,
        "day_total_today": day_total_today,
        "per_item_today": per_item_today
    }

class SlotLimitError(Exception):
    def __init__(self, code: str, message: str, meta: dict | None = None):
        super().__init__(message)
        self.code = code
        self.meta = meta or {}

def validate_items_against_limits(conn, *, emp_id: str, slot_code: str, grouped_items: dict[str,int]):
    limits = get_slot_limits(conn, emp_id, slot_code)
    per_item_max    = limits.get("per_item_max")
    slot_total_max  = limits.get("slot_total_max")
    daily_total_max = limits.get("daily_total_max")
    usage = get_usage_today(conn, emp_id, slot_code)
    used_per_item   = usage["per_item_today"]
    used_slot_total = usage["slot_total_today"]
    used_day_total  = usage["day_total_today"]
    order_total_qty = sum(max(0, int(q)) for q in grouped_items.values())
    if per_item_max is not None:
        for code, q in grouped_items.items():
            q = max(0, int(q))
            already = int(used_per_item.get(str(code), 0))
            if already + q > int(per_item_max):
                raise SlotLimitError(
                    "per_item_exceeded",
                    f"Per-item limit exceeded for {code}.",
                    {"item_code": code, "limit": int(per_item_max), "used": already, "requested": q,
                     "remaining": max(0, int(per_item_max) - already)}
                )
    if slot_total_max is not None:
        if used_slot_total + order_total_qty > int(slot_total_max):
            raise SlotLimitError(
                "slot_total_exceeded",
                "Slot total exceeded.",
                {"limit": int(slot_total_max), "used": used_slot_total,
                 "requested": order_total_qty,
                 "remaining": max(0, int(slot_total_max) - used_slot_total)}
            )
    if daily_total_max is not None:
        if used_day_total + order_total_qty > int(daily_total_max):
            raise SlotLimitError(
                "daily_total_exceeded",
                "Daily total (across slots) limit exceeded.",
                {"limit": int(daily_total_max), "used": used_day_total,
                 "requested": order_total_qty,
                 "remaining": max(0, int(daily_total_max) - used_day_total)}
            )
    return {
        "ok": True,
        "limits": limits,
        "used": usage,
        "order_total_qty": order_total_qty
    }

def group_items_for_limits(conn, items_in: list):
    grouped: dict[str,int] = {}
    for raw in items_in:
        code, qty = _resolve_item_full(conn, raw)
        if not code:
            continue
        qty = int(qty) if str(qty).isdigit() else 1
        if qty <= 0: qty = 1
        grouped[code] = grouped.get(code, 0) + qty
    return grouped


# -----------------------------------------------------------------------------
# UI routes
# -----------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/menu')
def menu():
    session.pop("admin_session_active", None)
    session.pop("admin_emp_id", None)
    return render_template('menu.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/user')
def user():
    return render_template('user.html')

@app.route("/register")
def register():
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop("admin_session_active", None)
    session.pop("admin_emp_id", None)
    return redirect(url_for("menu"))

@app.route('/edit')
def edit():
    return render_template('edit.html')

@app.route('/delete')
def delete():
    return render_template('delete.html')

@app.route("/finger_user")
def finger_user():
    return render_template("finger_user.html")

@app.route("/finger_register")
def finger_register():
    return render_template("finger_register.html")

@app.route("/finger_edit")
def finger_edit():
    return render_template("finger_edit.html")

@app.route("/finger_delete")
def finger_delete():
    return render_template("finger_delete.html")

@app.route("/rfid_user")
def rfid_user_page():
    return render_template("rfid_user.html")

@app.route("/rfid_register")
def rfid_register_page():
    return render_template("rfid_register.html")

@app.route("/rfid_edit")
def rfid_edit():
    return render_template("rfid_edit.html")

@app.route("/rfid_delete")
def rfid_delete():
    return render_template("rfid_delete.html")

@app.route('/diagnostic')
def diagnostic_page():
    return render_template('diagnostic.html')

@app.route("/api/diagnostic")
def api_diagnostic():
    import diagnostic
    try:
        results = diagnostic.run_diagnostic(json_mode=True)
        return jsonify(results=results)
    except Exception as e:
        return jsonify(results=[{"name": "Error", "ok": False, "info": str(e)}])

# Themed Import/Export desktop pages (you supplied these templates)
@app.route("/import")
def import_page():
    return render_template("import.html")

@app.route("/export")
def export_page():
    return render_template("export.html")


# -----------------------------------------------------------------------------
# Camera (live stream) — single authoritative implementation (no duplicates)
# -----------------------------------------------------------------------------
picam2_instance = None
vcap_instance = None
_cam_lock = Lock()
_CAM_SIZE = (640, 480)

def _init_camera_locked():
    global picam2_instance, vcap_instance
    if picam2_instance or vcap_instance:
        return
    if Picamera2 is not None:
        try:
            _p = Picamera2()
            _p.configure(_p.create_preview_configuration(
                main={"format": "YUV420", "size": _CAM_SIZE}
            ))
            _p.start()
            time.sleep(0.4)
            picam2_instance = _p
            return
        except Exception as e:
            print(f"[CAM] PiCamera2 unavailable: {e}. Falling back to OpenCV webcam...")
    cap = cv2.VideoCapture(0, cv2.CAP_V4L2)
    if not cap or not cap.isOpened():
        raise RuntimeError("No camera found (PiCamera2 and /dev/video0 both unavailable)")
    cap.set(cv2.CAP_PROP_FRAME_WIDTH,  _CAM_SIZE[0])
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, _CAM_SIZE[1])
    vcap_instance = cap

def _yuv420_to_bgr(yuv, size):
    w, h = size
    if yuv.ndim == 2 and yuv.shape[0] == h * 3 // 2 and yuv.shape[1] == w:
        return cv2.cvtColor(yuv, cv2.COLOR_YUV2BGR_I420)
    if yuv.ndim == 3 and yuv.shape[0] == h and yuv.shape[1] == w and yuv.shape[2] in (2, 3):
        try:
            return cv2.cvtColor(yuv, cv2.COLOR_YUV2BGR_NV12)
        except Exception:
            pass
    return yuv

def get_live_frame_bgr():
    global picam2_instance, vcap_instance
    with _cam_lock:
        if not (picam2_instance or vcap_instance):
            _init_camera_locked()
        if picam2_instance:
            yuv = picam2_instance.capture_array("main")
            if yuv is None:
                raise RuntimeError("PiCamera2 capture returned None")
            frame_bgr = _yuv420_to_bgr(yuv, _CAM_SIZE)
            return frame_bgr
        ok, frame_bgr = vcap_instance.read()
        if not ok or frame_bgr is None:
            raise RuntimeError("Webcam frame read failed")
        return frame_bgr

def gen_frames():
    while True:
        try:
            bgr = get_live_frame_bgr()
            ret, buffer = cv2.imencode('.jpg', bgr)
            if not ret:
                continue
            frame_bytes = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
        except Exception as e:
            print(f"[CAM] gen_frames error: {e}")
            time.sleep(0.25)

@app.route('/video_feed')
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/api/show_keyboard')
def show_keyboard():
    return ('', 204)


# -----------------------------------------------------------------------------
# Serve stored user images (for register.html HEAD check)
# -----------------------------------------------------------------------------
USERS_IMG_DIR = os.path.join(os.getcwd(), "users")
os.makedirs(USERS_IMG_DIR, exist_ok=True)

@app.route("/users/<path:filename>", methods=["GET", "HEAD"])
def serve_user_image(filename):
    if not re.fullmatch(r"[A-Za-z0-9_\-\.]+", filename):
        return abort(404)
    path = os.path.join(USERS_IMG_DIR, filename)
    if not os.path.isfile(path):
        return abort(404)
    return send_from_directory(USERS_IMG_DIR, filename)


# -----------------------------------------------------------------------------
# Lightweight NO-MESH STUBS (mesh/TCP/UDP removed)
# -----------------------------------------------------------------------------
def load_mesh_state():
    """Mesh removed — return empty state so callers behave normally."""
    return {}

def send_udp_json(ip, port, payload):
    """Mesh removed — log and ignore."""
    try:
        print(f"[NET-UDP-STUB] Would send to {ip}:{port} payload keys: {list(payload.keys())}")
    except Exception:
        pass
    return False

def broadcast_tcp(payload):
    """Mesh removed — log and ignore."""
    try:
        print(f"[NET-TCP-STUB] Would broadcast TCP payload keys: {list(payload.keys())}")
    except Exception:
        pass
    return False

def broadcast_login_udp(emp_id, name, medium):
    """Called when login happens — stubbed out."""
    try:
        print(f"[LOGIN-UDP-STUB] login {emp_id} ({name}) via {medium}")
    except Exception:
        pass

def broadcast_login_tcp(emp_id, name, medium):
    """Called when login happens — stubbed out."""
    try:
        print(f"[LOGIN-TCP-STUB] login {emp_id} ({name}) via {medium}")
    except Exception:
        pass


# -----------------------------------------------------------------------------
# Template-ID API (auto-incremental & reserved per emp_id)
# -----------------------------------------------------------------------------
@app.route("/api/user_template_id")
def api_user_template_id():
    emp_id = (request.args.get("emp_id") or "").strip()
    if not emp_id:
        return jsonify({"success": False, "message": "emp_id required"}), 400
    try:
        tid, created = get_or_reserve_template_id(emp_id)
        return jsonify({"success": True, "template_id": tid, "reserved": created})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# -----------------------------------------------------------------------------
# User upsert (emp_id, name, role)
# -----------------------------------------------------------------------------
@app.route("/api/user_upsert", methods=["POST"])
def api_user_upsert():
    data = request.get_json(force=True)
    emp_id = (data.get("emp_id") or "").strip()
    name   = (data.get("name") or "").strip()
    role   = (data.get("role") or "User").strip()
    if not emp_id:
        return jsonify({"success": False, "message": "Employee ID required."}), 400
    conn = get_db_connection()
    try:
        conn.execute("INSERT OR IGNORE INTO users (emp_id) VALUES (?)", (emp_id,))
        if name:
            conn.execute("UPDATE users SET name=? WHERE emp_id=?", (name, emp_id))
        conn.execute("UPDATE users SET role=? WHERE emp_id=?", (role, emp_id))
        conn.commit()
        # after commit in user_upsert:
        enqueue_sync_to_all_devices("user_upsert", {"emp_id": emp_id, "name": name, "role": role})

        tid, _ = get_or_reserve_template_id(emp_id)
        return jsonify({"success": True, "template_id": tid})
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Face login & helpers
# -----------------------------------------------------------------------------
recognizer = FaceRecognizer(DB_PATH)
recognizer.load_all_encodings()

@app.route("/api/face_login", methods=["POST"])
def face_login():
    data = request.json or {}
    img_data = (data.get("image") or "").split(",")[-1]
    if not img_data:
        return jsonify({"success": False, "reason": "bad_payload"}), 400

    try:
        img_bytes = base64.b64decode(img_data)
        nparr = np.frombuffer(img_bytes, np.uint8)
        bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if bgr is None:
            return jsonify({"success": False, "reason": "decode_failed"}), 400

        frame_rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)

        import face_recognition
        if not face_recognition.face_locations(frame_rgb):
            return jsonify({"success": False, "reason": "no_face"}), 200

        user_id = recognizer.recognize(frame_rgb)
        if not user_id:
            return jsonify({"success": False, "reason": "unknown_face"}), 200

        # Fetch name (optional)
        name = ""
        conn = get_db_connection()
        try:
            row = conn.execute("SELECT name FROM users WHERE emp_id=?", (str(user_id),)).fetchone()
            if row and row["name"]:
                name = row["name"]
        finally:
            conn.close()

        # ---- NEW: days-allowed gate
        ok_allowed, msg_denied = is_login_allowed_by_days(str(user_id))
        if not ok_allowed:
            run_parallel(lambda: led_blink((255, 0, 0), 0.8))
            return jsonify({"success": False, "reason": "days_limit", "message": msg_denied}), 403

        # ---- NEW: persist & broadcast (broadcast is now a safe no-op)
        insert_login_log(str(user_id), name, "face")
        try: broadcast_login_udp(str(user_id), name, "face")
        except Exception: pass

        # Existing effects + PG logging
        run_parallel(
            lambda: led_blink((0, 255, 0), 1.2),
            lambda: print_user_id_and_cut(str(user_id)),
            lambda: pg_log_event_or_queue(
                emp_id=str(user_id),
                name=name,
                medium="face",
                success=True,
                payload={"source": "face_login"},
            ),
        )
        _emit_thankyou(str(user_id), name, "face")
        return jsonify({"success": True, "user_id": str(user_id), "name": name})
    except Exception as e:
        return jsonify({"success": False, "reason": "error", "message": str(e)}), 500

@app.route("/api/face_detect", methods=["POST"])
def api_face_detect():
    try:
        data = request.get_json(force=True) or {}
        img_b64 = (data.get("image") or "").split(",")[-1]
        img_bytes = base64.b64decode(img_b64)
        nparr = np.frombuffer(img_bytes, np.uint8)
        bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if bgr is None:
            return jsonify({"success": False, "message": "decode_failed"})
        rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)

        import face_recognition
        locs = face_recognition.face_locations(rgb)
        if not locs:
            return jsonify({"success": False})
        top, right, bottom, left = locs[0]
        box = {"x": int(left), "y": int(top), "w": int(right - left), "h": int(bottom - top)}
        return jsonify({"success": True, "box": box, "score": 0.96})
    except Exception:
        return jsonify({"success": False})

@app.route("/api/check_face_duplicate", methods=["POST"])
def check_face_duplicate():
    data = request.json
    img_data = (data.get("image") or "").split(",")[-1]
    if not img_data:
        return jsonify({"duplicate": False})
    img_bytes = base64.b64decode(img_data)
    nparr = np.frombuffer(img_bytes, np.uint8)
    bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if bgr is None:
        return jsonify({"duplicate": False})
    frame = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
    match = recognizer.find_duplicate(frame)
    if match:
        return jsonify({
            "duplicate": True, "emp_id": match["emp_id"], "name": match["name"], "image": match["image"]
        })
    else:
        return jsonify({"duplicate": False})

@app.route("/api/face_register", methods=["POST"])
def face_register():
    data = request.json or {}
    img_data = (data.get("image") or "").split(",")[-1]
    emp_id = (data.get("employee_id") or data.get("emp_id") or "").strip()
    name   = (data.get("name") or "").strip()
    role   = (data.get("role") or "User").strip()

    if not img_data or not emp_id:
        return jsonify({"success": False, "message": "image and emp_id required"}), 400

    try:
        img_bytes = base64.b64decode(img_data)
        nparr = np.frombuffer(img_bytes, np.uint8)
        bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if bgr is None:
            return jsonify({"success": False, "message": "Image decode failed"})
        frame = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)

        match = recognizer.find_duplicate(frame)
        if match:
            return jsonify({
                "success": False,
                "message": f"Face already registered (Emp ID: {match['emp_id']}, Name: {match['name']})"
            })

        result, encoding_arr = recognizer.save_face(frame)
        if not result:
            return jsonify({"success": False, "message": encoding_arr})

        # convert encoding array to bytes for storage
        encoding_bytes = encoding_arr.astype(np.float64).tobytes()

        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO users (emp_id) VALUES (?)", (emp_id,))
            if name:
                c.execute("UPDATE users SET name=? WHERE emp_id=?", (name, emp_id))
            c.execute("UPDATE users SET role=? WHERE emp_id=?", (role, emp_id))
            c.execute("UPDATE users SET face_encoding=?, display_image=? WHERE emp_id=?",
                      (sqlite3.Binary(encoding_bytes), sqlite3.Binary(img_bytes), emp_id))
            conn.commit()
        finally:
            conn.close()

        # enqueue a sync to other devices (safe; worker/stub will handle network)
        payload = {
            "emp_id": emp_id,
            "name": name,
            "encoding": base64.b64encode(encoding_bytes).decode() if encoding_bytes else None,
            "display_image": base64.b64encode(img_bytes).decode()
        }
        enqueue_sync_to_all_devices("face_register", payload)

        recognizer.load_all_encodings()

        # optional: also attempt per-device UDP (stubs are safe)
        try:
            state = load_mesh_state()
            self_ip = get_self_ip()
            if state.get("devices"):
                payload2 = {
                    "type": "face_sync",
                    "emp_id": emp_id,
                    "name": name,
                    "registered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "encoding": base64.b64encode(encoding_bytes).decode(),
                    "display_image": base64.b64encode(img_bytes).decode()
                }
                for dev in state.get("devices", []):
                    ip = dev.get("ip")
                    if ip and ip != self_ip:
                        try:
                            send_udp_json(ip, 5006, payload2)
                        except Exception:
                            pass
        except Exception:
            pass

        return jsonify({"success": True, "message": "Face registered successfully."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/face_edit", methods=["POST"])
def face_edit():
    data = request.json
    img_data = (data.get("image") or "").split(",")[-1]
    emp_id = (data.get("emp_id") or "").strip()
    if not img_data or not emp_id:
        return jsonify({"success": False, "message": "image and emp_id required"}), 400

    img_bytes = base64.b64decode(img_data)
    nparr = np.frombuffer(img_bytes, np.uint8)
    bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if bgr is None:
        return jsonify({"success": False, "message": "Image decode failed"})
    frame = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
    result = recognizer.update_user_encoding(frame, emp_id)
    recognizer.load_all_encodings()

    # mesh/tcp removed — stubs do nothing
    try:
        state = load_mesh_state()
        self_ip = get_self_ip()
        if result and state.get("devices"):
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT face_encoding, name, display_image FROM users WHERE emp_id=?", (emp_id,))
            row = c.fetchone()
            conn.close()
            if row:
                encoding_bytes, name, disp_img = row["face_encoding"], row["name"], row["display_image"]
                payload = {
                  "emp_id": emp_id,
                  "name": name,
                  "encoding": base64.b64encode(encoding_bytes).decode() if encoding_bytes else None,
                  "display_image": base64.b64encode(img_bytes).decode() if img_bytes else ""
                }
                enqueue_sync_to_all_devices("face_edit", payload)

                for dev in state.get("devices", []):
                    ip = dev.get("ip")
                    if ip and ip != self_ip:
                        try: send_udp_json(ip, 5006, payload)
                        except Exception: pass
    except Exception:
        pass

    return jsonify({"success": bool(result), "message": "Edit successful" if result else "Edit failed"})


# -----------------------------------------------------------------------------
# Avatar/image fetch for popup (success-only avatar hydration)
# -----------------------------------------------------------------------------
def _generate_initials_avatar_b64(text: str, size=120):
    t = "".join([ch for ch in text if ch.isalnum()]) or "?"
    initials = (t[:1] + (t[1:2] if len(t) > 1 else "")).upper()
    bg  = (230, 240, 255)  # BGR light background
    fg  = (40, 60, 90)     # BGR dark text
    img = np.full((size, size, 3), bg, dtype=np.uint8)
    cv2.circle(img, (size//2, size//2), int(size*0.49), bg, thickness=-1)
    font = cv2.FONT_HERSHEY_SIMPLEX
    font_scale = 1.8 if len(initials) == 1 else 1.4
    thickness  = 3
    (tw, th), _ = cv2.getTextSize(initials, font, font_scale, thickness)
    x = (size - tw) // 2
    y = (size + th) // 2 - 6
    cv2.putText(img, initials, (x, y), font, font_scale, fg, thickness, cv2.LINE_AA)
    ok, enc = cv2.imencode(".png", img)
    return base64.b64encode(enc if ok else b"").decode("utf-8")

@app.route("/api/get_user_image", methods=["POST"])
def get_user_image():
    try:
        data = request.get_json(force=True) or {}
        emp_id = (data.get("emp_id") or "").strip()
        if not emp_id:
            img_b64 = _generate_initials_avatar_b64("?", size=120)
            return jsonify({"success": False, "image": f"data:image/png;base64,{img_b64}"})

        conn = get_db_connection()
        row = conn.execute("SELECT name, display_image FROM users WHERE emp_id=?", (emp_id,)).fetchone()
        conn.close()

        if row and row["display_image"]:
            try:
                nparr = np.frombuffer(row["display_image"], np.uint8)
                bgr   = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                if bgr is not None:
                    bgr = cv2.resize(bgr, (120, 120), interpolation=cv2.INTER_AREA)
                    ok, enc = cv2.imencode(".png", bgr)
                    if ok:
                        return jsonify({
                            "success": True,
                            "image": "data:image/png;base64," + base64.b64encode(enc).decode("utf-8")
                        })
            except Exception:
                pass

        initials = (row["name"] or emp_id) if row else emp_id
        img_b64 = _generate_initials_avatar_b64(initials, size=120)
        return jsonify({"success": False, "image": f"data:image/png;base64,{img_b64}"})
    except Exception:
        img_b64 = _generate_initials_avatar_b64("?", size=120)
        return jsonify({"success": False, "image": f"data:image/png;base64,{img_b64}"})


# -----------------------------------------------------------------------------
# Fingerprint APIs
# -----------------------------------------------------------------------------
fingerprint_sensor = None
sensor_lock = Lock()

def _auto_serial_port(candidates=("/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyACM0", "/dev/ttyACM1")):
    for p in candidates:
        if os.path.exists(p):
            return p
    for p in glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"):
        return p
    return "/dev/ttyUSB0"

def get_fingerprint_sensor():
    global fingerprint_sensor
    if fingerprint_sensor is None:
        port = _auto_serial_port()
        fingerprint_sensor = Fingerprint(port, 9600)
        if not fingerprint_sensor.init():
            raise Exception(f"Fingerprint sensor not detected on {port}!")
    return fingerprint_sensor

def call_with_timeout(func, timeout=30):
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return False, "Operation timed out. Please try again."

# --- replace the whole /api/finger_register in app.py with this ---

# ====== PUT THESE 2 HELPERS JUST ABOVE /api/finger_register ======

@app.route("/api/operator_finger_verify", methods=["POST"])
def api_operator_finger_verify():
    try:
        s = get_fingerprint_sensor()
        with sensor_lock:
            s.open()
            try:
                # capture
                if hasattr(s, "capture_finger"):
                    if not s.capture_finger():
                        return jsonify(success=False, message="Place finger on sensor"), 200

                # identify
                rid = s.identify() if "side_effects" not in inspect.signature(s.identify).parameters else s.identify(side_effects=True)
                if rid is None:
                    return jsonify(success=False, message="No finger"), 200
                if int(rid) < 0:
                    return jsonify(success=False, message="Unknown finger"), 200

                # map template slot -> emp_id, name
                emp_id, name = template_to_empname(int(rid))

                # log + broadcast (broadcast stubs do nothing)
                insert_login_log(str(emp_id), name, "finger")
                try:  broadcast_login_udp(str(emp_id), name, "finger")
                except Exception: pass
                try:  broadcast_login_tcp(str(emp_id), name, "finger")
                except Exception: pass

                return jsonify(success=True, emp_id=str(emp_id), name=name, template_id=int(rid)), 200
            finally:
                try: s.close()
                except Exception: pass
    except Exception as e:
        return jsonify(success=False, message=f"{type(e).__name__}: {e}"), 500



def template_to_empname(template_id: int):
    """
    Map sensor template slot -> (emp_id, name).
    Priority: fingerprint_map (canonical) -> users.template_id -> user_finger_map.
    Always returns strings; falls back to showing the slot if no mapping yet.
    """
    template_id = int(template_id)
    emp_id, name = None, None

    conn = get_db_connection()
    try:
        # 1) canonical mapping
        r = conn.execute(
            "SELECT emp_id, COALESCE(name,'') FROM fingerprint_map WHERE template_id=?",
            (template_id,)
        ).fetchone()
        if r:
            emp_id, name = r[0], r[1]

        # 2) fallback to users.template_id (only if column exists)
        if not emp_id:
            try:
                r2 = conn.execute(
                    "SELECT emp_id, COALESCE(name,'') FROM users WHERE template_id=?",
                    (template_id,)
                ).fetchone()
                if r2:
                    emp_id, name = r2[0], r2[1]
            except Exception:
                pass

        # 3) fallback to user_finger_map (+ users for name)
        if not emp_id:
            r3 = conn.execute(
                "SELECT m.emp_id, COALESCE(u.name,'') "
                "FROM user_finger_map m LEFT JOIN users u ON u.emp_id=m.emp_id "
                "WHERE m.template_id=?",
                (template_id,)
            ).fetchone()
            if r3:
                emp_id, name = r3[0], r3[1]
    finally:
        conn.close()

    if not emp_id:
        emp_id = str(template_id)  # last resort label
    return str(emp_id), (name or "")

MAX_FP_TEMPLATES = 3000

def _call_first(obj, names, *args, **kwargs):
    for name in names:
        fn = getattr(obj, name, None)
        if callable(fn):
            try:
                r = fn(*args, **kwargs)
                if isinstance(r, tuple) and len(r) >= 1 and isinstance(r[0], bool):
                    return r[0], (r[1] if len(r) > 1 else "")
                return (bool(r), str(r))
            except Exception:
                continue
    return False, " / ".join(names) + " not available"

def _pick_first_free_template_id(conn, sensor):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fingerprint_map(
            emp_id TEXT PRIMARY KEY,
            template_id INTEGER UNIQUE NOT NULL,
            name TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    rows = conn.execute("SELECT template_id FROM fingerprint_map").fetchall()
    used = {int(r[0]) for r in rows if r and r[0] is not None}

    def dev_used(tid: int) -> bool:
        ok, _ = _call_first(sensor, ["is_enrolled","IsEnrolled","check_enrolled","CheckEnrolled"], tid)
        if ok:
            try:
                probe = getattr(sensor, "is_enrolled", None) or getattr(sensor, "IsEnrolled", None) \
                        or getattr(sensor, "check_enrolled", None) or getattr(sensor, "CheckEnrolled", None)
                if callable(probe):
                    return bool(probe(tid))
            except Exception:
                pass
        return False

    for tid in range(1, MAX_FP_TEMPLATES + 1):
        if tid in used:
            continue
        try:
            if dev_used(tid):
                continue
        except Exception:
            pass
        return tid
    return None

# --- Device-side reassembly & generic handler (useful for devices receiving chunks) ---
_device_reassembly = {}

def device_udp_listener_main(bind_ip='0.0.0.0', port=UDP_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind_ip, port))
    s.settimeout(1.0)
    print(f"[DEVICE-LISTENER] listening on {bind_ip}:{port}")
    while True:
        try:
            data, addr = s.recvfrom(8192)
            try:
                hdr, payload = data.split(b'\n', 1)
                j = json.loads(hdr.decode('utf-8', errors='ignore'))
            except Exception:
                continue
            mid = j.get("message_id"); idx = int(j.get("chunk_index",0)); total = int(j.get("total_chunks",1))
            if mid not in _device_reassembly:
                _device_reassembly[mid] = {"chunks": {}, "total": total, "first_ts": time.time(), "addr": addr}
            _device_reassembly[mid]["chunks"][idx] = payload
            if len(_device_reassembly[mid]["chunks"]) == _device_reassembly[mid]["total"]:
                parts = [ _device_reassembly[mid]["chunks"][i] for i in range(_device_reassembly[mid]["total"]) ]
                env_bytes = b''.join(parts)
                try:
                    envelope = json.loads(env_bytes.decode('utf-8'))
                    handle_incoming_envelope(envelope)
                    ack = json.dumps({"type":"ack","message_id":mid}).encode('utf-8')
                    s.sendto(ack, addr)
                except Exception as e:
                    print("[DEVICE] reassembly error:", e)
                del _device_reassembly[mid]
        except socket.timeout:
            # cleanup stale
            now = time.time()
            stale = [k for k,v in _device_reassembly.items() if now - v["first_ts"] > 30]
            for k in stale: del _device_reassembly[k]
        except KeyboardInterrupt:
            break
        except Exception as e:
            print("[DEVICE-LISTENER] error:", e)
            time.sleep(0.1)

def handle_incoming_envelope(envelope: dict):
    """
    Minimal handler — expands to apply payload to local DB/sensor.
    Recognized envelope types: user_upsert, user_delete, face_register, face_edit, finger_register, finger_edit.
    """
    t = envelope.get("type")
    payload = envelope.get("payload") or {}
    # face sync
    if t in ("face_register", "face_edit"):
        emp_id = payload.get("emp_id"); name = payload.get("name")
        enc_b64 = payload.get("encoding"); img_b64 = payload.get("display_image")
        try:
            enc = base64.b64decode(enc_b64) if enc_b64 else None
            img = base64.b64decode(img_b64) if img_b64 else None
            conn = get_db_connection()
            try:
                conn.execute("INSERT OR IGNORE INTO users (emp_id, name) VALUES (?, ?)", (emp_id, name))
                if enc is not None:
                    conn.execute("UPDATE users SET face_encoding=? WHERE emp_id=?", (sqlite3.Binary(enc), emp_id))
                if img is not None:
                    conn.execute("UPDATE users SET display_image=? WHERE emp_id=?", (sqlite3.Binary(img), emp_id))
                conn.commit()
            finally:
                conn.close()
            print(f"[DEVICE] stored face for {emp_id}")
        except Exception as e:
            print("[DEVICE] face store error:", e)
    elif t in ("finger_register", "finger_edit"):
        tpl_b64 = payload.get("template"); user_id = payload.get("user_id") or payload.get("template_id") or payload.get("emp_id")
        try:
            tpl = base64.b64decode(tpl_b64) if tpl_b64 else None
            if tpl:
                conn = get_db_connection()
                try:
                    tid = None
                    try: tid = int(user_id)
                    except Exception: tid = get_template_id_if_any(user_id) or _first_free_template_id(conn)
                    conn.execute("INSERT OR REPLACE INTO fingerprints (id, username, template) VALUES (?, ?, ?)", (tid, payload.get("username") or payload.get("emp_id") or "", sqlite3.Binary(tpl)))
                    if payload.get("emp_id"):
                        conn.execute("INSERT OR REPLACE INTO user_finger_map (emp_id, template_id) VALUES (?, ?)", (payload.get("emp_id"), tid))
                    conn.commit()
                finally:
                    conn.close()
                # optionally write to hardware sensor if you have finger API available
                try:
                    if Fingerprint is not None:
                        fp = Fingerprint()
                        if hasattr(fp, "write_template_to_sensor"):
                            fp.write_template_to_sensor(tid, tpl)
                except Exception as e:
                    print("[DEVICE] write-to-sensor failed:", e)
                print(f"[DEVICE] stored fingerprint tid={tid}")
        except Exception as e:
            print("[DEVICE] finger store error:", e)
    elif t == "user_delete":
        emp = payload.get("emp_id")
        try:
            conn = get_db_connection()
            try:
                conn.execute("DELETE FROM users WHERE emp_id=?", (emp,))
                conn.execute("DELETE FROM user_finger_map WHERE emp_id=?", (emp,))
                conn.commit()
            finally:
                conn.close()
            print(f"[DEVICE] deleted user {emp}")
        except Exception as e:
            print("[DEVICE] delete error:", e)
    elif t == "user_upsert":
        emp = payload.get("emp_id"); name = payload.get("name"); role = payload.get("role")
        try:
            conn = get_db_connection()
            try:
                conn.execute("INSERT OR IGNORE INTO users (emp_id, name, role) VALUES (?, ?, ?)", (emp, name, role))
                if name: conn.execute("UPDATE users SET name=? WHERE emp_id=?", (name, emp))
                if role: conn.execute("UPDATE users SET role=? WHERE emp_id=?", (role, emp))
                conn.commit()
            finally:
                conn.close()
            print(f"[DEVICE] user upsert {emp}")
        except Exception as e:
            print("[DEVICE] user_upsert failed:", e)



@app.route("/api/finger_register", methods=["POST"])
def api_finger_register():
    """
    Payloads supported:
      { "emp_id": "35322", "name": "Alice" }
      { "employee_id": "35322", "username": "Alice" }
      { "user_id": "35322", "username": "Alice" }   # your UI today
      { "user_id": 12, "username": "Alice" }        # force slot 1..3000
    """
    try:
        data = request.get_json(silent=True) or {}
        emp_id = (data.get("emp_id") or data.get("employee_id") or "").strip()
        username = (data.get("username") or data.get("name") or "").strip()

        template_id = None
        raw_user_id = data.get("user_id")
        if raw_user_id is not None and str(raw_user_id).strip() != "":
            # numeric? treat as slot (1..3000). Otherwise treat as emp_id.
            s = str(raw_user_id).strip()
            try:
                sid = int(s)
                if 1 <= sid <= MAX_FP_TEMPLATES:
                    template_id = sid
                else:
                    emp_id = s
            except Exception:
                emp_id = s

        if not template_id and not emp_id:
            return jsonify(success=False, message="emp_id or user_id required"), 400

        conn = get_db_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fingerprint_map(
                    emp_id TEXT PRIMARY KEY,
                    template_id INTEGER UNIQUE NOT NULL,
                    name TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            if emp_id:
                r = conn.execute("SELECT template_id,name FROM fingerprint_map WHERE emp_id=?", (emp_id,)).fetchone()
                if r:
                    return jsonify(success=False, duplicate=True, emp_id=emp_id,
                                   name=r[1] or username, template_id=int(r[0]),
                                   message=f"Employee {emp_id} already has fingerprint (ID {r[0]})."), 200

            s = get_fingerprint_sensor()
            with sensor_lock:
                s.open()
                try:
                    _call_first(s, ["_flush","flush"])

                    if not template_id:
                        template_id = _pick_first_free_template_id(conn, s)
                        if not template_id:
                            return jsonify(success=False, message="Sensor storage full (no free template IDs)."), 409

                    # quick duplicate check
                    ok_cap, _ = _call_first(s, ["capture_finger","CaptureFinger","capture","scan","getImage"])
                    if ok_cap:
                        ok_ident, ident_val = _call_first(s, ["identify","Identify","search","Search"])
                        if ok_ident and isinstance(ident_val, int):
                            if ident_val >= 0 and ident_val != int(template_id):
                                return jsonify(success=False, duplicate=True,
                                               message=f"Duplicate fingerprint detected (template #{ident_val})."), 200

                    # enroll sequence
                    ok_start, msg = _call_first(s, ["start_enroll","EnrollStart","enroll_start","startEnroll"], int(template_id))
                    if not ok_start:
                        return jsonify(success=False, message=f"Enroll start failed ({msg})."), 200

                    for step, names in enumerate(
                        (["enroll1","Enroll1","enroll_step1"],
                         ["enroll2","Enroll2","enroll_step2"],
                         ["enroll3","Enroll3","enroll_step3"]),
                        start=1
                    ):
                        time.sleep(1.5)
                        ok_cap, _ = _call_first(s, ["capture_finger","CaptureFinger","capture","scan","getImage"])
                        if not ok_cap:
                            return jsonify(success=False, message=f"Capture failed at step {step}."), 200
                        ok_step, msg_step = _call_first(s, names)
                        if not ok_step:
                            return jsonify(success=False, message=f"Enroll step {step} failed ({msg_step})."), 200

                    ok_tpl, tpl = _call_first(s, ["get_template","GetTemplate","getTemplate","download","download_template"], int(template_id))
                    if not ok_tpl or not tpl:
                        if ok_tpl and not tpl:
                            ok2, tpl2 = _call_first(s, ["get_template","GetTemplate","getTemplate","download","download_template"])
                            if ok2 and tpl2:
                                tpl = tpl2
                        if not tpl:
                            return jsonify(success=False, message="Template not captured."), 200

                    if isinstance(tpl, str):
                        try: tpl = base64.b64decode(tpl)
                        except Exception: tpl = tpl.encode("utf-8","ignore")

                    # mirror template into fingerprints table
                    db = get_finger_db()
                    try:
                        db.execute("""
                            CREATE TABLE IF NOT EXISTS fingerprints(
                                id INTEGER PRIMARY KEY,
                                username TEXT,
                                template BLOB NOT NULL
                            )
                        """)
                        db.execute("INSERT OR REPLACE INTO fingerprints (id, username, template) VALUES (?, ?, ?)",
                                   (int(template_id), username or emp_id or "", sqlite3.Binary(tpl)))
                        db.commit()
                    finally:
                        db.close()

                    # persist mapping (canonical)
                    if emp_id:
                        conn.execute(
                            "INSERT OR REPLACE INTO fingerprint_map(emp_id, template_id, name) VALUES (?,?,?)",
                            (emp_id, int(template_id), username or None)
                        )
                        # keep mirrors in sync
                        conn.execute("INSERT OR REPLACE INTO user_finger_map(emp_id, template_id) VALUES (?, ?)",
                                     (emp_id, int(template_id)))
                        conn.execute("UPDATE users SET template_id=? WHERE emp_id=?", (int(template_id), emp_id))
                        conn.commit()

                    # broadcasts removed — stubs will do nothing
                    try:
                        state = load_mesh_state()
                        self_ip = get_self_ip()
                        if state.get("devices"):
                            payload = {
                                "type": "finger_register",
                                "user_id": int(template_id),
                                "username": username or emp_id or "",
                                "template": base64.b64encode(tpl).decode()
                            }
                            for dev in state.get("devices", []):
                                ip = dev.get("ip")
                                if ip and ip != self_ip:
                                    try: send_udp_json(ip, 5006, payload)
                                    except Exception as e: print("[UDP-STUB] finger_register broadcast failed:", e)
                            try: broadcast_tcp(payload)
                            except Exception: pass
                    except Exception:
                        pass

                    return jsonify(success=True, template_id=int(template_id),
                                   message=f"Fingerprint enrolled (ID {template_id})."), 200
                finally:
                    try: _call_first(s, ["_flush","flush"])
                    except Exception: pass
                    try: s.close()
                    except Exception: pass
        finally:
            conn.close()
    except Exception as e:
        return jsonify(success=False, message=f"{type(e).__name__}: {e}"), 500



@app.route("/api/finger_identify", methods=["POST"])
def api_finger_identify():
    def do_identify():
        fdb = get_finger_db()
        try:
            with sensor_lock:
                s = get_fingerprint_sensor()
                s.open()
                try:
                    if hasattr(s, "_flush"):
                        s._flush()
                    rid = s.identify() if "side_effects" not in inspect.signature(s.identify).parameters else s.identify(side_effects=True)
                finally:
                    try:
                        if hasattr(s, "_flush"): s._flush()
                    except Exception:
                        pass
                    s.close()
        finally:
            try: fdb.close()
            except Exception: pass

        if rid is None:
            return {"success": False, "message": "No finger"}
        if int(rid) < 0:
            run_parallel(lambda: led_blink((255, 0, 0), 0.7))
            return {"success": False, "reason": "not_identified", "message": "Fingerprint not recognized"}

        # NEW: map slot -> (emp_id, name) properly
        emp_id_str, name = template_to_empname(int(rid))

        # days-allowed check (your existing gate)
        ok_allowed, msg_denied = is_login_allowed_by_days(emp_id_str)
        if not ok_allowed:
            run_parallel(lambda: led_blink((255, 0, 0), 0.8))
            return {"success": False, "reason": "days_limit", "message": msg_denied}

        # Persist + broadcast (broadcast stubs do nothing)
        insert_login_log(emp_id_str, name, "fingerprint")
        try: broadcast_login_udp(emp_id_str, name, "fingerprint")
        except Exception: pass

        # Existing effects + PG logging
        run_parallel(
            lambda: led_blink((0, 255, 0), 1.2),
            lambda: print_user_id_and_cut(emp_id_str),
            lambda: pg_log_event_or_queue(
                emp_id=str(emp_id_str),
                name=name,
                medium="fingerprint",
                success=True,
                payload={"source": "finger_identify"},
            ),
        )
        _emit_thankyou(emp_id_str, name, "fingerprint")
        return {"success": True, "user_id": emp_id_str, "username": name or "Unknown"}

    result = call_with_timeout(do_identify, timeout=30)
    return jsonify(result)

@app.route("/api/finger_edit", methods=["POST"])
def api_finger_edit():
    data = request.json or {}
    emp_id = (data.get("emp_id") or "").strip()
    if "user_id" in data and str(data["user_id"]).strip() != "":
        user_id = int(data["user_id"])
    elif emp_id:
        user_id, _ = get_or_reserve_template_id(emp_id)
    else:
        return jsonify({"success": False, "message": "emp_id or user_id required"}), 400

    username = (data.get("username") or data.get("name") or "").strip()

    def do_update():
        db = get_finger_db()
        if username:
            db.execute(
                "INSERT OR REPLACE INTO fingerprints (id,username,template) "
                "VALUES (?, COALESCE((SELECT username FROM fingerprints WHERE id=?), ?), "
                "COALESCE((SELECT template FROM fingerprints WHERE id=?), X''))",
                (user_id, user_id, username, user_id))
            db.commit()
        with sensor_lock:
            s = get_fingerprint_sensor()
            s.open()
            try:
                if not s.delete(user_id):
                    return False, f"Could not delete existing fingerprint at ID {user_id}."
                time.sleep(0.5)
                s._flush()
                ok = s.start_enroll(user_id)
                if not ok:
                    return False, "Enroll start failed"
                for step in (1, 2, 3):
                    time.sleep(2)
                    if not s.capture_finger():
                        return False, f"Capture failed at step {step}"
                    if not getattr(s, f'enroll{step}')():
                        return False, f"Enroll step {step} failed"
                    if step < 3:
                        time.sleep(1)
                tpl = s.get_template(user_id)
                if not tpl:
                    return False, "Template not captured"
                db.execute("INSERT OR REPLACE INTO fingerprints (id, username, template) VALUES (?, ?, ?)",
                           (user_id, username, sqlite3.Binary(tpl)))
                db.commit()

                # mesh/tcp removed — stubs do nothing
                try:
                    state = load_mesh_state()
                    self_ip = get_self_ip()
                    if state.get("devices"):
                        payload = {
                            "type": "finger_edit",
                            "user_id": user_id,
                            "username": username,
                            "template": base64.b64encode(tpl).decode()
                        }
                        for dev in state["devices"]:
                            ip = dev.get("ip")
                            if ip != self_ip:
                                try: send_udp_json(ip, 5006, payload)
                                except Exception: pass
                except Exception:
                    pass

                return True, "Fingerprint re-enrolled"
            finally:
                try:
                    s._flush()
                except Exception:
                    pass
                s.close()
                db.close()

    ok, umsg = call_with_timeout(do_update, timeout=30)
    return jsonify({"success": ok, "message": umsg})

@app.route("/api/finger_delete", methods=["POST"])
def api_finger_delete():
    data = request.json or {}
    emp_id = (data.get("emp_id") or "").strip()
    user_id = data.get("user_id")
    admin_pw = data.get("admin_password")
    if not check_admin_password(admin_pw or ""):
        return jsonify({"success": False, "message": "Invalid admin password"})

    if user_id is None:
        if not emp_id:
            return jsonify({"success": False, "message": "emp_id or user_id required"}), 400
        mapped = get_template_id_if_any(emp_id)
        if mapped is None:
            return jsonify({"success": False, "message": "No template mapped for emp_id"}), 400
        user_id = mapped
    try:
        user_id = int(user_id)
    except Exception:
        return jsonify({"success": False, "message": "user_id must be integer"}), 400

    def do_delete():
        db = get_finger_db()
        with sensor_lock:
            s = get_fingerprint_sensor()
            s.open()
            try:
                ok = s.delete(user_id)
            finally:
                try:
                    s._flush()
                except Exception:
                    pass
                s.close()
            if ok:
                db.execute("DELETE FROM fingerprints WHERE id=?", (user_id,))
                db.commit()
                db.close()
                # mesh/tcp removed — stubs do nothing
                try:
                    state = load_mesh_state()
                    self_ip = get_self_ip()
                    if state.get("devices"):
                        payload = {"type": "finger_delete", "user_id": user_id}
                        for dev in state["devices"]:
                            ip = dev.get("ip")
                            if ip != self_ip:
                                try: send_udp_json(ip, 5006, payload)
                                except Exception: pass
                except Exception:
                    pass
                return True, f"Deleted Template ID {user_id} from sensor and DB."
            else:
                db.close()
                return False, "Delete command failed on sensor."

    ok, msg = call_with_timeout(do_delete, timeout=30)
    return jsonify({"success": ok, "message": msg})

@app.route("/api/finger_delete_all", methods=["POST"])
def api_finger_delete_all():
    admin_pw = (request.json or {}).get("admin_password")
    if not check_admin_password(admin_pw or ""):
        return jsonify({"success": False, "message": "Invalid admin password"})

    def do_delete_all():
        db = get_finger_db()
        with sensor_lock:
            s = get_fingerprint_sensor()
            s.open()
            try:
                ok = s.delete()  # delete all on the module
            finally:
                try:
                    s._flush()
                except Exception:
                    pass
                s.close()
            if ok:
                db.execute("DELETE FROM fingerprints")
                db.commit()
                db.close()
                return True, "All fingerprints deleted from sensor and DB."
            else:
                db.close()
                return False, "Delete all failed on sensor."

    ok, msg = call_with_timeout(do_delete_all, timeout=30)
    return jsonify({"success": ok, "message": msg})

@app.route("/api/finger_reset", methods=["POST"])
def finger_reset():
    with sensor_lock:
        s = get_fingerprint_sensor()
        try:
            s.close()
            time.sleep(1)
            s.open()
            s._flush()
            return jsonify({"success": True, "message": "Sensor reset."})
        except Exception as e:
            return jsonify({"success": False, "message": f"Reset failed: {e}"})


# -----------------------------------------------------------------------------
# RFID APIs
# -----------------------------------------------------------------------------
@app.route("/api/rfid_register", methods=["POST"])
def api_rfid_register():
    data = request.json or {}
    employee_id = (data.get("employee_id") or "").strip()
    name = (data.get("name") or "").strip()
    if not employee_id or not name:
        return jsonify({"success": False, "message": "Employee ID and name required."})
    ok, msg = rfid.rfid_register(employee_id, name)
    out = {"success": bool(ok)}
    if isinstance(msg, dict):
        out.update(msg)
        if "message" not in out:
            out["message"] = "RFID registered"
    else:
        out["message"] = str(msg)
    return jsonify(out)

@app.route("/api/rfid_login", methods=["POST"])
def api_rfid_login():
    ok, result = rfid.rfid_login()
    if not ok:
        return jsonify({"success": False, "message": result})

    emp = str(result.get("employee_id") or result.get("emp_id") or "")
    nm  = result.get("name") or ""
    if not emp:
        return jsonify({"success": False, "message": "Employee ID missing"}), 400

    # ---- NEW: days-allowed gate
    ok_allowed, msg_denied = is_login_allowed_by_days(emp)
    if not ok_allowed:
        run_parallel(lambda: led_blink((255, 0, 0), 0.8))
        return jsonify({"success": False, "reason": "days_limit", "message": msg_denied}), 403

    # ---- NEW: persist & broadcast (broadcast stubs do nothing)
    insert_login_log(emp, nm, "rfid")
    try: broadcast_login_udp(emp, nm, "rfid")
    except Exception: pass

    # Existing PG logging + thank-you
    pg_log_event_or_queue(
        emp_id=emp,
        name=nm,
        medium="rfid",
        success=True,
        payload={"source": "rfid_login"},
    )
    _emit_thankyou(emp, nm, "rfid")

    return jsonify({
        "success": True,
        "employee_id": emp,
        "name": nm,
        "image": result.get("image"),
    })

@app.route("/api/rfid_edit", methods=["POST"])
def api_rfid_edit():
    data = request.json or {}
    employee_id = (data.get("employee_id") or "").strip()
    new_name = (data.get("name") or "").strip()
    admin_pw = (data.get("admin_password") or "").strip()
    if not check_admin_password(admin_pw):
        return jsonify({"success": False, "message": "Incorrect admin password."})
    ok, msg = rfid.rfid_edit(employee_id, new_name)
    return jsonify({"success": ok, "message": msg})

@app.route("/api/rfid_delete", methods=["POST"])
def api_rfid_delete():
    data = request.json or {}
    employee_id = (data.get("employee_id") or "").strip()
    admin_pw = (data.get("admin_password") or "").strip()
    if not check_admin_password(admin_pw):
        return jsonify({"success": False, "message": "Incorrect admin password."})
    ok, msg = rfid.rfid_delete(employee_id)
    return jsonify({"success": ok, "message": msg})


# -----------------------------------------------------------------------------
# Password change API
# -----------------------------------------------------------------------------
@app.route("/api/change_password", methods=["POST"])
def change_password():
    data = request.json or {}
    current = (data.get("current_password") or "").strip()
    newpw = (data.get("new_password") or "").strip()
    conf = (data.get("confirm_password") or "").strip()
    if not check_admin_password(current):
        return jsonify({"success": False, "message": "Current password incorrect."})
    elif not newpw or not conf:
        return jsonify({"success": False, "message": "New password cannot be empty."})
    elif newpw != conf:
        return jsonify({"success": False, "message": "Passwords do not match."})
    elif len(newpw) < 4:
        return jsonify({"success": False, "message": "Password too short."})
    else:
        set_admin_password(newpw)
        return jsonify({"success": True, "message": "Password changed successfully."})


# -----------------------------------------------------------------------------
# DB Config, WiFi, Volume, and misc APIs
# -----------------------------------------------------------------------------
@app.route("/api/wifi_scan")
def wifi_scan():
    try:
        output = subprocess.check_output("nmcli -t -f SSID dev wifi", shell=True, timeout=8).decode().splitlines()
        ssids = sorted(set(ssid for ssid in output if ssid))
        return jsonify(ssids)
    except Exception:
        return jsonify([])
        return jsonify({"success": True, "message": f"WiFi credentials for {ssid} saved and connected!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"WiFi setup failed: {e}"})

@app.route("/api/wifi_save", methods=["POST"])
def wifi_save():
    data = request.json
    ssid = data.get('ssid')
    password = data.get('password')
    if not ssid or not password:
        return jsonify({"success": False, "message": "SSID and password required."})
    try:
        subprocess.run(["nmcli", "dev", "wifi", "connect", ssid, "password", password], check=True, timeout=30)
        return jsonify({"success": True, "message": f"WiFi credentials for {ssid} saved and connected!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"WiFi setup failed: {e}"})


@app.route("/api/db_config", methods=["GET"])
def api_db_config_get():
    return jsonify({
        "host": get_setting("pg_host", "192.168.1.3"),
        "port": int(get_setting("pg_port", "5432") or "5432"),
        "dbname": get_setting("pg_dbname", "postgres"),
        "user": get_setting("pg_user", "postgres"),
        "password": get_setting("pg_password", "postgres"),
    })


@app.route("/api/db_config", methods=["POST"])
def api_db_config_set():
    data = request.get_json(force=True) or {}
    host = (data.get("host") or "").strip()
    port = (data.get("port") or "").strip()
    dbname = (data.get("dbname") or "").strip()
    user = (data.get("user") or "").strip()
    password = (data.get("password") or "").strip()

    if not host or not port or not dbname or not user:
        return jsonify({"success": False, "message": "All fields except password are required."}), 400
    try:
        int(port)
    except Exception:
        return jsonify({"success": False, "message": "Port must be an integer."}), 400

    set_setting("pg_host", host)
    set_setting("pg_port", port)
    set_setting("pg_dbname", dbname)
    set_setting("pg_user", user)
    set_setting("pg_password", password)

    load_pgcfg_from_settings()

    try:
        if pg_is_available():
            ensure_pg_table()
            ok = True
            msg = "Database settings saved. Connection OK."
        else:
            ok = False
            msg = "Saved, but cannot reach the database at the moment."
    except Exception as ex:
        ok = False
        msg = f"Saved, but connection failed: {ex}"

    return jsonify({"success": ok, "message": msg, "config": PGCFG})


@app.route("/api/db_test", methods=["POST"])
def api_db_test():
    data = request.get_json(silent=True) or {}
    test_cfg = {
        "host": (data.get("host") or PGCFG.get("host")),
        "port": int((data.get("port") or PGCFG.get("port") or 5432)),
        "dbname": (data.get("dbname") or PGCFG.get("dbname")),
        "user": (data.get("user") or PGCFG.get("user")),
        "password": (data.get("password") or PGCFG.get("password") or ""),
    }
    try:
        conn = psycopg2.connect(
            host=test_cfg["host"],
            port=test_cfg["port"],
            dbname=test_cfg["dbname"],
            user=test_cfg["user"],
            password=test_cfg["password"],
            connect_timeout=PG_CONNECT_TIMEOUT,
        )
        conn.close()
        return jsonify({"success": True, "message": "Connection OK", "tested": test_cfg})
    except Exception as e:
        return jsonify({"success": False, "message": str(e), "tested": test_cfg})


@app.route('/api/set_volume', methods=['POST'])
def set_volume():
    data = request.json or {}
    vol = data.get('volume')
    try:
        vol_int = int(vol)
        if not (0 <= vol_int <= 100):
            raise ValueError
        try:
            subprocess.run(["amixer", "sset", "PCM", f"{vol_int}%"], check=True, timeout=5)
        except Exception:
            subprocess.run(["amixer", "sset", "Master", f"{vol_int}%"], check=True, timeout=5)
        return jsonify({"success": True, "message": f"Volume set to {vol_int}%"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to set volume: {e}"})


@app.route('/api/get_volume')
def get_volume():
    try:
        try:
            output = subprocess.check_output("amixer get PCM", shell=True, timeout=5).decode()
        except Exception:
            output = subprocess.check_output("amixer get Master", shell=True, timeout=5).decode()
        m = re.search(r"\[(\d{1,3})%\]", output)
        if m:
            vol = int(m.group(1))
            return jsonify({"success": True, "volume": vol})
        else:
            return jsonify({"success": False, "message": "Could not parse volume"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


# -----------------------------------------------------------------------------
# Delete user
# -----------------------------------------------------------------------------
@app.route("/api/delete_user", methods=["POST"])
def delete_user():
    data = request.json or {}
    emp_id = (data.get("emp_id") or "").strip()
    admin_pw = (data.get("admin_password") or "").strip()
    if not check_admin_password(admin_pw):
        return jsonify({"success": False, "message": "Incorrect admin password."})

    mapped = get_template_id_if_any(emp_id)

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE emp_id=?", (emp_id,))
    c.execute("DELETE FROM user_finger_map WHERE emp_id=?", (emp_id,))
    conn.commit()
    enqueue_sync_to_all_devices("user_delete", {"emp_id": emp_id})

    conn.close()

    if mapped is not None:
        db = get_finger_db()
        db.execute("DELETE FROM fingerprints WHERE id=?", (mapped,))
        db.commit()
        db.close()

    recognizer.delete_user(emp_id)
    recognizer.load_all_encodings()

    # NOTE: broadcasting to other devices (TCP/UDP) has been removed.
    # If you want to re-enable mesh broadcasts later, implement a safe broadcasting mechanism here.
    # state = load_mesh_state()
    # self_ip = get_self_ip()
    # if state.get("is_root", False) and state.get("devices"):
    #     payload = {"type": "user_delete", "emp_id": emp_id}
    #     for dev in state["devices"]:
    #         ip = dev["ip"]
    #         if ip != self_ip:
    #             # broadcasting intentionally omitted
    #             pass

    return jsonify({"success": True, "message": f"User {emp_id} deleted from system."})


# -----------------------------------------------------------------------------
# Sync status & manual drain
# -----------------------------------------------------------------------------
@app.route("/api/sync_status")
def api_sync_status():
    conn = get_db_connection()
    row = conn.execute("SELECT COUNT(*) AS c FROM pg_event_queue").fetchone()
    conn.close()
    return jsonify({
        "pg_available": pg_is_available(),
        "pending": row["c"],
        "last_ok": _last_sync_info.get("last_ok"),
        "last_err": _last_sync_info.get("last_err"),
    })


@app.route("/api/sync_drain_now", methods=["POST"])
def api_sync_drain_now():
    try:
        n = drain_pg_queue_once(max_batch=500)
        return jsonify({"success": True, "drained": n})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route("/api/relay/state")
def relay_state():
    return jsonify({"on": relay.value == 1})

@app.route("/api/relay/<action>", methods=["POST"])
def relay_action(action):
    if action == "on":
        relay.on()
    elif action == "off":
        relay.off()
    elif action == "toggle":
        if relay.value == 1:
            relay.off()
        else:
            relay.on()
    else:
        return jsonify({"ok": False, "error": "unknown action"}), 400
    return jsonify({"ok": True, "on": relay.value == 1})


# -----------------------------------------------------------------------------
# Order API (helpers + submit)
# -----------------------------------------------------------------------------
def _resolve_item_full(conn, item_obj):
    if isinstance(item_obj, str):
        return item_obj.strip(), 1
    if not isinstance(item_obj, dict):
        return None, None

    def _deep_get_code(v):
        if isinstance(v, str):
            return v
        if isinstance(v, dict):
            for kk in ("item_code", "code", "id", "item_id", "value"):
                vv = v.get(kk)
                if isinstance(vv, str) and vv.strip():
                    return vv
        return None

    code = None
    for k in ("item_code", "code", "item", "id", "item_id"):
        if k in item_obj and item_obj[k] is not None:
            code = _deep_get_code(item_obj[k])
            if code:
                break

    if not code:
        look_name = None
        for k in ("item_name", "name", "label", "title"):
            v = item_obj.get(k)
            if isinstance(v, str):
                look_name = v.strip()
            elif isinstance(v, dict):
                for kk in ("text", "value", "name", "label"):
                    vv = v.get(kk)
                    if isinstance(vv, str) and vv.strip():
                        look_name = vv.strip()
                        break
            if look_name:
                break
        if look_name:
            row = conn.execute(
                "SELECT item_code FROM items WHERE lower(item_name)=lower(?) LIMIT 1",
                (look_name,)
            ).fetchone()
            if row:
                code = row["item_code"]

    try:
        qty = int(item_obj.get("qty", 1))
    except Exception:
        qty = 1
    if qty <= 0:
        qty = 1

    if isinstance(code, str):
        code = code.strip()
    else:
        code = None

    return (code or None), qty


def place_order_core(*, emp_id: str, item_code: str, qty: int):
    """
    Minimal core: resolves item_name + category, inserts order row(s), prints slip.
    """
    conn = get_db_connection()
    try:
        slot_code, slot_row = get_active_slot_code()
        if not slot_code:
            return False, {"reason": "closed", "message": "Canteen is closed"}
        # Resolve item name and category (menu)
        row = conn.execute("""
            SELECT i.item_code, i.item_name, m.menu_name, m.menu_code
            FROM items i
            JOIN menu_codes m ON m.menu_code = i.menu_code
            WHERE i.item_code=?
            LIMIT 1
        """, (item_code,)).fetchone()
        if not row:
            return False, {"reason": "unknown_item", "message": f"Unknown item_code '{item_code}'"}
        item_name = row["item_name"]
        category  = row["menu_name"]
        shift_name = slot_row["shift_name"] if slot_row else ""
        slot_name  = slot_row["slot_name"] if slot_row else ""

        # Insert order(s)
        order_id = generate_order_id()
        conn.execute("""
            INSERT INTO orders (order_id, emp_id, device_id, shift_code, slot_code, category, item_code, item_name, qty, order_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            order_id, emp_id, get_device_id(),
            slot_row["shift_code"] if slot_row else None,
            slot_code, category, item_code, item_name, int(qty),
            _now_iso()
        ))
        conn.commit()

        # Print slip
        try:
            print_order_receipt(order_id, emp_id, item_name, category, slot_name, shift_name)
        except Exception:
            pass

        return True, {
            "order_id": order_id,
            "item": {
                "item_code": item_code,
                "item_name": item_name,
                "category": category,
                "qty": int(qty),
            }
        }
    finally:
        conn.close()


@app.route("/api/order_submit", methods=["POST"])
def order_submit():
    data = request.get_json(silent=True) or {}

    emp_id = (data.get("emp_id") or data.get("employee_id") or data.get("user_id") or "")
    emp_id = str(emp_id).strip()
    if not emp_id:
        return jsonify({
            "success": False,
            "message": "emp_id missing (accepted keys: emp_id / employee_id / user_id).",
            "echo": data
        }), 400

    items_in = data.get("items")
    if not items_in:
        if any(k in data for k in ("item_code", "code", "item", "item_name", "name", "label", "title", "id", "item_id")):
            items_in = [data]
        else:
            return jsonify({
                "success": False,
                "message": "emp_id and items are required.",
                "hint": "Send items like [{'item_code':'TEA','qty':1}] or use 'item_name'.",
                "echo": data
            }), 400

    conn = get_db_connection()
    try:
        slot_code, slot_row = get_active_slot_code()
        if not slot_code:
            return jsonify({"success": False, "rejected": [{"reason": "closed", "message": "Canteen is closed"}], "accepted": []}), 400

        grouped = group_items_for_limits(conn, items_in)
        try:
            _ = validate_items_against_limits(conn, emp_id=emp_id, slot_code=slot_code, grouped_items=grouped)
        except SlotLimitError as e:
            return jsonify({
                "success": False,
                "accepted": [],
                "rejected": [{"reason": e.code, "message": str(e), "meta": e.meta}]
            }), 400

        successes, failures = [], []
        for raw in items_in:
            code, qty = _resolve_item_full(conn, raw)
            if not code:
                failures.append({"input": raw, "reason": "unresolved_item", "message": "Could not resolve to known item_code/item_name"})
                continue

            ok, payload = place_order_core(emp_id=emp_id, item_code=code, qty=qty)
            if ok:
                successes.append({
                    "item_code": code,
                    "qty": qty,
                    "order_id": payload.get("order_id"),
                    "item": payload.get("item")
                })
            else:
                failures.append({
                    "item_code": code,
                    "qty": qty,
                    **payload
                })

        overall_ok = len(successes) > 0
        return jsonify({
            "success": overall_ok,
            "accepted": successes,
            "rejected": failures
        }), (200 if overall_ok else 400)
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Admin gates (face/finger/rfid/password)
# -----------------------------------------------------------------------------
def _is_operator_role(role: str | None) -> bool:
    if not role: return False
    r = role.strip().lower()
    return r in ("admin", "super admin", "superadmin")


def _fetch_user_row(emp_id: str):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT emp_id, name, role FROM users WHERE emp_id=?", (str(emp_id),)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


@app.route("/api/operator_face_verify", methods=["POST"])
def api_operator_face_verify():
    data = request.get_json(silent=True) or {}
    img_b64 = (data.get("image") or "").split(",")[-1]
    if not img_b64:
        return jsonify({"success": False, "message": "no_image"}), 400

    try:
        img_bytes = base64.b64decode(img_b64)
        nparr = np.frombuffer(img_bytes, np.uint8)
        bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if bgr is None:
            return jsonify({"success": False, "message": "decode_failed"}), 400
        rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)

        import face_recognition
        if not face_recognition.face_locations(rgb):
            return jsonify({"success": False, "message": "no_face"})

        user_id = recognizer.recognize(rgb)
        if not user_id:
            return jsonify({"success": False, "message": "unknown_face"})

        u = _fetch_user_row(str(user_id)) or {"emp_id": str(user_id), "name": "", "role": ""}
        if not _is_operator_role(u.get("role")):
            return jsonify({"success": False, "message": "not_admin"}), 403

        session["admin_session_active"] = True
        session["admin_emp_id"] = str(u["emp_id"])
        return jsonify({"success": True, "emp_id": str(u["emp_id"]), "name": u.get("name",""), "role": u.get("role","")})
    except Exception as e:
        return jsonify({"success": False, "message": f"error: {e}"}), 500



@app.route("/api/operator_rfid_verify", methods=["POST"])
def api_operator_rfid_verify():
    try:
        ok, res = rfid.rfid_login()
        if not ok:
            return jsonify({"success": False, "message": "no_card"})

        emp = str(res.get("employee_id") or res.get("emp_id") or "")
        if not emp:
            return jsonify({"success": False, "message": "no_emp_id"}), 400

        u = _fetch_user_row(emp) or {"emp_id": emp, "name": "", "role": ""}
        if not _is_operator_role(u.get("role")):
            return jsonify({"success": False, "message": "not_admin"}), 403

        session["admin_session_active"] = True
        session["admin_emp_id"] = str(u["emp_id"])
        return jsonify({"success": True, "emp_id": str(u["emp_id"]), "name": u.get("name",""), "role": u.get("role","")})
    except Exception as e:
        return jsonify({"success": False, "message": f"error: {e}"}), 500


# Password fallback for operator
@app.route("/api/operator_password_login", methods=["POST"])
def api_operator_password_login():
    data = request.get_json(silent=True) or {}
    pw = (data.get("password") or "").strip()
    if not pw:
        return jsonify({"success": False, "message": "Password required"}), 400
    if not check_admin_password(pw):
        return jsonify({"success": False, "message": "Invalid password"}), 403

    session["admin_session_active"] = True
    session["admin_emp_id"] = "ADMIN"
    return jsonify({"success": True, "emp_id": "ADMIN", "name": "Administrator", "role": "Admin"})


# -----------------------------------------------------------------------------
# Handoff (QR) Import/Export flow
# -----------------------------------------------------------------------------
def _qr_base_url():
    # 1) explicit
    base = (app.config.get("PUBLIC_BASE_URL") or "").strip()
    if base:
        return base.rstrip("/")
    # 2) infer from request; if localhost, use LAN IP
    host = (request.host or "").split(":")[0]
    if host in ("127.0.0.1", "localhost"):
        ip = "127.0.0.1"
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            pass
        finally:
            try:
                if s:
                    s.close()
            except Exception:
                pass
        return f"http://{ip}:{app.config.get('APP_PORT', 5000)}"
    # 3) default to host_url
    return request.host_url.rstrip("/")


@app.route("/api/handoff_begin")
def api_handoff_begin():
    mode = (request.args.get("mode") or "").strip().lower()
    if mode not in ("import", "export"):
        return jsonify({"success": False, "message": "mode must be import or export"}), 400
    token = uuid.uuid4().hex[:8]
    state = {
        "mode": mode,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "status": "pending",
        "have_file": False,
        "original_name": "",
    }
    set_setting(f"handoff:{mode}-{token}", json.dumps(state))
    base = _qr_base_url()
    phone_url = f"{base}/handoff/{mode}/{mode}-{token}"
    return jsonify({"success": True, "token": f"{mode}-{token}", "url": phone_url})


@app.route("/api/handoff_status")
def api_handoff_status_qs():
    token = (request.args.get("token") or "").strip()
    if not token:
        return jsonify({"success": True, "exists": False}), 404
    return api_handoff_status_path(token)


@app.route("/api/handoff_status/<token>")
def api_handoff_status_path(token):
    blob = get_setting(f"handoff:{token}")
    if not blob:
        return jsonify({"success": True, "exists": False}), 404
    try:
        state = json.loads(blob)
    except Exception:
        return jsonify({"success": True, "exists": False}), 404

    out = {
        "success": True,
        "exists": True,
        "mode": state.get("mode"),
        "status": state.get("status", "pending"),
        "have_file": bool(state.get("have_file")),
        "original_name": state.get("original_name", ""),
    }
    return jsonify(out)


@app.route("/handoff/<mode>/<token>")
def handoff_portal(mode, token):
    blob = get_setting(f"handoff:{token}")
    if not blob:
        return render_template("handoff_portal.html", mode="expired", token=token), 403

    try:
        state = json.loads(blob)
    except Exception:
        return render_template("handoff_portal.html", mode="expired", token=token), 403

    created_at = state.get("created_at")
    if created_at:
        try:
            created = datetime.fromisoformat(created_at)
            if (datetime.now() - created).total_seconds() > HANDOFF_TTL_SECONDS:
                return render_template("handoff_portal.html", mode="expired", token=token), 403
        except Exception:
            pass

    mode = (mode or "").strip().lower()
    if mode not in ("import", "export") or state.get("mode") != mode:
        return render_template("handoff_portal.html", mode="expired", token=token), 403

    return render_template("handoff_portal.html", mode=mode, token=token)


@app.route("/api/import_upload", methods=["POST"])
def api_import_upload():
    token = (request.form.get("token") or "").strip()
    if not token:
        return jsonify(success=False, message="Missing token"), 400

    blob = get_setting(f"handoff:{token}")
    if not blob:
        return jsonify(success=False, message="Invalid or expired token"), 403
    try:
        state = json.loads(blob)
    except Exception:
        return jsonify(success=False, message="Token state corrupt"), 403
    if state.get("mode") != "import":
        return jsonify(success=False, message="Token is not for import"), 403

    f = request.files.get("file")
    if not f or f.filename == "":
        return jsonify(success=False, message="No file provided"), 400

    fname = secure_filename(f.filename)
    if not fname.lower().endswith(".xlsx"):
        return jsonify(success=False, message="Please upload a .xlsx file"), 400

    # Optionally persist the upload
    save_path = os.path.join(HANDOFF_UPLOAD_DIR, f"{token}__{fname}")
    try:
        f.save(save_path)
    except Exception as e:
        return jsonify(success=False, message=f"Save failed: {e}"), 500

    # Apply to DB
    try:
        with open(save_path, "rb") as xf:
            result = apply_xlsx_to_db(xf)
    except Exception as e:
        return jsonify(success=False, message=f"Import failed: {e}"), 500

    state.update({
        "status": "received",
        "have_file": True,
        "file_path": save_path,
        "original_name": fname,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "import_result": result
    })
    set_setting(f"handoff:{token}", json.dumps(state))

    return jsonify(success=result.get("ok", False), result=result, name=fname)


def _build_export_zip_bytes():
    """Build a ZIP that contains one .xlsx per SQLite table."""
    try:
        return io.BytesIO(export_all_tables_as_zip_of_xlsx())
    except Exception as e:
        # Fallback to old behavior if absolutely necessary
        print(f"[EXPORT] XLSX pack failed: {e}")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            if os.path.exists(DB_PATH):
                z.write(DB_PATH, arcname="users.db")
        buf.seek(0)
        return buf


@app.route("/api/handoff_prepare_export/<token>", methods=["POST"])
def api_handoff_prepare_export(token):
    blob = get_setting(f"handoff:{token}")
    if not blob:
        return jsonify(success=False, message="Invalid token"), 404
    try:
        state = json.loads(blob)
    except Exception:
        return jsonify(success=False, message="Corrupt token"), 404
    if state.get("mode") != "export":
        return jsonify(success=False, message="Wrong mode"), 400

    try:
        zip_bytes = export_all_tables_as_zip_of_xlsx()
        out_path = os.path.join(HANDOFF_UPLOAD_DIR, f"{token}_export.zip")
        with open(out_path, "wb") as f:
            f.write(zip_bytes)
        state.update({"prepared_zip": out_path, "status": "ready"})
        set_setting(f"handoff:{token}", json.dumps(state))
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


@app.route("/api/export_zip")
def api_export_zip():
    token = (request.args.get("token") or "").strip()
    if not token:
        abort(400, "Missing token")

    blob = get_setting(f"handoff:{token}")
    if not blob:
        abort(403, "Invalid or expired token")
    try:
        state = json.loads(blob)
    except Exception:
        abort(403, "Token corrupt")

    if state.get("mode") != "export":
        abort(403, "Wrong mode")

    p = state.get("prepared_zip")
    if p and os.path.exists(p):
        return send_file(p, as_attachment=True, download_name="export.zip", mimetype="application/zip")

    # Fallback: build now
    try:
        zip_bytes = export_all_tables_as_zip_of_xlsx()
        buf = io.BytesIO(zip_bytes)
        return send_file(buf, as_attachment=True, download_name="export.zip", mimetype="application/zip")
    except Exception as e:
        abort(500, f"Export failed: {e}")


# -----------------------------------------------------------------------------
# Themed Categories & Items browsing
# -----------------------------------------------------------------------------
@app.route('/api/categories')
def api_categories():
    db = get_db_connection()
    categories = [row['menu_name'] for row in db.execute("SELECT DISTINCT menu_name FROM menu_codes")]
    db.close()
    return jsonify(categories=categories)


@app.route('/api/items_for_category')
def api_items_for_category():
    category = request.args.get('category')
    db = get_db_connection()
    rows = db.execute("SELECT menu_code FROM menu_codes WHERE menu_name=?", (category,)).fetchall()
    if not rows:
        db.close()
        return jsonify(items=[])
    items = []
    for r in rows:
        items.extend([row['item_name'] for row in db.execute("SELECT item_name FROM items WHERE menu_code=?", (r['menu_code'],))])
    db.close()
    return jsonify(items=items)


# -----------------------------------------------------------------------------
# Users list API (paginated)
# -----------------------------------------------------------------------------
import logging

@app.get("/api/users_list")
def api_users_list():
    try:
        limit  = int(request.args.get("limit", "5000"))
        offset = int(request.args.get("offset", "0"))

        sql = """
            SELECT emp_id, name
            FROM users
            ORDER BY CAST(emp_id AS TEXT) ASC
            LIMIT ? OFFSET ?
        """
        params = (limit, offset)

        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()
        finally:
            conn.close()

        users = []
        for r in rows:
            emp_id = "" if r[0] is None else str(r[0])
            name   = "" if r[1] is None else str(r[1])
            users.append({"emp_id": emp_id, "name": name})

        return jsonify(success=True, users=users)
    except Exception as e:
        logging.exception("Error in /api/users_list")
        return jsonify(success=False, message=str(e)), 500


# -----------------------------------------------------------------------------
# QR image helper for handoff tokens
# -----------------------------------------------------------------------------
import io as _io_for_qr  # avoid shadowing above
import json as _json_for_qr
import qrcode as _qrcode_for_qr
from flask import send_file as _send_file_for_qr, abort as _abort_for_qr

@app.route("/api/qr_for_handoff/<token>.png")
def api_qr_for_handoff_png(token):
    blob = get_setting(f"handoff:{token}")
    if not blob:
        _abort_for_qr(404, "Invalid or expired token")
    try:
        state = _json_for_qr.loads(blob)
    except Exception:
        _abort_for_qr(404, "Corrupt token")
    mode = state.get("mode")
    if mode not in ("import","export"):
        _abort_for_qr(400, "Bad mode")

    # Construct phone URL (match your handoff portal route)
    base = app.config.get("PUBLIC_BASE_URL") or request.host_url.rstrip("/")
    # If kiosk is on 127.0.0.1/localhost, swap to LAN IP (optional)
    host = (request.host or "").split(":")[0]
    if host in ("127.0.0.1","localhost"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            base = f"http://{ip}:{app.config.get('APP_PORT', 5000)}"
        except Exception:
            pass

    phone_url = f"{base}/handoff/{mode}/{token}"

    buf = _io_for_qr.BytesIO()
    _qrcode_for_qr.make(phone_url).save(buf, format="PNG")
    buf.seek(0)
    return _send_file_for_qr(buf, mimetype="image/png")


# ---------------- XLSX helpers ----------------
def sqlite_list_tables(conn):
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [r[0] for r in rows]


def sqlite_table_info(conn, table):
    rows = conn.execute(f"PRAGMA table_info('{table}')").fetchall()
    cols = []
    for r in rows:
        if isinstance(r, sqlite3.Row):
            cols.append(dict(r))
        else:
            cols.append({"cid": r[0], "name": r[1], "type": r[2], "notnull": r[3], "dflt_value": r[4], "pk": r[5]})
    return cols


def _coerce_nan_to_none(df: pd.DataFrame) -> pd.DataFrame:
    return df.where(pd.notna(df), None)


def _xlsx_bytes_from_dataframe(df: pd.DataFrame, sheet_name="Sheet1") -> bytes:
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as w:
        df.to_excel(w, index=False, sheet_name=sheet_name)
    buf.seek(0)
    return buf.read()


def export_all_tables_as_zip_of_xlsx() -> bytes:
    conn = get_db_connection()
    try:
        tables = sqlite_list_tables(conn)
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for table in tables:
                try:
                    df = pd.read_sql_query(f'SELECT * FROM "{table}"', conn)
                    xlsx_bytes = _xlsx_bytes_from_dataframe(df, sheet_name=table)
                    zf.writestr(f"{table}.xlsx", xlsx_bytes)
                except Exception as e:
                    print(f"[EXPORT] skip {table}: {e}")
        zbuf.seek(0)
        return zbuf.read()
    finally:
        conn.close()


def apply_xlsx_to_db(xlsx_file) -> dict:
    """
    Accepts a single .xlsx with multiple sheets. Sheet name must match table name.
    Columns must be valid columns in that table. Uses INSERT OR REPLACE.
    """
    res = {"ok": True, "updated": {}, "errors": []}
    try:
        xl = pd.ExcelFile(xlsx_file)
    except Exception as e:
        return {"ok": False, "updated": {}, "errors": [f"Failed to read Excel: {e}"]}

    conn = get_db_connection()
    try:
        tables = set(sqlite_list_tables(conn))
        for sheet in xl.sheet_names:
            table = sheet.strip()
            if table not in tables:
                res["errors"].append(f"Skipping sheet '{sheet}': no matching table.")
                continue
            try:
                df = xl.parse(sheet_name=sheet).dropna(how="all")
            except Exception as e:
                res["ok"] = False
                res["errors"].append(f"Sheet '{sheet}': parse error: {e}")
                continue
            if df.empty:
                res["updated"][table] = 0
                continue

            info = sqlite_table_info(conn, table)
            table_cols = [c["name"] for c in info]
            keep = [c for c in df.columns if c in table_cols]
            if not keep:
                res["errors"].append(f"Sheet '{sheet}': no valid columns for '{table}'.")
                continue

            df = df[keep]
            df = _coerce_nan_to_none(df)

            placeholders = ", ".join(["?"] * len(keep))
            col_list = ", ".join([f'"{c}"' for c in keep])
            sql = f'INSERT OR REPLACE INTO "{table}" ({col_list}) VALUES ({placeholders})'

            cur = conn.cursor()
            count = 0
            try:
                for row in df.itertuples(index=False, name=None):
                    cur.execute(sql, tuple(row))
                    count += 1
                conn.commit()
            except Exception as e:
                conn.rollback()
                res["ok"] = False
                res["errors"].append(f"Sheet '{sheet}': DB error: {e}")
                continue
            res["updated"][table] = count
    finally:
        conn.close()
    return res


# ========= NEW: login logging + days-allowed policy =========
def insert_login_log(emp_id: str, name: str, mode: str):
    try:
        # Ensure table exists before insert (safe on every call)
        ensure_logs_table()
        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO logs (emp_id, name, device_id, mode, ts) VALUES (?, ?, ?, ?, ?)",
                (str(emp_id or ""), name or "", get_device_id(), mode, datetime.now().isoformat(timespec="seconds"))
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print("[logs] insert_login_log error:", e)


def _unique_day(dts: str) -> str:
    return (dts or "")[:10]


def _consecutive_days_count(emp_id: str) -> int:
    ensure_logs_table()
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT ts FROM logs WHERE emp_id=? ORDER BY ts DESC",
            (str(emp_id),)
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        return 0
    days = []
    seen = set()
    for r in rows:
        d = _unique_day(r["ts"])
        if d and d not in seen:
            days.append(d)
            seen.add(d)
    if not days:
        return 0
    today = date.today()
    count = 0
    cur = today
    for d in days:
        try:
            y, m, dd = d.split("-")
            ddt = date(int(y), int(m), int(dd))
        except Exception:
            continue
        if ddt == cur:
            count += 1
            cur = cur.fromordinal(cur.toordinal() - 1)
        else:
            break
    return count


def is_login_allowed_by_days(emp_id: str):
    try:
        dal = int(get_setting("days_allowed", "0") or "0")
    except Exception:
        dal = 0
    if dal <= 0:
        return True, None
    consec = _consecutive_days_count(emp_id)
    if consec >= dal:
        return False, f"Consecutive days limit reached ({dal}). User must take leave today."
    return True, None


@app.route("/api/days_allowed", methods=["GET"])
def api_days_allowed_get():
    try:
        val = int(get_setting("days_allowed", "0") or "0")
    except Exception:
        val = 0
    return jsonify({"success": True, "days_allowed": val})


@app.route("/api/days_allowed", methods=["POST"])
def api_days_allowed_set():
    data = request.get_json(force=True) or {}
    try:
        val = int(str(data.get("days_allowed", "0")).strip() or "0")
        if val < 0:
            val = 0
    except Exception:
        return jsonify({"success": False, "message": "days_allowed must be a number"}), 400
    set_setting("days_allowed", str(val))
    return jsonify({"success": True, "message": "Days allowed saved", "days_allowed": val})


# -----------------------------------------------------------------------------
# Logs UI + APIs
# -----------------------------------------------------------------------------
@app.route("/logs")
def logs_page():
    return render_template("logs.html")


@app.route("/api/logs")
def api_logs_list():
    ensure_logs_table()
    q = (request.args.get("q") or "").strip()
    try:
        limit = max(1, min(1000, int(request.args.get("limit", "200"))))
    except Exception:
        limit = 200
    try:
        offset = max(0, int(request.args.get("offset", "0")))
    except Exception:
        offset = 0

    conn = get_db_connection()
    try:
        if q:
            rows = conn.execute(
                """
                SELECT id, emp_id, name, device_id, mode, ts
                FROM logs
                WHERE emp_id LIKE ? OR name LIKE ?
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (f"%{q}%", f"%{q}%", limit, offset)
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, emp_id, name, device_id, mode, ts
                FROM logs
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset)
            ).fetchall()
        data = [dict(r) for r in rows]
        return jsonify({"success": True, "rows": data})
    finally:
        conn.close()


@app.route("/api/logs_export_csv")
def api_logs_export_csv():
    ensure_logs_table()
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT id, emp_id, name, device_id, mode, ts FROM logs ORDER BY id DESC").fetchall()
        import csv, io as _io2
        buf = _io2.StringIO()
        w = csv.writer(buf)
        w.writerow(["id","emp_id","name","device_id","mode","timestamp"])
        for r in rows:
            w.writerow([r["id"], r["emp_id"], r["name"], r["device_id"], r["mode"], r["ts"]])
        buf.seek(0)
        return Response(
            buf.getvalue(),
            headers={"Content-Disposition": "attachment; filename=logs.csv"},
            mimetype="text/csv"
        )
    finally:
        conn.close()

from pathlib import Path
import subprocess, json

@app.get("/api/version")
def api_version():
    # Read from version.txt so UI shows what the updater uses
    vfile = Path("version.txt")
    v = vfile.read_text().strip() if vfile.exists() else "0.0.0"
    return {"version": v}

@app.post("/api/reboot")
def api_reboot():
    try:
        subprocess.Popen(["sudo","systemctl","reboot"])
        return {"success": True, "message": "Rebooting..."}
    except Exception as e:
        return {"success": False, "message": str(e)}, 500

@app.post("/api/shutdown")
def api_shutdown():
    try:
        subprocess.Popen(["sudo","systemctl","poweroff"])
        return {"success": True, "message": "Shutting down..."}
    except Exception as e:
        return {"success": False, "message": str(e)}, 500
# --- Discovery dashboard routes & APIs ---
from flask import render_template, request, jsonify

@app.route("/discovery")
def discovery_page():
    """
    Render discovery dashboard page.
    Template references BRAND_LOGO injected by your existing inject_brand() context processor.
    """
    return render_template("discovery.html")


@app.route("/api/discovery/list", methods=["GET"])
def api_discovery_list():
    """
    Return discovered devices from mesh_devices table.
    If you later add 'last_seen' tracking, include it in the output.
    """
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT ip, device_id, name, port FROM mesh_devices ORDER BY ip COLLATE NOCASE").fetchall()
        devices = []
        for r in rows:
            devices.append({
                "ip": r["ip"],
                "device_id": r["device_id"],
                "name": r["name"],
                "port": int(r["port"] or UDP_PORT)
                # optionally add 'last_seen' if you add that column later
            })
        conn.close()
        return jsonify({"success": True, "devices": devices})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/discovery/scan", methods=["POST"])
def api_discovery_scan():
    """
    Trigger a network discovery broadcast (non-blocking).
    We spawn it in a thread so HTTP returns quickly; the listener will populate mesh_devices.
    """
    try:
        # run broadcast in a background thread so UI doesn't wait
        run_parallel(lambda: discovery_broadcast_once())
        return jsonify({"success": True, "message": "Discovery broadcast sent"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/discovery/pair", methods=["POST"])
def api_discovery_pair():
    """
    Mark a device as 'paired' by storing it in app_settings (simple approach).
    You can expand this to keep a separate pairing table.
    """
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"success": False, "message": "ip required"}), 400
    try:
        # store the paired target ip (simple single-target pairing)
        set_setting("paired_target_ip", ip)
        return jsonify({"success": True, "paired_ip": ip})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/discovery/sync", methods=["POST"])
def api_discovery_sync():
    """
    Enqueue a small 'request_sync' message to the selected device IP.
    This uses your reliable enqueue helper (so worker will attempt delivery).
    """
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    port = int((data.get("port") or UDP_PORT) or UDP_PORT)
    if not ip:
        return jsonify({"success": False, "message": "ip required"}), 400
    try:
        # prepare a minimal sync payload — you can expand to include actual user data.
        payload = {
            "type": "request_sync_users",
            "from": get_self_ip(),
            "requested_at": _now_iso()
        }
        # enqueue reliable send to single device
        reliable_udp_send_to(ip, port, payload, message_type="request_sync")
        return jsonify({"success": True, "message": "sync enqueued", "ip": ip})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/discovery/remove", methods=["POST"])
def api_discovery_remove():
    """
    Remove a discovered device from mesh_devices table.
    """
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"success": False, "message": "ip required"}), 400
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM mesh_devices WHERE ip=?", (ip,))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "removed": ip})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# -----------------------------------------------------------------------------
# Main entry
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    # Make sure critical tables exist before anything logs
    ensure_logs_table()
    # before starting the server or right after app/init:
    ensure_schema_migrations()

    # Persist TTL setting (optional)
    set_setting("handoff_ttl_seconds", str(HANDOFF_TTL_SECONDS))
    # App runs even if Postgres is down; events queue and sync later.
    app.run(host='0.0.0.0', port=app.config.get("APP_PORT", 5000), debug=False)
