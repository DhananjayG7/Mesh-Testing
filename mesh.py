import base64
import json
import socket
import threading
import sqlite3
import platform
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify
import os
import time

mesh_bp = Blueprint('mesh', __name__)
BROADCAST_PORT = 5005
ENCODING_PORT = 5006
MESH_STATE_FILE = "mesh_state.json"
DB_PATH = "users.db"
FINGER_DB_PATH = "fingerprints.db"
DEVICE_TIMEOUT = 20  # seconds before removing a device

# ---- Device Discovery (live, in-memory only) ----
known_devices = {}
known_devices_lock = threading.Lock()

def get_self_ip():
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip.startswith("127."):
            ip = os.popen("hostname -I").read().split()[0]
        return ip.strip()
    except: return "127.0.0.1"

def load_mesh_state():
    if os.path.exists(MESH_STATE_FILE):
        with open(MESH_STATE_FILE) as f:
            return json.load(f)
    return {}

def save_mesh_state(state):
    with open(MESH_STATE_FILE, "w") as f:
        json.dump(state, f)

def get_current_mesh_devices():
    now = time.time()
    with known_devices_lock:
        # Only show devices that have broadcasted in the last DEVICE_TIMEOUT seconds
        return [
            v for v in known_devices.values()
            if now - v.get("timestamp", 0) < DEVICE_TIMEOUT
        ]

def cleanup_known_devices():
    now = time.time()
    with known_devices_lock:
        for k in list(known_devices.keys()):
            if now - known_devices[k].get("timestamp", 0) > DEVICE_TIMEOUT:
                del known_devices[k]

def send_to_all_mesh(payload):
    # Always send to currently active devices except self
    my_ip = get_self_ip()
    for dev in get_current_mesh_devices():
        ip = dev.get("ip")
        if ip and ip != my_ip:
            send_udp_json(ip, ENCODING_PORT, payload)

# ----------- Flask Routes -----------

@mesh_bp.route("/device_comm")
def mesh_ui():
    return render_template("device_comm.html")

@mesh_bp.route("/api/mesh_devices")
def mesh_devices():
    cleanup_known_devices()
    devices = get_current_mesh_devices()
    return jsonify(devices={d['device']: d for d in devices})

@mesh_bp.route("/api/mesh_status")
def mesh_status():
    state = load_mesh_state()
    self_ip = get_self_ip()
    is_root = state.get("is_root", False)
    connected = bool(state.get("devices"))
    root_ip = state.get("root_ip", None)
    devices = state.get("devices", [])
    return jsonify({
        "is_root": is_root,
        "connected": connected,
        "root_ip": root_ip,
        "devices": devices,
        "self_ip": self_ip,
    })

@mesh_bp.route('/api/create_mesh', methods=['POST'])
def api_create_mesh():
    data = request.json
    ips = data.get("ips", [])
    self_ip = get_self_ip()
    # Pull device names from known_devices
    with known_devices_lock:
        device_map = {d['ip']: d for d in known_devices.values()}
    devices = []
    for ip in ips:
        dev = device_map.get(ip)
        dev_name = dev['device'] if dev else ip
        devices.append({"ip": ip, "device": dev_name})
    # Add self
    self_name = socket.gethostname()
    devices.append({"ip": self_ip, "device": self_name})

    mesh_state = {
        "root_ip": self_ip,
        "is_root": True,
        "devices": devices
    }
    save_mesh_state(mesh_state)
    # Propagate mesh to all members (UDP unicast)
    payload = {
        "type": "mesh_update",
        "mesh_state": mesh_state
    }
    send_to_all_mesh(payload)
    return jsonify({"success": True, "message": "Mesh created/updated!"})

@mesh_bp.route("/api/send_face_encoding", methods=["POST"])
def api_send_face_encoding():
    data = request.json
    emp_id = data.get("emp_id")
    # Use all currently active devices!
    current_mesh_devices = get_current_mesh_devices()
    ips = [d["ip"] for d in current_mesh_devices if "ip" in d]
    if not emp_id or not ips:
        return jsonify(success=False, message="Missing emp_id or devices")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT face_encoding, name, display_image FROM users WHERE emp_id=?", (emp_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify(success=False, message="User not found")
    encoding, name, display_image = row
    payload = {
        "type": "face_sync",
        "emp_id": emp_id,
        "name": name,
        "registered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "encoding": base64.b64encode(encoding).decode(),
        "display_image": base64.b64encode(display_image).decode() if display_image else None
    }
    failed = []
    for ip in ips:
        try:
            send_udp_json(ip, ENCODING_PORT, payload)
        except Exception as e:
            print(f"[Mesh] Failed to send to {ip}:", e)
            failed.append(ip)
    success = not failed
    msg = "Sent successfully." if success else f"Failed for: {', '.join(failed)}"
    return jsonify(success=success, message=msg)

# ========== UDP Networking & Receivers ==========

def send_udp_json(ip, port, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(json.dumps(payload).encode(), (ip, port))
    sock.close()

def receive_mesh_broadcast():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('', BROADCAST_PORT))
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            msg = json.loads(data.decode())
            if msg.get("device") and msg.get("ip"):
                with known_devices_lock:
                    # Always update!
                    known_devices[msg["device"]] = msg
            # Clean up old devices regularly
            cleanup_known_devices()
        except Exception as e:
            print(f"[Mesh] Broadcast receive error: {e}")

def receive_mesh_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', ENCODING_PORT))
    while True:
        try:
            data, addr = sock.recvfrom(16384)
            msg = json.loads(data.decode())
            # Mesh topology update
            if msg.get("type") == "mesh_update":
                mesh_state = msg["mesh_state"]
                self_ip = get_self_ip()
                if any(d["ip"] == self_ip for d in mesh_state.get("devices", [])):
                    mesh_state["is_root"] = (mesh_state.get("root_ip") == self_ip)
                    save_mesh_state(mesh_state)
                    print("[Mesh] Mesh state updated from root.")
            # ---- FACE SYNC ----
            elif msg.get("type") == "face_sync":
                emp_id = msg["emp_id"]
                name = msg.get("name")
                enc_bytes = base64.b64decode(msg["encoding"])
                display_image = base64.b64decode(msg["display_image"]) if msg.get("display_image") else None
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                if display_image:
                    c.execute("INSERT OR REPLACE INTO users (emp_id, name, face_encoding, display_image) VALUES (?, ?, ?, ?)",
                              (emp_id, name, enc_bytes, display_image))
                else:
                    c.execute("INSERT OR REPLACE INTO users (emp_id, name, face_encoding) VALUES (?, ?, ?)",
                              (emp_id, name, enc_bytes))
                conn.commit()
                conn.close()
                print(f"[Mesh] Synced face encoding for {emp_id}")
            elif msg.get("type") == "face_delete":
                emp_id = msg["emp_id"]
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("DELETE FROM users WHERE emp_id=?", (emp_id,))
                conn.commit()
                conn.close()
                print(f"[Mesh] Face deleted for {emp_id}")
            elif msg.get("type") == "face_edit":
                emp_id = msg["emp_id"]
                name = msg.get("name")
                encoding_bytes = base64.b64decode(msg["encoding"])
                display_image = base64.b64decode(msg["display_image"]) if msg.get("display_image") else None
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                if display_image:
                    c.execute("UPDATE users SET face_encoding=?, name=?, display_image=? WHERE emp_id=?", (encoding_bytes, name, display_image, emp_id))
                else:
                    c.execute("UPDATE users SET face_encoding=?, name=? WHERE emp_id=?", (encoding_bytes, name, emp_id))
                conn.commit()
                conn.close()
                print(f"[Mesh] Face updated for {emp_id}")
            # ---- FINGERPRINT SYNC ----
            elif msg.get("type") == "finger_register":
                user_id = int(msg["user_id"])
                username = msg.get("username", "")
                tpl = base64.b64decode(msg["template"])
                db = sqlite3.connect(FINGER_DB_PATH)
                db.execute('''CREATE TABLE IF NOT EXISTS fingerprints (
                    id INTEGER PRIMARY KEY,
                    username TEXT,
                    template BLOB NOT NULL
                )''')
                db.execute("INSERT OR REPLACE INTO fingerprints (id, username, template) VALUES (?, ?, ?)", (user_id, username, tpl))
                db.commit()
                db.close()
                print(f"[Mesh] Synced fingerprint for {user_id}")
            elif msg.get("type") == "finger_edit":
                user_id = int(msg["user_id"])
                username = msg.get("username", "")
                tpl = base64.b64decode(msg["template"])
                db = sqlite3.connect(FINGER_DB_PATH)
                db.execute("UPDATE fingerprints SET username=?, template=? WHERE id=?", (username, tpl, user_id))
                db.commit()
                db.close()
                print(f"[Mesh] Fingerprint edited for {user_id}")
            elif msg.get("type") == "finger_delete":
                user_id = int(msg["user_id"])
                db = sqlite3.connect(FINGER_DB_PATH)
                db.execute("DELETE FROM fingerprints WHERE id=?", (user_id,))
                db.commit()
                db.close()
                print(f"[Mesh] Fingerprint deleted for {user_id}")
            # ---- RFID SYNC ----
            elif msg.get("type") == "rfid_register":
                employee_id = msg["employee_id"]
                name = msg.get("name")
                rfid_cards = msg.get("rfid_cards", [])
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("INSERT OR IGNORE INTO users (emp_id, name) VALUES (?, ?)", (employee_id, name))
                c.execute("UPDATE users SET name=?, rfid_cards=? WHERE emp_id=?", (name, json.dumps(rfid_cards), employee_id))
                conn.commit()
                conn.close()
                print(f"[Mesh] Synced RFID register for {employee_id}")
            elif msg.get("type") == "rfid_edit":
                employee_id = msg["employee_id"]
                name = msg.get("name")
                rfid_cards = msg.get("rfid_cards", [])
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("UPDATE users SET name=?, rfid_cards=? WHERE emp_id=?", (name, json.dumps(rfid_cards), employee_id))
                conn.commit()
                conn.close()
                print(f"[Mesh] Synced RFID edit for {employee_id}")
            elif msg.get("type") == "rfid_delete":
                employee_id = msg["employee_id"]
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("UPDATE users SET rfid_cards=? WHERE emp_id=?", (json.dumps([]), employee_id))
                conn.commit()
                conn.close()
                print(f"[Mesh] Synced RFID delete for {employee_id}")
        except Exception as e:
            print("Mesh receive error:", e)

def start_mesh_broadcast(interval=5):
    BROADCAST_IP = "255.255.255.255"
    DEVICE_ID = platform.node() or f"pi_{os.getpid()}"
    def broadcaster():
        while True:
            try:
                MY_IP = get_self_ip()
                msg = {
                    "device": DEVICE_ID,
                    "ip": MY_IP,
                    "status": "active",
                    "timestamp": time.time()
                }
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.sendto(json.dumps(msg).encode(), (BROADCAST_IP, BROADCAST_PORT))
                sock.close()
            except Exception as e:
                print(f"[Mesh] Broadcast error: {e}")
            time.sleep(interval)
    threading.Thread(target=broadcaster, daemon=True).start()

def start_mesh_receivers():
    threading.Thread(target=receive_mesh_broadcast, daemon=True).start()
    threading.Thread(target=receive_mesh_udp, daemon=True).start()
    start_mesh_broadcast()

# ========== End mesh.py ==========
