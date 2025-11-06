import time
import threading
import subprocess
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from pirc522 import RFID
import board
import busio
import neopixel_spi as neopixel

# =========================
# ---- LED (WS2812/SPI0) --
# =========================
NUM_PIXELS = 4
LED_SPI = busio.SPI(board.SCK, MOSI=board.MOSI)  # SPI0 MOSI (GPIO10)
pixels = neopixel.NeoPixel_SPI(
    LED_SPI, NUM_PIXELS, auto_write=True, pixel_order=neopixel.GRB
)
pixels.brightness = 1.0

def _led_fill(color):
    try:
        pixels.fill(color)
    except Exception:
        pass

def _led_off():
    _led_fill((0, 0, 0))

def led_blink(color, duration=0.5):
    """Blocking blink; always schedule via io pool."""
    try:
        _led_fill(color)
        time.sleep(float(duration))
    finally:
        _led_off()

# =========================
# ---- AUDIO / PRINTER ----
# =========================
AUDIO_PATH = "/home/admin/ethos-device/static/audio/"
PRINTER_PORT = "/dev/serial0"
PRINTER_BAUDRATE = 9600
AUDIO_DEVICE = "plughw:2,0"  # keep as you had

_last_play = {}

def play_wav(file_path, min_interval=0.5):
    """Fire-and-forget WAV playback with basic de-dupe throttle."""
    try:
        now = time.time()
        last = _last_play.get(file_path, 0)
        if now - last < float(min_interval):
            return
        _last_play[file_path] = now
        subprocess.Popen(['aplay', file_path])
    except Exception as e:
        print(f"[AUDIO] error: {e}")

def print_user_id_and_cut(user_id):
    import serial
    GS = b'\x1d'
    CUT_FULL = GS + b'V\x00'
    try:
        with serial.Serial(PRINTER_PORT, PRINTER_BAUDRATE, timeout=2) as printer:
            printer.write(b'\n\n')
            printer.write(f"User ID: {user_id}\n".encode())
            printer.write(b'\n\n')
            printer.write(CUT_FULL)
            printer.flush()
    except Exception as e:
        print(f"[PRINTER] error: {e}")

# =========================
# ---- IO EXECUTOR --------
# =========================
# Use a shared pool instead of spawning many ad-hoc threads
io_exec = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rfid-io")

def run_parallel(*targets):
    """Run small side-effect functions concurrently (daemon-like)."""
    for fn in targets:
        try:
            io_exec.submit(fn)
        except Exception:
            pass

# Convenience wrappers so callsites are clean
def fx_success(emp_id):
    run_parallel(
        lambda: led_blink((0, 255, 0), 0.5),
        lambda: play_wav(AUDIO_PATH + "thank_you.wav"),
        lambda: print_user_id_and_cut(emp_id),
    )

def fx_denied():
    run_parallel(
        lambda: led_blink((255, 0, 0), 0.6),
        lambda: play_wav(AUDIO_PATH + "access_denied.wav"),
    )

def fx_registered(emp_id):
    run_parallel(
        lambda: led_blink((0, 255, 0), 0.5),
        lambda: play_wav(AUDIO_PATH + "Successfully_Registered.wav"),
        lambda: print_user_id_and_cut(emp_id),
    )

def fx_deleted(emp_id):
    run_parallel(
        lambda: led_blink((0, 255, 0), 0.5),
        lambda: play_wav(AUDIO_PATH + "success_deleted.wav"),
        lambda: print_user_id_and_cut(emp_id),
    )

# =========================
# --------- DB ------------
# =========================
USERS_DB_PATH = "users.db"

def _init_users_table():
    conn = sqlite3.connect(USERS_DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        emp_id TEXT PRIMARY KEY,
        name TEXT,
        display_image BLOB,
        face_encoding BLOB,
        rfid_cards TEXT
    )''')
    conn.commit()
    conn.close()

# =========================
# ------ RFID (SPI1) ------
# =========================
RFID_RST = 22
RFID_BUS = 1
RFID_DEVICE = 0
rfid_sensor_lock = threading.Lock()

def rfid_read(timeout=10):
    """
    Blocking RFID tag read with timeout (seconds).
    Returns:
      (True, uid_str)           -> tag PRESENT, UID captured
      (False, "no_tag")         -> no tag detected within timeout (DO NOTHING upstream)
      (False, "<error string>") -> actual error (recommended: still do nothing upstream)
    """
    end = time.time() + (timeout if timeout and timeout > 0 else 10)
    try:
        with rfid_sensor_lock:
            rdr = RFID(bus=RFID_BUS, device=RFID_DEVICE, pin_rst=RFID_RST, pin_irq=None)
            try:
                while time.time() < end:
                    err_req, _ = rdr.request()
                    if not err_req:
                        err_uid, uid = rdr.anticoll()
                        if not err_uid and uid:
                            return True, ''.join(str(i) for i in uid)
                        else:
                            return False, "rfid_uid_error"
                    time.sleep(0.05)
                return False, "no_tag"
            finally:
                try:
                    rdr.cleanup()
                except Exception:
                    pass
    except Exception as e:
        return False, f"rfid_exception:{e}"

# =========================
# --------- APIs ----------
# =========================
def rfid_register(employee_id, name):
    _init_users_table()
    ok, tag = rfid_read()
    if not ok:
        if tag == "no_tag":
            return False, "No card detected"
        return False, f"RFID read error: {tag}"

    try:
        conn = sqlite3.connect(USERS_DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO users (emp_id, name) VALUES (?, ?)", (employee_id, name))
        c.execute("SELECT rfid_cards FROM users WHERE emp_id=?", (employee_id,))
        row = c.fetchone()
        existing = json.loads(row[0]) if row and row[0] else []
        if tag in existing:
            conn.close()
            fx_denied()
            return False, "RFID tag already registered for this user."

        existing.append(tag)
        c.execute("UPDATE users SET rfid_cards=? WHERE emp_id=?", (json.dumps(existing), employee_id))
        conn.commit()
        conn.close()

        fx_registered(employee_id)
        return True, f"Registered {name} with tag {tag}"
    except Exception as e:
        fx_denied()
        return False, str(e)

def rfid_login():
    """
    Fast path:
    - NO base64 image encoding here (UI will fetch via /api/get_user_image later)
    - Side-effects run in background to keep the HTTP response instant
    """
    _init_users_table()
    ok, tag = rfid_read()
    if not ok:
        if tag == "no_tag":
            return False, "No card detected"
        return False, f"RFID read error: {tag}"

    try:
        conn = sqlite3.connect(USERS_DB_PATH)
        c = conn.cursor()
        c.execute("SELECT emp_id, name, rfid_cards FROM users WHERE rfid_cards IS NOT NULL")
        for emp_id, name, cards_json in c.fetchall():
            cards = json.loads(cards_json) if cards_json else []
            if tag in cards:
                # trigger background effects and return immediately
                fx_success(emp_id)
                conn.close()
                # IMPORTANT: do not include image here (saves 100–300 ms)
                return True, {"employee_id": emp_id, "name": name}
        conn.close()

        fx_denied()
        return False, "Unknown RFID tag!"
    except Exception as e:
        fx_denied()
        return False, str(e)

def rfid_edit(employee_id, new_name):
    _init_users_table()
    conn = sqlite3.connect(USERS_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT emp_id FROM users WHERE emp_id=?", (employee_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        fx_denied()
        return False, "Employee not found."
    c.execute("UPDATE users SET name=? WHERE emp_id=?", (new_name, employee_id))
    conn.commit()
    conn.close()

    fx_registered(employee_id)
    return True, "Name updated successfully."

def rfid_delete(employee_id):
    _init_users_table()
    conn = sqlite3.connect(USERS_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT emp_id FROM users WHERE emp_id=?", (employee_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        fx_denied()
        return False, "Employee not found."
    c.execute("UPDATE users SET rfid_cards=? WHERE emp_id=?", (json.dumps([]), employee_id))
    conn.commit()
    conn.close()

    fx_deleted(employee_id)
    return True, "RFID(s) deleted for employee."
