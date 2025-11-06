# face_recognizer.py — prioritized popup + true parallel side-effects (faster popup)

import face_recognition
import sqlite3
import numpy as np
import cv2
import subprocess
import threading
import time
import base64
import io
from concurrent.futures import ThreadPoolExecutor

DB_PATH = "users.db"
AUDIO_PATH = "/home/admin/ethos-device/static/audio/"
PRINTER_PORT = "/dev/serial0"
PRINTER_BAUDRATE = 9600

# =========================
# ---- EXECUTORS/UTILS ----
# =========================
# ui_exec: for *immediate* UI signals (popup); keep single worker to preserve order
ui_exec = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ui")
# io_exec: for background I/O (audio/LED/printer/encoding)
io_exec = ThreadPoolExecutor(max_workers=4, thread_name_prefix="io")

_last_play = {}
_popup_cb = None
_last_popup = {"ts": 0.0, "key": ""}  # rate-limit duplicate popups
_popup_cooldown = 0.15  # seconds (was 0.4 -> snappier)

def go_io(fn, *args, **kwargs):
    """Run a function in the IO pool (non-blocking)."""
    io_exec.submit(fn, *args, **kwargs)

def go_ui(fn, *args, **kwargs):
    """Run a function in the UI pool (non-blocking, prioritized)."""
    ui_exec.submit(fn, *args, **kwargs)

def play_wav(file_path, min_interval=0.6):
    """Non-blocking aplay with simple de-dup throttle."""
    try:
        now = time.monotonic()
        last = _last_play.get(file_path, 0.0)
        if now - last < float(min_interval):
            return
        _last_play[file_path] = now
        subprocess.Popen(["aplay", file_path])
    except Exception as e:
        print(f"[AUDIO] error: {e}")

def print_user_id_and_cut(user_id):
    """Print a small line with the user ID and issue a full cut."""
    try:
        import serial
        GS = b"\x1d"
        CUT_FULL = GS + b"V\x00"
        with serial.Serial(PRINTER_PORT, PRINTER_BAUDRATE, timeout=2) as printer:
            printer.write(b"\n\n")
            printer.write(f"User ID: {user_id}\n".encode())
            printer.write(b"\n\n")
            printer.write(CUT_FULL)
            printer.flush()
    except Exception as e:
        print(f"[PRINTER] error: {e}")

def set_popup_callback(cb):
    """Public API for app.py to provide a popup emitter (Socket.IO/SSE/etc)."""
    global _popup_cb
    _popup_cb = cb

def _emit_popup(payload: dict):
    """Emit popup immediately (priority executor) with rate limit."""
    try:
        if _popup_cb is None:
            return
        # dedupe by (status, emp_id, has_img) within cooldown
        has_img = '1' if (payload.get('image') or '') else '0'
        key = f"{payload.get('status','')}|{payload.get('emp_id','')}|{has_img}"
        now = time.monotonic()
        if key == _last_popup["key"] and (now - _last_popup["ts"]) < _popup_cooldown:
            return
        _last_popup["key"] = key
        _last_popup["ts"] = now
        go_ui(_popup_cb, payload)
    except Exception as e:
        print(f"[POPUP] error: {e}")

# =========================
# --------- LED -----------
# =========================
_led_available = False
_pixels = None

def _init_led_once():
    global _led_available, _pixels
    if _pixels is not None or _led_available:
        return
    try:
        import board
        import busio
        import neopixel_spi as neopixel
        NUM_PIXELS = 4
        LED_SPI = busio.SPI(board.SCK, MOSI=board.MOSI)  # SPI0 MOSI (GPIO10)
        _pixels = neopixel.NeoPixel_SPI(
            LED_SPI, NUM_PIXELS, auto_write=True, pixel_order=neopixel.GRB
        )
        _pixels.brightness = 1.0
        _pixels.fill((0, 0, 0))
        _led_available = True
    except Exception as e:
        _pixels = None
        _led_available = False
        print(f"[LED] init skipped: {e}")

_init_led_once()

def _led_fill(color):
    if not _led_available or _pixels is None:
        return
    try:
        _pixels.fill(color)
    except Exception:
        pass

def _led_off():
    _led_fill((0, 0, 0))

def led_blink(color, duration=0.35):
    """Blocking blink; should be scheduled on io_exec."""
    if not _led_available:
        return
    try:
        _led_fill(color)
        time.sleep(float(duration))
    finally:
        _led_off()

def led_success_bg():
    go_io(led_blink, (0, 255, 0), 0.35)  # quick green

def led_fail_bg():
    go_io(led_blink, (255, 0, 0), 0.6)   # quick red

# =========================
# ---- IMAGE HELPERS ------
# =========================
# Optional TurboJPEG for faster JPEG encode (if installed)
_turbo = None
try:
    from turbojpeg import TurboJPEG
    _turbo = TurboJPEG()
except Exception:
    _turbo = None

def _jpeg_encode_b64(img_bgr, quality=70):
    """Return data URI (jpeg) or '' on failure. Uses TurboJPEG if available."""
    try:
        if _turbo is not None:
            # TurboJPEG expects BGR->RGB conversion — do it quickly
            img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
            buf = _turbo.encode(img_rgb, quality=quality, jpeg_subsample=0)
            b64 = base64.b64encode(buf).decode()
            return "data:image/jpeg;base64," + b64
        # Fallback to OpenCV
        ok, buf = cv2.imencode(".jpg", img_bgr, [int(cv2.IMWRITE_JPEG_QUALITY), int(quality)])
        if not ok:
            return ""
        b64 = base64.b64encode(buf).decode()
        return "data:image/jpeg;base64," + b64
    except Exception:
        return ""

def _crop_for_b64(frame, box, max_side=320):
    """
    box format: (top, right, bottom, left)
    Downscales to max_side px to speed up encode+transport.
    Returns BGR ROI or None.
    """
    try:
        top, right, bottom, left = box
        h, w = frame.shape[:2]
        top = max(0, top); left = max(0, left)
        bottom = min(h, bottom); right = min(w, right)
        if bottom <= top or right <= left:
            return None
        roi = frame[top:bottom, left:right]
        rh, rw = roi.shape[:2]
        scale = min(1.0, float(max_side) / max(rh, rw))
        if scale < 1.0:
            roi = cv2.resize(roi, (int(rw*scale), int(rh*scale)), interpolation=cv2.INTER_AREA)
        return roi
    except Exception:
        return None

def _crop_and_b64(frame, box, jpeg_quality=70, max_side=320):
    """Convenience wrapper."""
    roi = _crop_for_b64(frame, box, max_side=max_side)
    if roi is None:
        return ""
    return _jpeg_encode_b64(roi, quality=jpeg_quality)

# =========================
# ----- FACE RECOG --------
# =========================
class FaceRecognizer:
    def __init__(self, db_path=DB_PATH):
        self.sql_path = db_path
        self.encodings = []
        self.ids = []
        # Haar is okay for speed on Pi; if you switch to YuNet/Scrfd you can swap here.
        self.face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        )
        self.index = None
        self._init_db()
        self.load_all_encodings()

    # expose popup setter
    def set_popup_callback(self, cb):
        set_popup_callback(cb)

    def _init_db(self):
        conn = sqlite3.connect(self.sql_path)
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

    def load_all_encodings(self):
        self.encodings = []
        self.ids = []
        conn = sqlite3.connect(self.sql_path)
        c = conn.cursor()
        self._init_db()
        c.execute("SELECT emp_id, face_encoding FROM users WHERE face_encoding IS NOT NULL")
        rows = c.fetchall()
        conn.close()
        for emp_id, encoding_bytes in rows:
            arr = np.frombuffer(encoding_bytes, dtype=np.float64)
            self.encodings.append(arr)
            self.ids.append(emp_id)
        self.build_index()

    def build_index(self):
        if len(self.encodings) == 0:
            self.index = None
            return
        encs = np.vstack(self.encodings).astype('float32')
        try:
            import faiss
            self.index = faiss.IndexFlatL2(128)
            self.index.add(encs)
        except ImportError:
            self.index = None
            print("faiss not installed, face recognition will use CPU fallback (optimized).")

    def detect_faces(self, frame):
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = self.face_cascade.detectMultiScale(gray, 1.1, 4)
        boxes = []
        for (x, y, w, h) in faces:
            boxes.append([y, x + w, y + h, x])  # (top, right, bottom, left)
        return boxes

    # -----------------------
    # Parallel side-effects
    # -----------------------
    def _emit_success_instant_then_update(self, user_id, frame, box):
        """
        Emit an instant popup (no image), then encode the crop in IO thread and
        re-emit with image so UI updates smoothly without initial delay.
        """
        # 1) instant — no image
        _emit_popup({"status": "success", "emp_id": user_id, "name": "", "image": ""})
        # 2) update with image in background
        def _encode_and_update():
            img_b64 = _crop_and_b64(frame, box, jpeg_quality=65, max_side=300)
            if img_b64:
                _emit_popup({"status": "success", "emp_id": user_id, "name": "", "image": img_b64})
        go_io(_encode_and_update)

    def _emit_denied_instant_then_update(self, frame, box):
        _emit_popup({"status": "denied", "emp_id": "", "name": "", "image": ""})
        def _encode_and_update():
            img_b64 = _crop_and_b64(frame, box, jpeg_quality=65, max_side=300)
            if img_b64:
                _emit_popup({"status": "denied", "emp_id": "", "name": "", "image": img_b64})
        go_io(_encode_and_update)

    def _parallel_success(self, user_id, frame, box):
        # POPUP first (instant), then effects, then image update
        self._emit_success_instant_then_update(user_id, frame, box)
        go_io(play_wav, AUDIO_PATH + "thank_you.wav")
        led_success_bg()
        go_io(print_user_id_and_cut, user_id)

    def _parallel_denied(self, frame, box):
        self._emit_denied_instant_then_update(frame, box)
        go_io(play_wav, AUDIO_PATH + "access_denied.wav")
        led_fail_bg()

    # -----------------------
    # Core API
    # -----------------------
    def recognize(self, frame):
        """
        Returns:
          - emp_id (str) on success (face present & verified)
          - '' (empty string) on present but NOT verified (ACCESS DENIED side-effects)
          - None when NO face detected / not encodable / index empty (DO NOTHING)
        """
        boxes = self.detect_faces(frame)

        # NO FACE -> DO NOTHING
        if len(boxes) == 0:
            return None

        # Pre-pick the primary face box once
        box = boxes[0]

        # Try encoding (CPU heavy); if fails, trigger denied
        face_encodings = face_recognition.face_encodings(frame, boxes)
        if len(face_encodings) == 0:
            self._parallel_denied(frame, box)
            return ""

        # If we don't have an index/encs, it's a denied
        if self.index is None or not self.encodings:
            self._parallel_denied(frame, box)
            return ""

        query = face_encodings[0].astype('float32')

        # Try FAISS (L2)
        try:
            D, I = self.index.search(np.expand_dims(query, 0), 1)
            if D[0][0] < 0.35 * 0.35:
                user_id = self.ids[I[0][0]]
                self._parallel_success(user_id, frame, box)
                return user_id
            else:
                self._parallel_denied(frame, box)
                return ""
        except Exception:
            # Vectorized CPU fallback (fast)
            encs = np.vstack([e.astype('float32') for e in self.encodings])
            diffs = encs - query
            dists = np.sqrt((diffs * diffs).sum(axis=1))
            if dists.size:
                min_idx = int(np.argmin(dists))
                if dists[min_idx] < 0.50:
                    user_id = self.ids[min_idx]
                    self._parallel_success(user_id, frame, box)
                    return user_id
            self._parallel_denied(frame, box)
            return ""

    def save_face(self, frame):
        boxes = self.detect_faces(frame)
        if len(boxes) == 0:
            return False, "No face detected."
        if len(boxes) != 1:
            self._parallel_denied(frame, boxes[0])
            return False, "Multiple faces detected."

        encoding = face_recognition.face_encodings(frame, boxes)
        if not encoding:
            self._parallel_denied(frame, boxes[0])
            return False, "Face could not be encoded."
        encoding_arr = encoding[0]
        return True, encoding_arr

    def find_duplicate(self, frame, tolerance=0.25):
        """
        Returns a dict with emp_id, name, image if this face is already registered.
        No LED/audio here.
        """
        boxes = self.detect_faces(frame)
        if len(boxes) != 1 or not self.encodings:
            return None
        encoding = face_recognition.face_encodings(frame, boxes)
        if not encoding:
            return None
        new_encoding = encoding[0].astype('float32')
        encs = np.vstack([e.astype('float32') for e in self.encodings])
        diffs = encs - new_encoding
        dists = np.sqrt((diffs * diffs).sum(axis=1))
        # quick check
        idx = int(np.argmin(dists))
        if dists[idx] < tolerance:
            emp_id = self.ids[idx]
            conn = sqlite3.connect(self.sql_path)
            c = conn.cursor()
            c.execute("SELECT name, display_image FROM users WHERE emp_id=?", (emp_id,))
            row = c.fetchone()
            conn.close()
            name = row[0] if row and row[0] else ""
            img_b64 = ""
            if row and row[1]:
                img_b64 = "data:image/jpeg;base64," + base64.b64encode(row[1]).decode()
            return {"emp_id": emp_id, "name": name, "image": img_b64}
        return None

    def update_user_encoding(self, frame, emp_id):
        boxes = self.detect_faces(frame)
        if len(boxes) != 1:
            if len(boxes) > 1:
                self._parallel_denied(frame, boxes[0])
            return False
        encoding = face_recognition.face_encodings(frame, boxes)
        if not encoding:
            self._parallel_denied(frame, boxes[0])
            return False
        encoding_bytes = encoding[0].astype(np.float64).tobytes()
        conn = sqlite3.connect(self.sql_path)
        c = conn.cursor()
        self._init_db()
        c.execute("UPDATE users SET face_encoding=? WHERE emp_id=?", (encoding_bytes, emp_id))
        conn.commit()
        result = c.rowcount
        conn.close()
        self.load_all_encodings()
        if result > 0:
            # Instant popup, then update with image + effects
            box = boxes[0]
            _emit_popup({"status": "success", "emp_id": emp_id, "name": "", "image": ""})
            def _encode_and_update_then_effects():
                img_b64 = _crop_and_b64(frame, box, jpeg_quality=65, max_side=300)
                if img_b64:
                    _emit_popup({"status": "success", "emp_id": emp_id, "name": "", "image": img_b64})
                play_wav(AUDIO_PATH + "thank_you.wav")
                led_success_bg()
                print_user_id_and_cut(emp_id)
            go_io(_encode_and_update_then_effects)
        else:
            self._parallel_denied(frame, boxes[0])
        return result > 0

    def delete_user(self, emp_id):
        conn = sqlite3.connect(self.sql_path)
        c = conn.cursor()
        self._init_db()
        c.execute("DELETE FROM users WHERE emp_id=?", (emp_id,))
        conn.commit()
        result = c.rowcount
        conn.close()
        self.load_all_encodings()
        if result > 0:
            _emit_popup({"status": "success", "emp_id": emp_id, "name": "", "image": ""})
            def _fx():
                play_wav(AUDIO_PATH + "success_deleted.wav")
                led_success_bg()
                print_user_id_and_cut(emp_id)
            go_io(_fx)
        else:
            self._parallel_denied(None, None)
        return result > 0
