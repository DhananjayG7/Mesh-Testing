# fingerprint.py — non-blocking side-effects for instant popup (with audio pack)

import os
import time
import serial
import subprocess
from concurrent.futures import ThreadPoolExecutor

# =========================
# --- AUDIO / PRINTER -----
# =========================
# Adjust if your audio lives elsewhere
AUDIO_PATH = "/home/admin/ethos-device/static/audio/"
PRINTER_PORT = "/dev/serial0"
PRINTER_BAUDRATE = 9600

# Known audio cues used around the app
AUDIO_FILES = {
    "thank_you":               "thank_you.wav",
    "access_denied":           "access_denied.wav",
    "success_registered":      "Successfully_Registered.wav",
    "success_deleted":         "success_deleted.wav",
}

# Track missing files so we only log once per filename
_missing_once = set()

def _audio_abspath(name_or_path: str) -> str:
    """Return absolute path for a cue name or direct filename/path."""
    # If they passed a full/relative path already, honor it
    if os.path.sep in name_or_path or name_or_path.lower().endswith(".wav"):
        p = name_or_path
        if not os.path.isabs(p):
            p = os.path.join(AUDIO_PATH, p)
        return p
    # If they passed a logical cue key, map to filename
    fname = AUDIO_FILES.get(name_or_path, name_or_path)
    return os.path.join(AUDIO_PATH, fname)

def _audio_exists(path: str) -> bool:
    if os.path.exists(path):
        return True
    if path not in _missing_once:
        _missing_once.add(path)
        print(f"[AUDIO] missing: {path} (skipping playback)")
    return False

# small de-dupe so the same wav isn't spammed twice quickly
_last_play = {}

# Background IO pool for LED/audio/printer so API can return immediately
io_exec = ThreadPoolExecutor(max_workers=4, thread_name_prefix="fp-io")

def go_io(fn, *args, **kwargs):
    try:
        io_exec.submit(fn, *args, **kwargs)
    except Exception:
        pass

def play_wav(file_or_key, min_interval=0.60):
    """
    Fire-and-forget WAV playback with basic de-dupe throttle and graceful fallback.
    Accepts:
      - logical key (e.g., 'thank_you', 'access_denied', 'success_registered', 'success_deleted')
      - filename (e.g., 'thank_you.wav')
      - absolute path
    """
    try:
        path = _audio_abspath(str(file_or_key))
        if not _audio_exists(path):
            return
        now = time.time()
        last = _last_play.get(path, 0)
        if now - last < float(min_interval):
            return
        _last_play[path] = now
        # Use aplay quietly; won't block the API path
        subprocess.Popen(["aplay", "-q", path])
    except Exception as e:
        print(f"[AUDIO] error: {e}")

def print_user_id_and_cut(user_id):
    """Print a small line with the user ID and issue a full cut."""
    GS = b"\x1d"
    CUT_FULL = GS + b"V\x00"
    try:
        with serial.Serial(PRINTER_PORT, PRINTER_BAUDRATE, timeout=2) as printer:
            printer.write(b"\n\n")
            printer.write(f"User ID: {user_id}\n".encode())
            printer.write(b"\n\n")
            printer.write(CUT_FULL)
            printer.flush()
    except Exception as e:
        print(f"[PRINTER] error: {e}")

# =========================
# --------- LED -----------
# =========================
_led_available = False
_pixels = None

def _init_led():
    global _led_available, _pixels
    try:
        import board
        import busio
        import neopixel_spi as neopixel
        NUM_PIXELS = 4
        LED_SPI = busio.SPI(board.SCK, MOSI=board.MOSI)  # SPI0
        _pixels = neopixel.NeoPixel_SPI(
            LED_SPI, NUM_PIXELS, auto_write=True, pixel_order=neopixel.GRB
        )
        _pixels.brightness = 1.0
        _led_available = True
    except Exception as e:
        _led_available = False
        _pixels = None
        print(f"[LED] init skipped: {e}")

_init_led()

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
    """Blocking blink; call via go_io to avoid blocking API."""
    if not _led_available:
        return
    try:
        _led_fill(color)
        time.sleep(float(duration))
    finally:
        _led_off()

def led_success_bg():
    go_io(led_blink, (0, 255, 0), 0.35)   # quick green

def led_fail_bg():
    go_io(led_blink, (255, 0, 0), 0.55)   # quick red

# =========================
# ---- Fingerprint I/O ----
# =========================
class Fingerprint:
    """
    GT-521Fxx UART protocol minimal driver.
    - identify():
        * returns user_id (int) on recognized (schedules thank_you/LED/printer in background)
        * returns -1 on present but not recognized (schedules access_denied/LED red)
        * returns None on no finger / capture fail / timeouts (silent)
    """
    COMMANDS = {
        'Open': 0x01, 'Close': 0x02, 'CmosLed': 0x12,
        'GetEnrollCount': 0x20, 'CheckEnrolled': 0x21,
        'EnrollStart': 0x22, 'Enroll1': 0x23, 'Enroll2': 0x24, 'Enroll3': 0x25,
        'IsPressFinger': 0x26, 'CaptureFinger': 0x60,
        'DeleteID': 0x40, 'DeleteAll': 0x41,
        'Verify1_1': 0x50, 'Identify1_N': 0x51,
        'GetTemplate': 0x70, 'SetTemplate': 0x71,
        'Ack': 0x30, 'Nack': 0x31
    }
    PKT_RES = (0x55, 0xAA)
    PKT_DATA = (0x5A, 0xA5)

    def __init__(self, port, baud=9600, timeout=2):
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self.ser = None

    # ---------- Serial helpers ----------
    def _ensure_open(self):
        if self.ser is None or not self.ser.is_open:
            self._open_serial()

    def _open_serial(self):
        try:
            if self.ser and self.ser.is_open:
                self.ser.close()
            self.ser = serial.Serial(self.port, self.baud, timeout=self.timeout, write_timeout=self.timeout)
            time.sleep(0.5)
        except Exception as e:
            print(f"[FP] serial open error: {e}")
            self.ser = None
            raise

    def init(self):
        """Quick sanity to see if sensor responds to Open/Close."""
        try:
            self._open_serial()
            self.open()
            self._flush()
            self.close()
            return True
        except Exception as e:
            print(f"[FP] init failed: {e}")
            self.force_reset()
            return False

    def _send_packet(self, cmd, param=0):
        try:
            self._ensure_open()
            code = self.COMMANDS[cmd]
            p = [(param >> (8 * i)) & 0xFF for i in range(4)]
            pkt = bytearray(12)
            pkt[0:2] = b'\x55\xAA'
            pkt[2:4] = b'\x01\x00'
            pkt[4:8] = bytes(p)
            pkt[8] = code & 0xFF
            pkt[9] = (code >> 8) & 0xFF
            chk = sum(pkt[:10])
            pkt[10] = chk & 0xFF
            pkt[11] = (chk >> 8) & 0xFF
            if self.ser and self.ser.writable():
                self.ser.write(pkt)
                return True
        except Exception as e:
            print(f"[FP] send error: {e}")
            self.force_reset()
        return False

    def _read(self):
        try:
            b = self.ser.read(1)
            if not b:
                raise TimeoutError("read timeout")
            return b[0]
        except Exception as e:
            print(f"[FP] read byte error: {e}")
            self.force_reset()
            return None

    def _read_header(self):
        return self._read(), self._read()

    def _read_packet(self):
        try:
            # find response header
            while True:
                h1, h2 = self._read_header()
                if h1 is None or h2 is None:
                    raise TimeoutError("timeout reading header")
                if (h1, h2) == self.PKT_RES:
                    break
            body = self.ser.read(10)
            if len(body) < 10:
                raise TimeoutError("timeout reading body")
            pkt = bytes([h1, h2]) + body
            ack = (pkt[8] == self.COMMANDS['Ack'])
            param = int.from_bytes(pkt[4:8], 'little')
            res = int.from_bytes(pkt[8:10], 'little')
            data = None
            # optional data packet
            if self.ser.in_waiting >= 2:
                d1, d2 = self._read_header()
                if (d1, d2) == self.PKT_DATA:
                    length_bytes = self.ser.read(2)
                    if len(length_bytes) < 2:
                        return ack, param, res, None
                    length = int.from_bytes(length_bytes, 'little')
                    data = self.ser.read(length)
            return ack, param, res, data
        except Exception as e:
            print(f"[FP] read packet error: {e}")
            self.force_reset()
            return None, None, None, None

    def _flush(self):
        if not self.ser:
            return
        try:
            while self.ser.in_waiting:
                self.ser.read(self.ser.in_waiting)
        except Exception:
            self.force_reset()

    def _send_and_ack(self, cmd, param=0):
        if self._send_packet(cmd, param):
            ack, _, _, _ = self._read_packet()
            return ack
        return False

    # ---------- High-level commands ----------
    def open(self):
        try:
            ok = self._send_and_ack('Open')
            if ok:
                self._flush()
            return ok
        except Exception:
            self.force_reset()
            return False

    def close(self):
        try:
            return self._send_and_ack('Close')
        except Exception:
            self.force_reset()
            return False

    def set_led(self, on):
        try:
            return self._send_and_ack('CmosLed', 1 if on else 0)
        except Exception:
            self.force_reset()
            return False

    # ---------- Enroll sequence ----------
    def start_enroll(self, idx, side_effects=True):
        try:
            ack = self._send_and_ack('EnrollStart', int(idx))
            if side_effects:
                if ack:
                    play_wav("success_registered")
                    go_io(print_user_id_and_cut, idx)
                    led_success_bg()
                else:
                    play_wav("access_denied")
                    led_fail_bg()
            return ack
        except Exception:
            if side_effects:
                play_wav("access_denied")
                led_fail_bg()
            self.force_reset()
            return False

    def enroll1(self, side_effects=True):
        try:
            ack = self._send_and_ack('Enroll1')
            if side_effects:
                play_wav("success_registered" if ack else "access_denied")
                (led_success_bg() if ack else led_fail_bg())
            return ack
        except Exception:
            if side_effects:
                play_wav("access_denied")
                led_fail_bg()
            self.force_reset()
            return False

    def enroll2(self, side_effects=True):
        try:
            ack = self._send_and_ack('Enroll2')
            if side_effects:
                play_wav("success_registered" if ack else "access_denied")
                (led_success_bg() if ack else led_fail_bg())
            return ack
        except Exception:
            if side_effects:
                play_wav("access_denied")
                led_fail_bg()
            self.force_reset()
            return False

    def enroll3(self, side_effects=True):
        try:
            ack = self._send_and_ack('Enroll3')
            if side_effects:
                play_wav("success_registered" if ack else "access_denied")
                (led_success_bg() if ack else led_fail_bg())
            return ack
        except Exception:
            if side_effects:
                play_wav("access_denied")
                led_fail_bg()
            self.force_reset()
            return False

    # ---------- Capture / Identify ----------
    def capture_finger(self, best=False):
        """
        Capture a finger image. Returns True on success.
        **Silent**: no audio/LED on success or failure (prevents double sounds).
        """
        try:
            self.set_led(True)
            if self._send_packet('CaptureFinger', 1 if best else 0):
                ack, _, _, _ = self._read_packet()
                self.set_led(False)
                return bool(ack)
            self.set_led(False)
        except Exception:
            self.set_led(False)
            self.force_reset()
        return False

    def identify(self, side_effects=True):
        """
        Identify finger against DB in sensor.

        Returns:
        - user_id (int) on success (present + verified)  -> schedules thank_you.wav, green LED, printer
        - -1 on present but NOT verified                 -> schedules access_denied.wav, red LED
        - None if no finger / capture failed / timeouts  -> silent
        """
        try:
            captured = self.capture_finger()
            if not captured:
                return None  # silent

            if self._send_packet('Identify1_N'):
                ack, p, _, _ = self._read_packet()
                if ack and p != -1:
                    if side_effects:
                        led_success_bg()
                        play_wav("thank_you")
                        go_io(print_user_id_and_cut, p)
                    return p
                else:
                    if side_effects:
                        led_fail_bg()
                        play_wav("access_denied")
                    return -1

            return None

        except Exception as e:
            msg = str(e).lower()
            if "timeout" in msg or "read timeout" in msg:
                self.force_reset()
                return None
            if side_effects:
                led_fail_bg()
                play_wav("access_denied")
            self.force_reset()
            return -1

    # ---------- Delete / Template ----------
    def delete(self, idx=None, side_effects=True):
        """
        Delete one template (idx) or ALL if idx is None.
        Returns True on success.
        """
        try:
            if idx is None:
                self._send_packet('DeleteAll')
            else:
                self._send_packet('DeleteID', int(idx))
            ack, _, _, _ = self._read_packet()
            if side_effects:
                if ack:
                    led_success_bg()
                    play_wav("success_deleted")
                else:
                    led_fail_bg()
                    play_wav("access_denied")
            return bool(ack)
        except Exception:
            if side_effects:
                led_fail_bg()
                play_wav("access_denied")
            self.force_reset()
            return False

    def delete_all_fingers(self, side_effects=True):
        """Convenience wrapper to wipe the sensor’s database."""
        return self.delete(idx=None, side_effects=side_effects)

    def get_template(self, idx):
        try:
            if not self._send_packet('GetTemplate', int(idx)):
                return None
            ack, _, _, _ = self._read_packet()
            if not ack:
                return None
            h1, h2 = self._read_header()
            if (h1, h2) != self.PKT_DATA:
                return None
            length_bytes = self.ser.read(2)
            if not length_bytes or len(length_bytes) < 2:
                return None
            length = int.from_bytes(length_bytes, 'little')
            return self.ser.read(length)
        except Exception:
            self.force_reset()
            return None

    # ---------- Recovery ----------
    def force_reset(self):
        """Close and reopen the serial port after a short pause."""
        try:
            if self.ser and self.ser.is_open:
                self.ser.close()
        except Exception:
            pass
        self.ser = None
        time.sleep(0.5)
        try:
            self._open_serial()
        except Exception:
            pass
