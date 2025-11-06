#!/usr/bin/env python3
import sys, importlib, subprocess, time, os, requests

FINGERPRINT_PORT = "/dev/ttyUSB0"
PRINTER_PORT = "/dev/serial0"    # UART0 on GPIO8 (TXD) and GPIO10 (RXD)
RFID_SPI_BUS = 1                 # SPI1
LED_SPI_BUS = 0                  # SPI0

# ----------------------
# MODULE PRESENCE CHECK
# ----------------------
def check_module(name):
    try:
        importlib.import_module(name)
        return True, f"Python module '{name}' found."
    except ImportError:
        return False, f"Python module '{name}' NOT found!"

# ----------------------
# CAMERA HEALTH CHECK
# ----------------------
def check_camera():
    """
    Do NOT open a new Picamera2 (conflicts with /video_feed).
    Instead, try hitting our own Flask /video_feed endpoint if server is up.
    If not running inside Flask, we just check that 'picamera2' is importable.
    """
    try:
        import picamera2  # confirm import
    except Exception as e:
        return False, f"Camera library missing: {e}"

    # If Flask app is running, query /video_feed (localhost:5000)
    try:
        r = requests.get("http://127.0.0.1:5000/video_feed", stream=True, timeout=3)
        if r.status_code == 200:
            return True, "Camera stream is active via /video_feed."
        else:
            return False, f"Camera endpoint returned {r.status_code}."
    except Exception:
        # Fallback: just confirm module loaded
        return True, "Picamera2 import OK, but live feed not reachable (Flask not running?)."

# ----------------------
# FINGERPRINT CHECK
# ----------------------
def check_fingerprint():
    try:
        from fingerprint import Fingerprint
        s = Fingerprint(FINGERPRINT_PORT, 9600)
        if s.init():
            s.close()
            return True, f"Fingerprint sensor detected on {FINGERPRINT_PORT}."
        else:
            return False, f"Fingerprint sensor NOT detected on {FINGERPRINT_PORT}."
    except Exception as e:
        return False, f"Fingerprint test failed: {e}"

# ----------------------
# RFID CHECK
# ----------------------
def check_rfid():
    try:
        import rfid
    except Exception as e:
        return False, f"RFID import failed: {e}"

    if hasattr(rfid, "rfid_read"):
        try:
            rfid.rfid_read(timeout=1)
            return True, "RFID module responsive (rfid_read() callable)."
        except TypeError:
            return True, "RFID module loaded; rfid_read() present (skipped)."
        except Exception as e:
            return False, f"RFID rfid_read() test failed: {e}"

    if hasattr(rfid, "get_rfid_reader"):
        try:
            rfid.get_rfid_reader()
            return True, "RFID driver initialized via get_rfid_reader()."
        except Exception as e:
            return False, f"RFID init via get_rfid_reader() failed: {e}"

    try:
        import spidev
        devnode = "/dev/spidev1.0"
        if not os.path.exists(devnode):
            return False, f"SPI1 device {devnode} not found."
        spi = spidev.SpiDev(); spi.open(RFID_SPI_BUS, 0); spi.close()
        return True, "SPI1 device present; basic SPI open OK."
    except Exception as e:
        return False, f"RFID SPI open failed: {e}"

# ----------------------
# LED CHECK
# ----------------------
def check_led():
    try:
        import spidev
        devnode = "/dev/spidev0.0"
        if not os.path.exists(devnode):
            return False, f"SPI0 device {devnode} not found."
        spi = spidev.SpiDev(); spi.open(LED_SPI_BUS, 0); spi.close()
        return True, "SPI0/MOSI interface present. (LED libs should work.)"
    except Exception as e:
        return False, f"LED SPI test failed: {e}"

# ----------------------
# PRINTER CHECK
# ----------------------
def check_printer():
    try:
        import serial
        ser = serial.Serial(PRINTER_PORT, 9600, timeout=1)
        ser.write(b"TEST\n"); ser.close()
        return True, "UART port opened, test data sent to printer."
    except Exception as e:
        return False, f"Printer test failed: {e}"

# ----------------------
# SPEAKER CHECK
# ----------------------
def check_speaker():
    try:
        subprocess.run(
            ["aplay", "/usr/share/sounds/alsa/Front_Center.wav"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True, "Audio output played test sound."
    except Exception as e:
        return False, f"Speaker test failed: {e}"

# ----------------------
# MAIN RUNNER
# ----------------------
def run_diagnostic(json_mode=False):
    results = []
    modules = [
        "picamera2", "RPi.GPIO", "flask", "numpy", "sqlite3",
        "spidev", "serial", "board", "busio", "neopixel_spi"
    ]
    for mod in modules:
        ok, msg = check_module(mod)
        results.append({"name": f"Python module: {mod}", "ok": ok, "info": msg})

    for func, name in [
        (check_camera, "Camera (via /video_feed)"),
        (check_fingerprint, "Fingerprint (USB-TTL)"),
        (check_rfid, "RFID (SPI1)"),
        (check_led, "LED Strip (SPI0)"),
        (check_printer, "Autocutter Printer (UART)"),
        (check_speaker, "AUX Speaker"),
    ]:
        ok, msg = func()
        results.append({"name": name, "ok": ok, "info": msg})

    if json_mode:
        return results

    print("==== ETHOS DEVICE DIAGNOSTIC ====")
    for res in results:
        icon = "✅" if res["ok"] else "❌"
        print(f"{icon} {res['name']}: {res['info']}")
    failures = [r for r in results if not r["ok"]]
    print("===============================")
    if not failures:
        print("ALL SYSTEMS GO.\n"); sys.exit(0)
    else:
        print(f"FAILED: {len(failures)} checks failed."); sys.exit(1)

if __name__ == "__main__":
    run_diagnostic()
