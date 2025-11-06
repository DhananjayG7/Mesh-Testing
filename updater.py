#!/usr/bin/env python3
import os, json, hashlib, shutil, subprocess, zipfile, tempfile
from urllib.request import urlopen, Request
from pathlib import Path

# CONFIG
MANIFEST_URL = "https://raw.githubusercontent.com/DhananjayG7/BMS/main/manifest.json"
APP_DIR = Path("/home/admin/ethos-device")
VERSION_FILE = APP_DIR / "version.txt"
CURRENT_VERSION = VERSION_FILE.read_text().strip() if VERSION_FILE.exists() else "0.0.0"
TMP_DIR = APP_DIR / "tmp_update"
ZIP_PATH = TMP_DIR / "update.zip"

def version_tuple(v): return tuple(int(x) for x in v.split("."))

def get_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def run(cmd):
    print(f"[run] {' '.join(cmd)}")
    subprocess.run(cmd, check=False)

def main():
    print(f"Current version: {CURRENT_VERSION}")
    # Fetch manifest
    req = Request(MANIFEST_URL, headers={"User-Agent": "ethos-updater"})
    with urlopen(req, timeout=20) as r:
        manifest = json.loads(r.read().decode("utf-8"))

    latest_ver = manifest["version"]
    if version_tuple(latest_ver) <= version_tuple(CURRENT_VERSION):
        print(f"No update needed. Latest is {latest_ver}")
        return

    asset = manifest["asset"]
    url = asset["url"]
    sha = asset["sha256"]
    size = asset["size"]
    print(f"New version available: {latest_ver}")
    print(f"Downloading {url} ...")

    TMP_DIR.mkdir(exist_ok=True)
    with urlopen(Request(url, headers={"User-Agent": "ethos-updater"})) as r, open(ZIP_PATH, "wb") as f:
        shutil.copyfileobj(r, f)

    got_sha = get_sha256(ZIP_PATH)
    if got_sha.lower() != sha.lower():
        print("Checksum mismatch! Update aborted.")
        return

    print("Extracting update ...")
    new_dir = APP_DIR / f"update_{latest_ver}"
    if new_dir.exists():
        shutil.rmtree(new_dir)
    new_dir.mkdir()

    with zipfile.ZipFile(ZIP_PATH, "r") as z:
        z.extractall(new_dir)

    # Copy files to main app dir
    print("Installing update ...")
    for item in new_dir.iterdir():
        dest = APP_DIR / item.name
        if dest.is_dir():
            if dest.exists(): shutil.rmtree(dest)
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)

    (APP_DIR / "version.txt").write_text(latest_ver)
    print(f"Updated to version {latest_ver}")

    # Clean up
    shutil.rmtree(TMP_DIR, ignore_errors=True)
    shutil.rmtree(new_dir, ignore_errors=True)

    print("Restarting app...")
    run(["sudo", "systemctl", "restart", "ethos-device.service"])

if __name__ == "__main__":
    main()
