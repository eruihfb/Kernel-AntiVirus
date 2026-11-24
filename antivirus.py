import os
import json
import time
import shutil
import hashlib
import subprocess
import threading
from datetime import datetime, timedelta
import schedule
import vt
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

HOME = os.path.expanduser("~")
APP_DIR = os.path.join(HOME, ".kernel_av")
DOWNLOADS_DIR = os.path.join(HOME, "Downloads")
LOG_FILE = os.path.join(APP_DIR, "antivirus.log")
QUARANTINE_DIR = os.path.join(HOME, ".kernel_quarantine")
CONFIG_FILE = os.path.join(HOME, ".kernel_config.json")
PAUSE_FILE = os.path.join(HOME, ".kernel_paused")

DEFAULT_CONFIG = {
    "api_key": "",
    "restore_path": os.path.join(HOME, "Downloads"),
    "scan_dirs": [
        os.path.join(HOME, "Downloads"),
        os.path.join(HOME, "Desktop"),
        os.path.join(HOME, "Documents")
    ],
    "daily_scan_time": "12:00",
    "log_retention_days": 7,
    "upload_on_daily_scan": False,
    "whitelist": []
}

MAX_UPLOAD_BYTES = 32 * 1024 * 1024
LAST_ERROR_ALERT = 0
ERROR_COOLDOWN = 900

def load_config():
    os.makedirs(APP_DIR, exist_ok=True)
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
        for k, v in DEFAULT_CONFIG.items():
            data.setdefault(k, v)
        return data
    except Exception:
        return DEFAULT_CONFIG.copy()

def is_paused():
    return os.path.exists(PAUSE_FILE)

def is_whitelisted(file_path):
    cfg = load_config()
    abs_path = os.path.abspath(os.path.expanduser(file_path))
    for w in cfg.get("whitelist", []):
        w_abs = os.path.abspath(os.path.expanduser(w))
        if abs_path == w_abs or abs_path.startswith(w_abs + os.sep):
            return True
    return False

def get_stats():
    stats = {"clean": 0, "suspicious": 0, "malicious": 0, "quarantined": 0, "last_scan": "Never"}
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            for line in f:
                if "] CLEAN " in line:
                    stats["clean"] += 1
                elif "] SUSPICIOUS " in line:
                    stats["suspicious"] += 1
                elif "] WARNING " in line:
                    stats["malicious"] += 1
                elif "Daily Scan Complete" in line and line.startswith("["):
                    stats["last_scan"] = line[1:20]
    if os.path.exists(QUARANTINE_DIR):
        stats["quarantined"] = len([f for f in os.listdir(QUARANTINE_DIR) if not f.startswith(".")])
    return stats

def alert_error(error_detail):
    global LAST_ERROR_ALERT
    now = time.time()
    if now - LAST_ERROR_ALERT < ERROR_COOLDOWN:
        return
    LAST_ERROR_ALERT = now
    msg = (
        "Kernel Antivirus encountered an error. Check logs (kv logs) and run 'kv status' in Terminal to see when it returns online.\\n\\n"
        f"Details: {error_detail[:120]}"
    )
    safe_msg = msg.replace('"', '\\"')
    applescript = (
        f'tell application "Finder"\n'
        f'    activate\n'
        f'    display dialog "{safe_msg}" '
        f'with title "Kernel Antivirus — Error" '
        f'buttons {{"OK"}} '
        f'default button "OK" '
        f'with icon caution\n'
        f'end tell'
    )
    subprocess.run(["osascript", "-e", applescript], capture_output=True, text=True)

def log_message(message):
    os.makedirs(APP_DIR, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def cleanup_old_logs():
    cfg = load_config()
    retention_days = cfg.get("log_retention_days", 7)
    if retention_days <= 0 or not os.path.exists(LOG_FILE):
        return
    cutoff = datetime.now() - timedelta(days=retention_days)
    kept_lines = []
    removed_count = 0
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                if line.startswith("[") and len(line) >= 21:
                    try:
                        entry_time = datetime.strptime(line[1:20], "%Y-%m-%d %H:%M:%S")
                        if entry_time >= cutoff:
                            kept_lines.append(line)
                        else:
                            removed_count += 1
                        continue
                    except ValueError:
                        pass
                kept_lines.append(line)
        if removed_count > 0:
            with open(LOG_FILE, "w") as f:
                f.writelines(kept_lines)
            log_message(f"AUTO-CLEANUP: Removed {removed_count} log entries older than {retention_days} day(s).")
    except Exception as e:
        log_message(f"LOG CLEANUP ERROR: {e}")

def quarantine_file(file_path):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    filename = os.path.basename(file_path)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    dest_path = os.path.join(QUARANTINE_DIR, f"{timestamp}_{filename}.quarantined")
    shutil.move(file_path, dest_path)
    os.chmod(dest_path, 0o000)
    log_message(f"QUARANTINED: {file_path} -> {dest_path}")

def prompt_malware_action(file_path, malicious_count, total_engines, is_suspicious=False):
    filename = os.path.basename(file_path)
    safe_filename = filename.replace('"', '\\"')
    if is_suspicious:
        title = "Kernel Antivirus — Suspicious File Detected"
        icon_type = "caution"
        default_btn = "Quarantine"
        message = f"Kernel Antivirus flagged '{safe_filename}' as suspicious ({malicious_count}/{total_engines} engines — possible false positive).\\n\\nLocation: {file_path}"
    else:
        title = "Kernel Antivirus — Malicious File Detected"
        icon_type = "stop"
        default_btn = "Delete File"
        message = f"Kernel Antivirus flagged '{safe_filename}' as malicious ({malicious_count}/{total_engines} engines detected threats).\\n\\nLocation: {file_path}"
    applescript = (
        f'tell application "Finder"\n'
        f'    activate\n'
        f'    set userChoice to button returned of (display dialog "{message}" '
        f'with title "{title}" buttons {{"Leave It", "Quarantine", "Delete File"}} '
        f'default button "{default_btn}" with icon {icon_type})\n'
        f'    return userChoice\n'
        f'end tell'
    )
    result = subprocess.run(["osascript", "-e", applescript], capture_output=True, text=True)
    choice = result.stdout.strip()
    if choice == "Delete File":
        try:
            os.remove(file_path)
            log_message(f"DELETED: User chose to delete {file_path}")
        except Exception as e:
            log_message(f"ERROR DELETING {file_path}: {e}")
            alert_error(f"Failed to delete {filename}: {e}")
    elif choice == "Quarantine":
        try:
            quarantine_file(file_path)
        except Exception as e:
            log_message(f"ERROR QUARANTINING {file_path}: {e}")
            alert_error(f"Failed to quarantine {filename}: {e}")
    else:
        log_message(f"IGNORED: User chose to leave {file_path}")

def get_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError, IsADirectoryError):
        return None

def evaluate_results(file_path, stats, source_label):
    filename = os.path.basename(file_path)
    malicious = stats.get("malicious", 0)
    total_engines = sum(stats.values())
    if malicious >= 3:
        log_message(f"WARNING ({source_label}): {filename} flagged by {malicious}/{total_engines} engines. | Path: {file_path}")
        prompt_malware_action(file_path, malicious, total_engines, is_suspicious=False)
    elif malicious > 0:
        log_message(f"SUSPICIOUS ({source_label}): {filename} flagged by {malicious}/{total_engines} engines. | Path: {file_path}")
        prompt_malware_action(file_path, malicious, total_engines, is_suspicious=True)
    else:
        log_message(f"CLEAN ({source_label}): {filename} — 0/{total_engines} engines flagged this file. | Path: {file_path}")

def upload_and_scan_file(client, file_path):
    filename = os.path.basename(file_path)
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0 or file_size > MAX_UPLOAD_BYTES:
            return
        log_message(f"UPLOADING unknown file to Kernel Antivirus: {filename}...")
        with open(file_path, "rb") as f:
            analysis = client.scan_file(f, wait_for_completion=True)
        evaluate_results(file_path, analysis.stats, "Uploaded & Scanned")
    except Exception as e:
        log_message(f"UPLOAD ERROR for {filename}: {e}")
        alert_error(f"Upload failed for {filename}: {e}")

def check_file_vt(file_path, allow_upload=True):
    if is_paused():
        return
    filename = os.path.basename(file_path)
    if filename.startswith('.') or file_path.endswith(('.crdownload', '.part', '.tmp', '.download', '.quarantined')):
        return
    if is_whitelisted(file_path):
        return
    api_key = load_config().get("api_key", "").strip()
    if not api_key:
        log_message("ERROR: No API key configured. Run 'kv api_key <your_key>' in Terminal.")
        return
    file_hash = get_sha256(file_path)
    if not file_hash:
        return
    try:
        with vt.Client(api_key) as client:
            try:
                file_info = client.get_object(f"/files/{file_hash}")
                evaluate_results(file_path, file_info.last_analysis_stats, "Known Hash")
            except vt.APIError as e:
                if e.code == "NotFoundError":
                    if allow_upload:
                        upload_and_scan_file(client, file_path)
                else:
                    log_message(f"API ERROR for {filename}: {e}")
                    alert_error(f"API error on {filename}: {e}")
    except Exception as e:
        log_message(f"CONNECTION ERROR for {filename}: {e}")
        alert_error(f"Connection error on {filename}: {e}")

class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            time.sleep(3)
            check_file_vt(event.src_path, allow_upload=True)
    def on_moved(self, event):
        if not event.is_directory:
            check_file_vt(event.dest_path, allow_upload=True)

def daily_scan():
    if is_paused():
        return
    cleanup_old_logs()
    cfg = load_config()
    log_message("--- Starting Kernel Antivirus Daily Scan ---")
    files_checked = 0
    for folder in cfg.get("scan_dirs", DEFAULT_CONFIG["scan_dirs"]):
        expanded_folder = os.path.expanduser(folder)
        if not os.path.exists(expanded_folder):
            continue
        for root, dirs, files in os.walk(expanded_folder):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                if files_checked >= 400:
                    log_message("--- Kernel Antivirus Daily Scan Complete ---")
                    return
                check_file_vt(os.path.join(root, file), allow_upload=cfg.get("upload_on_daily_scan", False))
                files_checked += 1
                time.sleep(16)
    log_message(f"--- Kernel Antivirus Daily Scan Complete ({files_checked} files checked) ---")

def run_scheduler():
    cfg = load_config()
    schedule.every().day.at(cfg.get("daily_scan_time", "12:00")).do(daily_scan)
    schedule.every().day.at("00:00").do(cleanup_old_logs)
    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    cleanup_old_logs()
    cfg = load_config()
    log_message(f"Kernel Antivirus monitor started (Daily scan at {cfg.get('daily_scan_time')}).")
    threading.Thread(target=run_scheduler, daemon=True).start()
    observer = Observer()
    observer.schedule(DownloadHandler(), DOWNLOADS_DIR, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    except Exception as e:
        log_message(f"CRITICAL MONITOR ERROR: {e}")
        alert_error(f"Monitor crashed: {e}")
        observer.stop()
    observer.join()
