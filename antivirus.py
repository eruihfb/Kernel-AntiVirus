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

def get_network_context(error_detail=""):
    def run_cmd(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            return r.stdout.strip()
        except Exception:
            return ""

    iface = "en0"
    gateway = "Unknown"
    for line in run_cmd(["route", "-n", "get", "default"]).splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            iface = line.split(":", 1)[1].strip()
        elif line.startswith("gateway:"):
            gateway = line.split(":", 1)[1].strip()

    local_ip = run_cmd(["ipconfig", "getifaddr", iface]) or "No IP (Offline)"

    wifi_name = "Unknown / Wired"
    net_out = run_cmd(["networksetup", "-getairportnetwork", iface])
    if "Current Wi-Fi Network:" in net_out:
        wifi_name = net_out.split(":", 1)[1].strip()
    else:
        for line in run_cmd(["ipconfig", "getsummary", iface]).splitlines():
            if line.strip().startswith("SSID :"):
                wifi_name = line.split(":", 1)[1].strip()
                break
    if wifi_name in ("", "<redacted>"):
        wifi_name = "Hidden by macOS Location Privacy"

    dns_out = run_cmd(["networksetup", "-getdnsservers", "Wi-Fi"])
    if not dns_out or "aren't any DNS Servers" in dns_out:
        dns_servers = f"Auto ({gateway})"
    else:
        dns_servers = ", ".join(dns_out.splitlines()[:2])

    proxy_out = run_cmd(["scutil", "--proxy"])
    proxies = []
    if "HTTPEnable : 1" in proxy_out:
        proxies.append("HTTP")
    if "HTTPSEnable : 1" in proxy_out:
        proxies.append("HTTPS")
    if "ProxyAutoConfigEnable : 1" in proxy_out:
        proxies.append("PAC Auto-Proxy")
    proxy_status = ", ".join(proxies) if proxies else "None"

    err = error_detail.lower()
    if "sslcertverificationerror" in err or "certificate_verify_failed" in err:
        cause = "School/public Wi-Fi HTTPS inspection or firewall intercepting SSL"
    elif "401" in err or "wrong api key" in err or "authentication" in err:
        cause = "Invalid or missing VirusTotal API key (run 'kv api_key <key>')"
    elif "429" in err or "quota" in err:
        cause = "VirusTotal free API rate limit reached (4/min or 500/day)"
    elif "nameresolutionerror" in err or "nodename nor servname" in err or local_ip.startswith("No IP"):
        cause = "Offline, DNS blocked, or Wi-Fi captive portal login needed"
    else:
        cause = "Firewall blocking virustotal.com, captive portal, or unstable Wi-Fi"

    return {
        "wifi": wifi_name,
        "iface": iface,
        "ip": local_ip,
        "gateway": gateway,
        "dns": dns_servers,
        "proxy": proxy_status,
        "cause": cause,
    }


def alert_error(error_detail):
    global LAST_ERROR_ALERT
    net = get_network_context(error_detail)
    log_message(
        f"NETWORK INFO: Wi-Fi={net['wifi']} ({net['iface']}) | IP={net['ip']} | "
        f"Router={net['gateway']} | DNS={net['dns']} | Proxy={net['proxy']} | Cause={net['cause']}"
    )
    now = time.time()
    if now - LAST_ERROR_ALERT < ERROR_COOLDOWN:
        return
    LAST_ERROR_ALERT = now
    msg = (
        f"Kernel Antivirus could not complete a scan.\n\n"
        f"Error: {error_detail[:110]}\n\n"
        f"Connection Details:\n"
        f"• Wi-Fi: {net['wifi']} ({net['iface']})\n"
        f"• Local IP: {net['ip']} (Router: {net['gateway']})\n"
        f"• DNS: {net['dns']} | Proxy: {net['proxy']}\n"
        f"• Likely Cause: {net['cause']}"
    )
    safe_msg = msg.replace('"', '\\"')
    applescript = (
        f'tell application "Finder"\n'
        f'    activate\n'
        f'    display dialog "{safe_msg}" '
        f'with title "Kernel Antivirus - Error" '
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

def _get_running_binaries():
    try:
        res = subprocess.run(["ps", "-axo", "pid=,pcpu=,rss=,comm="], capture_output=True, text=True, timeout=5)
    except Exception:
        return []
    procs = []
    for line in res.stdout.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 4:
            continue
        try:
            pid = int(parts[0])
            cpu = float(parts[1])
            ram_mb = round(int(parts[2]) / 1024.0, 1)
            exe = parts[3].strip()
        except ValueError:
            continue
        real_exe = os.path.realpath(exe) if os.path.exists(exe) else exe
        procs.append({
            "pid": pid,
            "cpu": cpu,
            "ram_mb": ram_mb,
            "name": os.path.basename(exe),
            "path": real_exe,
        })
    return procs


def inspect_processes(print_report=True):
    cfg = load_config()
    max_ram = float(cfg.get("max_ram_mb", 2048))
    max_cpu = float(cfg.get("max_cpu_percent", 90.0))
    whitelist = set(cfg.get("whitelist", []))
    procs = _get_running_binaries()

    high_res = [p for p in procs if (p["ram_mb"] >= max_ram or p["cpu"] >= max_cpu) and p["path"] not in whitelist]
    suspicious_locs = []
    seen_paths = set()

    for p in procs:
        path = p["path"]
        if path in seen_paths or path in whitelist or not os.path.isfile(path):
            continue
        seen_paths.add(path)
        if path.startswith(("/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/sbin/")):
            continue
        risky_dir = path.startswith(("/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/")) or "/." in path
        sig = subprocess.run(["codesign", "-v", path], capture_output=True, text=True)
        unsigned = sig.returncode != 0
        if risky_dir or unsigned:
            reason = []
            if risky_dir:
                reason.append("high-risk path")
            if unsigned:
                reason.append("unsigned binary")
            suspicious_locs.append((p, ", ".join(reason)))

    if print_report:
        top_ram = sorted(procs, key=lambda x: x["ram_mb"], reverse=True)[:8]
        print("📊 Top Running Processes by RAM:")
        for p in top_ram:
            flag = " ⚠️ HIGH" if (p["ram_mb"] >= max_ram or p["cpu"] >= max_cpu) else ""
            print(f"  PID {p['pid']:<6} | RAM: {p['ram_mb']:>7.1f} MB | CPU: {p['cpu']:>5.1f}% | {p['name']}{flag}")
        if high_res:
            print(f"\n🔥 Resource Alerts (> {max_ram:.0f} MB RAM or > {max_cpu:.0f}% CPU): {len(high_res)} process(es)")
        else:
            print(f"\n✅ No processes exceeding {max_ram:.0f} MB RAM or {max_cpu:.0f}% CPU.")
        if suspicious_locs:
            print("\n🕵️  Unsigned or High-Risk Location Processes:")
            for p, why in suspicious_locs:
                print(f"  PID {p['pid']:<6} | {p['name']} ({why}) -> {p['path']}")
        else:
            print("✅ No unsigned or suspicious-path processes running.")

    for p in high_res:
        log_message(f"HIGH RESOURCE PROCESS: {p['name']} (PID {p['pid']}) using {p['ram_mb']} MB RAM, {p['cpu']}% CPU | {p['path']}")
    return procs, high_res, suspicious_locs


def scan_running_processes(interactive=True):
    cfg = load_config()
    api_key = cfg.get("api_key", "").strip()
    if not api_key:
        log_message("ERROR: No API key configured. Run 'kv api_key <your_key>' in Terminal.")
        return
    whitelist = set(cfg.get("whitelist", []))
    procs, _, _ = inspect_processes(print_report=interactive)

    unique_bins = {}
    for p in procs:
        path = p["path"]
        if path in whitelist or not os.path.isfile(path):
            continue
        if path.startswith(("/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/sbin/")):
            continue
        if path not in unique_bins or p["ram_mb"] > unique_bins[path]["ram_mb"]:
            unique_bins[path] = p

    cache_path = os.path.expanduser("~/.kernel_av/proc_hash_cache.json")
    try:
        cache = json.load(open(cache_path)) if os.path.exists(cache_path) else {}
    except Exception:
        cache = {}

    to_check = []
    for path, p in unique_bins.items():
        try:
            st = os.stat(path)
            sig_key = f"{st.st_mtime}:{st.st_size}"
            if cache.get(path) == sig_key:
                continue
            file_hash = get_file_hash(path)
            if file_hash:
                to_check.append((path, p, file_hash, sig_key))
        except Exception:
            continue

    if interactive:
        print(f"\n🔍 Scanning {len(to_check)} uncached third-party process binaries on VirusTotal ({len(unique_bins) - len(to_check)} cached clean)...")

    threats = 0
    try:
        with vt.Client(api_key) as client:
            for path, p, file_hash, sig_key in to_check:
                try:
                    obj = client.get_object(f"/files/{file_hash}")
                    stats = obj.last_analysis_stats
                    mal = stats.get("malicious", 0)
                    sus = stats.get("suspicious", 0)
                    total = sum(stats.values())
                    if mal > 0 or sus > 2:
                        threats += 1
                        log_message(f"THREAT RUNNING: {p['name']} (PID {p['pid']}, {p['ram_mb']} MB RAM) flagged {mal}/{total} | {path}")
                        if interactive:
                            print(f"🚨 THREAT: PID {p['pid']} ({p['name']}) flagged by {mal}/{total} engines! Path: {path}")
                        alert_malicious_process(p, mal, total)
                    else:
                        cache[path] = sig_key
                except vt.APIError as e:
                    if "NotFoundError" in str(e):
                        cache[path] = sig_key
                    elif "QuotaExceededError" in str(e) or "429" in str(e):
                        time.sleep(16)
                    else:
                        log_message(f"PROCESS SCAN API ERROR ({p['name']}): {e}")
    except Exception as e:
        log_message(f"PROCESS SCAN CONNECTION ERROR: {e}")
        alert_error(str(e))

    try:
        json.dump(cache, open(cache_path, "w"), indent=2)
    except Exception:
        pass

    if interactive:
        print(f"✅ Process scan complete. Active threats found: {threats}")


def alert_malicious_process(proc, mal, total):
    msg = (
        f"Malicious active process detected!\\n\\n"
        f"Process: {proc['name']} (PID {proc['pid']})\\n"
        f"Usage: {proc['ram_mb']} MB RAM | {proc['cpu']}% CPU\\n"
        f"Detections: {mal}/{total} engines\\n"
        f"Path: {proc['path']}\\n\\n"
        f"Kill the process and quarantine its executable?"
    )
    safe_msg = msg.replace('"', '\\"')
    applescript = (
        f'tell application "Finder"\n'
        f'    activate\n'
        f'    set r to display dialog "{safe_msg}" '
        f'with title "Kernel Antivirus - Active Threat" '
        f'buttons {{"Ignore", "Kill & Quarantine"}} '
        f'default button "Kill & Quarantine" '
        f'with icon stop\n'
        f'    return button returned of r\n'
        f'end tell'
    )
    res = subprocess.run(["osascript", "-e", applescript], capture_output=True, text=True)
    if "Kill & Quarantine" in res.stdout:
        try:
            os.kill(proc["pid"], 9)
            log_message(f"KILLED PROCESS: PID {proc['pid']} ({proc['name']})")
        except Exception as e:
            log_message(f"FAILED TO KILL PID {proc['pid']}: {e}")
        if os.path.exists(proc["path"]):
            quarantine_file(proc["path"])


def daily_scan():
    scan_running_processes(interactive=False)
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
