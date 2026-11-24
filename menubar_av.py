import os
import re
import sys
import time
import threading
import subprocess
import rumps
from AppKit import NSImage, NSFont, NSAttributedString, NSFontAttributeName

HOME = os.path.expanduser("~")
APP_DIR = os.path.join(HOME, ".kernel_av")
sys.path.append(APP_DIR)
import antivirus

PAUSE_FILE = os.path.join(HOME, ".kernel_paused")
REPORT_FILE = os.path.join(APP_DIR, "report.txt")

def get_sf_symbol(symbol_name):
    img = NSImage.imageWithSystemSymbolName_accessibilityDescription_(symbol_name, "Kernel Antivirus")
    if img:
        img.setTemplate_(True)
    return img

class KernelMenuBarApp(rumps.App):
    def __init__(self):
        super(KernelMenuBarApp, self).__init__("", quit_button="Quit Menu Bar")
        header_item = rumps.MenuItem("Kernel Antivirus", callback=lambda _: None)
        bold_font = NSFont.boldSystemFontOfSize_(13.0)
        attr_title = NSAttributedString.alloc().initWithString_attributes_("Kernel Antivirus", {NSFontAttributeName: bold_font})
        header_item._menuitem.setAttributedTitle_(attr_title)

        self.status_item = rumps.MenuItem("Engine: Checking...", callback=self.toggle_engine)
        self.stats_item = rumps.MenuItem("Scanned: 0 | Threats: 0 | Vault: 0", callback=self.open_detailed_report)

        self.menu = [
            header_item, None,
            self.status_item, self.stats_item, None,
            rumps.MenuItem("Scan a File...", callback=self.scan_file_picker),
            rumps.MenuItem("Run Full Folder Scan Now", callback=self.run_full_scan), None,
            rumps.MenuItem("View Live Logs", callback=self.open_logs),
            rumps.MenuItem("Open Quarantine Vault", callback=self.open_quarantine),
            rumps.MenuItem("Restart Background Engine", callback=self.restart_engine),
        ]
        self.refresh_status(None)

    def is_engine_running(self):
        res = subprocess.run(["launchctl", "list"], capture_output=True, text=True)
        return ("com.kernelav.engine" in res.stdout) and (not os.path.exists(PAUSE_FILE))

    def set_native_icon(self, symbol_name):
        img = get_sf_symbol(symbol_name)
        if img and hasattr(self, "_nsapp") and hasattr(self._nsapp, "nsstatusitem"):
            self._nsapp.nsstatusitem.button().setImage_(img)

    @rumps.timer(5)
    def refresh_status(self, _):
        running = self.is_engine_running()
        self.set_native_icon("lock.shield.fill" if running else "exclamationmark.shield.fill")
        self.status_item.title = "Engine: Active (Click to Stop)" if running else "Engine: Stopped (Click to Start)"
        st = antivirus.get_stats()
        total = st["clean"] + st["suspicious"] + st["malicious"]
        self.stats_item.title = f"Scanned: {total} | Threats: {st['malicious']} | Vault: {st['quarantined']}"

    def toggle_engine(self, _):
        if self.is_engine_running():
            open(PAUSE_FILE, "w").close()
            antivirus.log_message("ENGINE PAUSED: User paused real-time monitoring.")
            rumps.notification("Kernel Antivirus", "Engine Stopped", "Real-time download protection is paused.")
        else:
            if os.path.exists(PAUSE_FILE):
                os.remove(PAUSE_FILE)
            antivirus.log_message("ENGINE RESUMED: User resumed real-time monitoring.")
            rumps.notification("Kernel Antivirus", "Engine Started", "Real-time download protection is active.")
        self.refresh_status(None)

    def open_detailed_report(self, _):
        st = antivirus.get_stats()
        total = st["clean"] + st["suspicious"] + st["malicious"]
        rows = []
        if os.path.exists(antivirus.LOG_FILE):
            with open(antivirus.LOG_FILE, "r") as f:
                for line in f:
                    m = re.match(r"^\[(.*?)\]\s+(CLEAN|SUSPICIOUS|WARNING)\s+\((.*?)\):\s+(.*?)(?:\s+\|\s+Path:\s+(.*))?$", line.strip())
                    if m:
                        ts, status, source, detail, fpath = m.groups()
                        fname = detail.split(" — ")[0].split(" flagged by ")[0]
                        eng_match = re.search(r"(\d+/\d+)\s+engines", detail)
                        engines = eng_match.group(1) if eng_match else "0/?"
                        rows.append((ts, status, engines, fname, fpath or f"~/Downloads/{fname}"))

        vault_items = []
        if os.path.exists(antivirus.QUARANTINE_DIR):
            for f in sorted(os.listdir(antivirus.QUARANTINE_DIR)):
                if not f.startswith("."):
                    vault_items.append((f, os.path.join(antivirus.QUARANTINE_DIR, f)))

        with open(REPORT_FILE, "w") as out:
            out.write("=" * 112 + "\n")
            out.write("                                   KERNEL ANTIVIRUS — DETAILED SECURITY REPORT\n")
            out.write(f"                                       Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            out.write("=" * 112 + "\n\n")
            out.write(f"SUMMARY:  Total Scanned: {total}  |  Clean: {st['clean']}  |  Suspicious: {st['suspicious']}  |  Malicious: {st['malicious']}  |  Vault: {st['quarantined']}  |  Last Daily Scan: {st['last_scan']}\n\n")
            out.write("-" * 112 + "\nQUARANTINED VAULT ITEMS\n" + "-" * 112 + "\n")
            if vault_items:
                out.write(f"{'LOCKED FILENAME':<48} | {'VAULT PATH'}\n" + "-" * 112 + "\n")
                for vname, vpath in vault_items:
                    out.write(f"{vname:<48} | {vpath}\n")
            else:
                out.write("No files currently locked in quarantine.\n")
            out.write("\n" + "-" * 112 + "\nSCAN HISTORY (MOST RECENT FIRST)\n" + "-" * 112 + "\n")
            out.write(f"{'TIMESTAMP':<20} | {'STATUS':<10} | {'ENGINES':<8} | {'FILE NAME':<28} | {'FILE PATH'}\n" + "-" * 112 + "\n")
            for ts, status, engines, fname, path_str in reversed(rows):
                short_name = (fname[:25] + "...") if len(fname) > 28 else fname
                out.write(f"{ts:<20} | {status:<10} | {engines:<8} | {short_name:<28} | {path_str}\n")
        subprocess.run(["open", "-a", "TextEdit", REPORT_FILE])

    def scan_file_picker(self, _):
        script = 'POSIX path of (choose file with prompt "Select a file to scan with Kernel Antivirus:")'
        res = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
        file_path = res.stdout.strip()
        if file_path and os.path.exists(file_path):
            rumps.notification("Kernel Antivirus", "Scanning File...", os.path.basename(file_path))
            threading.Thread(target=antivirus.check_file_vt, args=(file_path,), kwargs={"allow_upload": True}, daemon=True).start()

    def run_full_scan(self, _):
        rumps.notification("Kernel Antivirus", "Full Folder Scan Started", "Scanning configured directories in background.")
        threading.Thread(target=antivirus.daily_scan, daemon=True).start()

    def open_logs(self, _):
        subprocess.run(["open", "-a", "Console", antivirus.LOG_FILE])

    def open_quarantine(self, _):
        os.makedirs(antivirus.QUARANTINE_DIR, exist_ok=True)
        subprocess.run(["open", antivirus.QUARANTINE_DIR])

    def restart_engine(self, _):
        if os.path.exists(PAUSE_FILE):
            os.remove(PAUSE_FILE)
        subprocess.run(["pkill", "-f", os.path.join(APP_DIR, "antivirus.py")])
        time.sleep(0.5)
        self.refresh_status(None)
        rumps.notification("Kernel Antivirus", "Engine Restarted", "Background monitor is active.")

if __name__ == "__main__":
    app = KernelMenuBarApp()
    rumps.Timer(lambda t: (app.refresh_status(None), t.stop()), 0.2).start()
    app.run()
