#!/bin/bash
set -e

APP_DIR="$HOME/.kernel_av"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "🛡️  Installing Kernel Antivirus..."
mkdir -p "$APP_DIR"
cp "$SCRIPT_DIR/antivirus.py" "$APP_DIR/antivirus.py"
cp "$SCRIPT_DIR/menubar_av.py" "$APP_DIR/menubar_av.py"
cp "$SCRIPT_DIR/uninstall.sh" "$APP_DIR/uninstall.sh"
chmod +x "$APP_DIR/uninstall.sh"

if [ ! -d "$APP_DIR/venv" ]; then
    echo "📦 Creating isolated Python environment..."
    python3 -m venv "$APP_DIR/venv"
fi

echo "⬇️  Installing dependencies..."
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"

echo ""
read -p "🔑 Paste your VirusTotal API key (or press Enter to set it later via 'kv api_key'): " USER_KEY

"$APP_DIR/venv/bin/python3" -c "
import sys, json, plistlib, os
sys.path.append('$APP_DIR')
import antivirus

cfg = antivirus.load_config()
if '$USER_KEY'.strip():
    cfg['api_key'] = '$USER_KEY'.strip()
json.dump(cfg, open(antivirus.CONFIG_FILE, 'w'), indent=4)

agents_dir = os.path.expanduser('~/Library/LaunchAgents')
os.makedirs(agents_dir, exist_ok=True)
py_bin = os.path.join('$APP_DIR', 'venv', 'bin', 'python3')

with open(os.path.join(agents_dir, 'com.kernelav.engine.plist'), 'wb') as f:
    plistlib.dump({
        'Label': 'com.kernelav.engine',
        'ProgramArguments': [py_bin, os.path.join('$APP_DIR', 'antivirus.py')],
        'RunAtLoad': True,
        'KeepAlive': True,
    }, f)

with open(os.path.join(agents_dir, 'com.kernelav.menubar.plist'), 'wb') as f:
    plistlib.dump({
        'Label': 'com.kernelav.menubar',
        'ProgramArguments': [py_bin, os.path.join('$APP_DIR', 'menubar_av.py')],
        'LimitLoadToSessionType': 'Aqua',
        'RunAtLoad': True,
        'KeepAlive': True,
    }, f)
"

launchctl unload ~/Library/LaunchAgents/com.kernelav.engine.plist 2>/dev/null || true
launchctl load ~/Library/LaunchAgents/com.kernelav.engine.plist
launchctl unload ~/Library/LaunchAgents/com.kernelav.menubar.plist 2>/dev/null || true
launchctl load ~/Library/LaunchAgents/com.kernelav.menubar.plist

if ! grep -q "# --- Kernel Antivirus CLI Shortcuts ---" ~/.zshrc 2>/dev/null; then
cat << 'ZSH' >> ~/.zshrc

# --- Kernel Antivirus CLI Shortcuts ---
kv() {
    PY="$HOME/.kernel_av/venv/bin/python3"
    APP="$HOME/.kernel_av"
    CFG="$HOME/.kernel_config.json"

    case "$1" in
        status)
            if [ -f "$HOME/.kernel_paused" ]; then echo "⏸️  Kernel Antivirus is PAUSED."
            elif launchctl list | grep -q "com.kernelav.engine"; then echo "✅ Kernel Antivirus is RUNNING."
            else echo "❌ Kernel Antivirus is STOPPED."; fi ;;
        api_key)
            [ -z "$2" ] && echo "Usage: kv api_key <key>" || ($PY -c "import sys, json; sys.path.insert(0, '$APP'); import antivirus; cfg=antivirus.load_config(); cfg['api_key']='$2'; json.dump(cfg, open('$CFG','w'), indent=4)" && echo "✅ API key updated.") ;;
        stats)
            $PY -c "import sys; sys.path.insert(0, '$APP'); import antivirus; st=antivirus.get_stats(); print(f'📊 Scanned: {st[\"clean\"]+st[\"suspicious\"]+st[\"malicious\"]} | Clean: {st[\"clean\"]} | Suspicious: {st[\"suspicious\"]} | Malicious: {st[\"malicious\"]} | Vault: {st[\"quarantined\"]} | Last Scan: {st[\"last_scan\"]}')" ;;
        whitelist)
            [ -z "$2" ] && echo "Usage: kv whitelist <path>" || $PY -c "import sys, os, json; sys.path.insert(0, '$APP'); import antivirus; cfg=antivirus.load_config(); p=os.path.abspath(os.path.expanduser('$2')); wl=cfg.get('whitelist',[]); wl.append(p) if p not in wl else None; cfg['whitelist']=wl; json.dump(cfg, open('$CFG','w'), indent=4); print('✅ Whitelisted:', p)" ;;
        unwhitelist)
            [ -z "$2" ] && echo "Usage: kv unwhitelist <path>" || $PY -c "import sys, os, json; sys.path.insert(0, '$APP'); import antivirus; cfg=antivirus.load_config(); p=os.path.abspath(os.path.expanduser('$2')); cfg['whitelist']=[x for x in cfg.get('whitelist',[]) if x != p]; json.dump(cfg, open('$CFG','w'), indent=4); print('🗑️  Removed:', p)" ;;
        config)
            $PY -c "import sys, json; sys.path.insert(0, '$APP'); import antivirus; c=antivirus.load_config(); c['api_key']='***HIDDEN***' if c.get('api_key') else ''; print(json.dumps(c, indent=4))" ;;
        restore_path)
            [ -z "$2" ] && echo "Usage: kv restore_path <dir>" || (TD="${2/#\~/$HOME}"; mkdir -p "$TD"; $PY -c "import sys, json; sys.path.insert(0, '$APP'); import antivirus; cfg=antivirus.load_config(); cfg['restore_path']='$TD'; json.dump(cfg, open('$CFG','w'), indent=4)"; echo "✅ Restore path: $TD") ;;
        autoscan_folders)
            [ -z "$2" ] && echo "Usage: kv autoscan_folders <d1,d2>" || $PY -c "import sys, os, json; sys.path.insert(0, '$APP'); import antivirus; cfg=antivirus.load_config(); cfg['scan_dirs']=[os.path.abspath(os.path.expanduser(p.strip())) for p in '$2'.split(',') if p.strip()]; json.dump(cfg, open('$CFG','w'), indent=4); print('✅ Updated scan_dirs')" ;;
        scan_time)
            [ -z "$2" ] && echo "Usage: kv scan_time <HH:MM>" || ($PY -c "import sys, json; sys.path.insert(0, '$APP'); import antivirus; cfg=antivirus.load_config(); cfg['daily_scan_time']='$2'; json.dump(cfg, open('$CFG','w'), indent=4)" && pkill -f "$APP/antivirus.py" 2>/dev/null || true && echo "✅ Daily scan time: $2") ;;
        log_autodelete)
            [ -z "$2" ] && echo "Usage: kv log_autodelete <days>" || ($PY -c "import sys, json; sys.path.insert(0, '$APP'); import antivirus; cfg=antivirus.load_config(); cfg['log_retention_days']=int('$2'); json.dump(cfg, open('$CFG','w'), indent=4); antivirus.cleanup_old_logs()" && echo "✅ Log retention: $2 day(s)") ;;
        clear_logs) > "$APP/antivirus.log" && echo "🧹 Logs cleared." ;;
        procs)
            $PY -c "import sys; sys.path.insert(0, '$APP'); import antivirus; antivirus.inspect_processes(print_report=True)" ;;
        scan_procs)
            $PY -c "import sys; sys.path.insert(0, '$APP'); import antivirus; antivirus.scan_running_processes(interactive=True)" ;;
        scan_now) $PY -c "import sys; sys.path.insert(0, '$APP'); import antivirus; antivirus.daily_scan()" ;;
        logs) tail -n 20 -f "$APP/antivirus.log" ;;
        scan) [ -z "$2" ] && echo "Usage: kv scan <file>" || ($PY -c "import sys; sys.path.insert(0, '$APP'); import antivirus; antivirus.check_file_vt('$2', allow_upload=True)" && tail -n 1 "$APP/antivirus.log") ;;
        quarantine) ls -lh "$HOME/.kernel_quarantine" 2>/dev/null || echo "Vault is empty." ;;
        restore) [ -z "$2" ] && echo "Usage: kv restore <file>" || (RD=$($PY -c "import sys; sys.path.insert(0, '$APP'); import antivirus; print(antivirus.load_config()['restore_path'])"); mkdir -p "$RD" && chmod 644 "$HOME/.kernel_quarantine/$2" && mv "$HOME/.kernel_quarantine/$2" "$RD/${2%.quarantined}" && echo "✅ Restored to $RD/${2%.quarantined}") ;;
        purge) rm -f "$HOME/.kernel_quarantine"/* && echo "🗑️  Vault emptied." ;;
        restart) rm -f "$HOME/.kernel_paused" && pkill -f "$APP/antivirus.py" 2>/dev/null || true && echo "🔄 Restarted." ;;
        stop) touch "$HOME/.kernel_paused" && echo "🛑 Paused." ;;
        start) rm -f "$HOME/.kernel_paused" && echo "▶️  Resumed." ;;
        uninstall) read "R?⚠️  Uninstall Kernel Antivirus? (y/N): "; [[ "$R" =~ ^[Yy]$ ]] && bash "$APP/uninstall.sh" || echo "Cancelled." ;;
        help|*) echo "🛡️  Kernel Antivirus Commands: status | api_key | stats | whitelist | unwhitelist | config | restore_path | autoscan_folders | scan_time | log_autodelete | clear_logs | scan | scan_now | logs | quarantine | restore | purge | restart | stop | start | uninstall" ;;
    esac
}
ZSH
fi
echo "✅ Kernel Antivirus installed! Open a new Terminal window and type 'kv help'."
