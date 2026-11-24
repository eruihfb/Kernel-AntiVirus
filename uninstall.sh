#!/bin/bash
echo "🛑 Uninstalling Kernel Antivirus..."
launchctl unload ~/Library/LaunchAgents/com.kernelav.engine.plist 2>/dev/null || true
launchctl unload ~/Library/LaunchAgents/com.kernelav.menubar.plist 2>/dev/null || true
rm -f ~/Library/LaunchAgents/com.kernelav.engine.plist ~/Library/LaunchAgents/com.kernelav.menubar.plist
rm -rf "$HOME/.kernel_av" "$HOME/.kernel_paused"
echo "✅ Removed cleanly. (~/.kernel_quarantine was kept safe.)"
