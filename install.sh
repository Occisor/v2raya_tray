#!/usr/bin/env bash
# Install the v2rayA tray icon for the current user (no root needed).
# Установка значка v2rayA в трей для текущего пользователя (root не нужен).
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)/v2raya_tray.py"
BIN="$HOME/.local/bin/v2raya-tray"
CONF="${XDG_CONFIG_HOME:-$HOME/.config}/v2raya-tray/config.json"
AUTOSTART="${XDG_CONFIG_HOME:-$HOME/.config}/autostart/v2raya-tray.desktop"

python3 -c "import gi" 2>/dev/null || {
  echo "Need python3-gi and AppIndicator / Нужны python3-gi и AppIndicator:"
  echo "  Debian/Ubuntu: sudo apt install python3-gi gir1.2-ayatanaappindicator3-0.1"
  echo "  Fedora:        sudo dnf install python3-gobject libayatana-appindicator-gtk3"
  echo "  Arch:          sudo pacman -S python-gobject libayatana-appindicator"
  exit 1
}

install -Dm755 "$SRC" "$BIN"

if [ ! -f "$CONF" ]; then
  "$BIN" --setup   # asks for language, url, login, password; stores them encrypted
fi

mkdir -p "$(dirname "$AUTOSTART")"
cat > "$AUTOSTART" <<EOT
[Desktop Entry]
Type=Application
Name=v2rayA tray
Comment=v2rayA VPN status in the system tray
Exec=$BIN
Icon=network-vpn
X-GNOME-Autostart-enabled=true
EOT

echo "Check / Проверка:"
"$BIN" --once || true
echo "Run now / Запуск сейчас: $BIN &"
