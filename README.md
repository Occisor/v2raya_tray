# v2raya-tray

A system tray indicator for [v2rayA](https://github.com/v2rayA/v2rayA) on Linux. It shows at a glance whether your VPN is active and which node you are connected to.

v2rayA is a web client: you control it from a browser and it has no tray icon of its own. This small script fills that gap by polling the v2rayA REST API and displaying the result in your panel.

> This is an independent, unofficial companion tool. It is not affiliated with or endorsed by the v2rayA project, and it does not modify v2rayA in any way.

## Features

- Tray icon whose color shows the state of v2rayA
- Name of the connected node next to the icon, in the tooltip and in the menu
- Current mode shown in the menu (`tun`, `tproxy`, `redirect`, system proxy, or proxy ports only)
- Menu shortcut to open the v2rayA web interface
- Credentials stored encrypted, using only the Python standard library
- English and Russian interface, English by default
- No root required, no dependencies beyond GTK bindings and AppIndicator

## Icon states

| Icon | Meaning |
| --- | --- |
| Green shield with a check mark | v2rayA core is running. The label shows the node name, e.g. `VPN: AT-Vienna` |
| Gray shield | Core is stopped |
| Yellow shield | Network is paused |
| Red shield | Error: v2rayA is unreachable, login failed, or no account exists yet. The reason is shown in the menu |

If several nodes are connected, the label shows the first one followed by `+N`, and the menu lists all of them. If a group has one member pinned, that member is shown, since all traffic goes through it.

## How it works

Every few seconds the script:

1. Logs in with `POST /api/login` and keeps the JWT token (it logs in again automatically when the token expires).
2. Reads `GET /api/touch` for the `running` and `networkPaused` flags and the list of connected servers, and resolves node names from the servers and subscriptions in the same response.
3. Reads `GET /api/setting` to display the transparent proxy mode.

It only reads data. It never starts, stops or changes anything in v2rayA.

## Requirements

- Linux with a desktop environment that supports tray indicators (StatusNotifierItem / AppIndicator)
- Python 3.8 or newer
- PyGObject (`python3-gi`) and the Ayatana AppIndicator GObject bindings
- A running v2rayA instance with an account already created

Install the system packages for your distribution:

```bash
# Debian / Ubuntu
sudo apt install python3-gi gir1.2-ayatanaappindicator3-0.1

# Fedora
sudo dnf install python3-gobject libayatana-appindicator-gtk3

# Arch
sudo pacman -S python-gobject libayatana-appindicator
```

**GNOME note:** GNOME does not show tray icons by default. Install and enable the *AppIndicator and KStatusNotifierItem Support* extension (it is enabled out of the box on Ubuntu). KDE Plasma, XFCE, Cinnamon, MATE and Budgie work without extra steps.

## Installation

```bash
git clone https://github.com/occisor/v2raya-tray.git
cd v2raya-tray
bash ./install.sh
```

Run the installer with `bash`, not `sh`: it uses bash features that `dash` (the default `sh` on Debian and Ubuntu) does not support.

The installer:

- copies the script to `~/.local/bin/v2raya-tray`
- asks for language, v2rayA address, username and password, and stores them encrypted (see [Security](#security))
- creates an autostart entry so the icon appears at every login
- runs a connection check

Start it right away without logging out:

```bash
~/.local/bin/v2raya-tray &
```

### Manual installation

```bash
install -Dm755 v2raya_tray.py ~/.local/bin/v2raya-tray
~/.local/bin/v2raya-tray --setup
~/.local/bin/v2raya-tray &
```

To autostart it, create `~/.config/autostart/v2raya-tray.desktop`:

```ini
[Desktop Entry]
Type=Application
Name=v2raya tray
Exec=/home/YOUR_USER/.local/bin/v2raya-tray
```

## Configuration

Settings live in `~/.config/v2raya-tray/config.json` (or under `$XDG_CONFIG_HOME`). Run `v2raya-tray --setup` to create or update it. You can also edit the non-secret options by hand and restart the icon.

```json
{
  "language": "en",
  "url": "http://127.0.0.1:2017",
  "username": "enc:v1:...",
  "password": "enc:v1:...",
  "interval": 5,
  "show_label": true
}
```

| Option | Default | Description |
| --- | --- | --- |
| `language` | `en` | Interface language: `en` or `ru` |
| `url` | `http://127.0.0.1:2017` | Address of the v2rayA web interface. Include the path prefix if you run v2rayA behind one |
| `username`, `password` | empty | v2rayA account. Stored encrypted; do not edit by hand, use `--setup` |
| `interval` | `5` | Seconds between status checks |
| `show_label` | `true` | Show text next to the icon. Not every panel draws it; KDE, for example, shows only the icon, and the name stays available in the tooltip and menu |

Environment variables `V2RAYA_URL`, `V2RAYA_USERNAME` and `V2RAYA_PASSWORD` override the file, which is handy for testing.

### Command line

| Command | Description |
| --- | --- |
| `v2raya-tray` | Start the tray icon |
| `v2raya-tray --setup` | Interactively set language, address and credentials |
| `v2raya-tray --once` | Print the current status to the terminal and exit (no GUI), useful for diagnostics |

## Security

The v2rayA username and password are stored encrypted in `config.json`. The encryption uses only the Python standard library: HMAC-SHA256 in counter mode as a stream cipher, with encrypt-then-MAC (HMAC-SHA256) for integrity. The key is a random 32-byte file, `~/.config/v2raya-tray/key` (mode `600`), mixed with `/etc/machine-id`.

What this protects against: the config file leaking on its own (a backup, a dotfiles repository, a screenshot), or being copied to another machine.

What it does not protect against: someone who can already run code as your user. The icon has to decrypt the credentials unattended at login, so the key necessarily lives on the same machine. If your threat model includes that, use a dedicated low-privilege v2rayA account for the tray and keep v2rayA bound to `127.0.0.1` (`--address 127.0.0.1:2017`).

The cipher is a small custom construction built from standard primitives because the standard library offers no AES. If you need something audited, use your desktop keyring instead.

If the `key` file is lost or changed, the icon shows an error with a hint; run `v2raya-tray --setup` to enter the credentials again.

If you have an older plaintext `config.json`, it is encrypted in place the first time the script runs.

## Updating

Pull the new version and run the installer again. It replaces the script and leaves your existing configuration untouched.

```bash
git pull
bash ./install.sh
pkill -f v2raya-tray; ~/.local/bin/v2raya-tray &
```

## Uninstallation

```bash
# 1. stop the running icon
pkill -f v2raya-tray

# 2. remove the program and the autostart entry
rm -f ~/.local/bin/v2raya-tray
rm -f ~/.config/autostart/v2raya-tray.desktop

# 3. remove the configuration (encrypted credentials and key) and icons
rm -rf ~/.config/v2raya-tray
rm -rf ~/.local/share/v2raya-tray
```

If you set `XDG_CONFIG_HOME` or `XDG_DATA_HOME`, the paths are relative to those directories instead of `~/.config` and `~/.local/share`.

The system packages (`python3-gi`, AppIndicator) are shared with other applications, so you can keep them. To remove them anyway, for example on Debian/Ubuntu:

```bash
sudo apt remove python3-gi gir1.2-ayatanaappindicator3-0.1
```

Uninstalling the tray icon does not affect v2rayA itself.

## Troubleshooting

**No icon appears.** On GNOME, make sure the AppIndicator extension is installed and enabled. Then check that the script runs: `v2raya-tray --once` should print a status line.

**`./install.sh: Illegal option -o pipefail`.** You ran it with `sh`. Use `bash ./install.sh`.

**Red icon, "v2rayA is unreachable".** Check that the service is running (`systemctl status v2raya`) and that `url` in the config matches the address v2rayA listens on.

**Red icon, "Login failed".** Wrong username or password. Run `v2raya-tray --setup`.

**Red icon, "v2rayA has no account yet".** Open the v2rayA web interface and create the administrator account first.

**Red icon, "Cannot decrypt credentials".** The `key` file next to the config was changed or deleted, or the config was copied from another machine. Run `v2raya-tray --setup`.

**`ModuleNotFoundError` / missing library message.** Install the system packages listed in [Requirements](#requirements).

## Files

| File | Purpose |
| --- | --- |
| `v2raya_tray.py` | The whole application: API client, encryption, tray UI |
| `install.sh` | Installer: copies the script, runs setup, adds autostart |

## Credits

Built for [v2rayA](https://github.com/v2rayA/v2rayA), a web client for an Xray-based core with transparent proxy support. Please follow v2rayA's own terms and local laws when using it.

<a href="https://www.donationalerts.com/r/sociophobenoob"><img src="https://img.shields.io/badge/Donate-DonationAlerts-F57D07" />
