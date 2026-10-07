#!/usr/bin/env python3
"""Tray indicator for v2rayA on Linux / Значок v2rayA в системном трее Linux.

Shows whether the v2rayA core is running and the name of the connected node.
Data comes from the v2rayA REST API: POST /api/login, GET /api/touch, GET /api/setting.
Credentials are stored encrypted (standard library only).
"""
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

APP_ID = "v2raya-tray"
CONFIG_PATH = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_ID / "config.json"
KEY_PATH = CONFIG_PATH.with_name("key")
ICON_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / APP_ID / "icons"

DEFAULTS = {
    "url": "http://localhost:2017",
    "username": "",
    "password": "",
    "language": "en",     # en | ru
    "interval": 5,        # seconds between polls
    "show_label": True,   # text next to the icon (not every panel draws it)
}

# ---------------------------------------------------------------- i18n
STRINGS = {
    "en": {
        "vpn_active": "VPN: active",
        "vpn_server": "VPN: {name}{extra}",
        "vpn_off": "VPN off",
        "vpn_paused": "VPN paused",
        "vpn_error": "v2rayA: error",
        "mode_ports": "proxy ports only (SOCKS5/HTTP)",
        "mode_transparent": "transparent proxy: {kind}, mode {mode}",
        "err_no_creds": "No credentials set. Run: v2raya-tray --setup",
        "err_decrypt": "Cannot decrypt credentials (key file changed?). Run: v2raya-tray --setup",
        "err_first_run": "v2rayA has no account yet: create one in the web interface",
        "err_login": "Login failed: {msg}",
        "err_wrong_pass": "wrong username or password",
        "err_api": "API error",
        "err_not_api": "HTTP {status}: not a v2rayA API? Check the url",
        "err_unexpected": "HTTP {status}: unexpected response",
        "err_auth": "Could not authenticate to v2rayA",
        "err_unreachable": "v2rayA is unreachable ({url}): {reason}",
        "err_libs": "Libraries for the tray icon are missing: {err}",
        "menu_open": "Open v2rayA",
        "menu_refresh": "Refresh now",
        "menu_quit": "Quit",
        "setup_url": "v2rayA address [{default}]: ",
        "setup_user": "v2rayA username: ",
        "setup_pass": "v2rayA password: ",
        "setup_lang": "Language en/ru [{default}]: ",
        "setup_done": "Saved to {path} (credentials encrypted).",
    },
    "ru": {
        "vpn_active": "VPN: активен",
        "vpn_server": "VPN: {name}{extra}",
        "vpn_off": "VPN выключен",
        "vpn_paused": "VPN на паузе",
        "vpn_error": "v2rayA: ошибка",
        "mode_ports": "только прокси-порты (SOCKS5/HTTP)",
        "mode_transparent": "прозрачный прокси: {kind}, режим {mode}",
        "err_no_creds": "Логин и пароль не заданы. Выполните: v2raya-tray --setup",
        "err_decrypt": "Не удалось расшифровать логин/пароль (изменился файл key?). Выполните: v2raya-tray --setup",
        "err_first_run": "В v2rayA ещё нет аккаунта: создайте его в веб-интерфейсе",
        "err_login": "Не удалось войти: {msg}",
        "err_wrong_pass": "неверный логин или пароль",
        "err_api": "ошибка API",
        "err_not_api": "HTTP {status}: это не API v2rayA? Проверьте url",
        "err_unexpected": "HTTP {status}: неожиданный ответ",
        "err_auth": "Не удалось авторизоваться в v2rayA",
        "err_unreachable": "v2rayA недоступен ({url}): {reason}",
        "err_libs": "Не найдены библиотеки для значка в трее: {err}",
        "menu_open": "Открыть v2rayA",
        "menu_refresh": "Обновить сейчас",
        "menu_quit": "Выход",
        "setup_url": "Адрес v2rayA [{default}]: ",
        "setup_user": "Логин v2rayA: ",
        "setup_pass": "Пароль v2rayA: ",
        "setup_lang": "Язык en/ru [{default}]: ",
        "setup_done": "Сохранено в {path} (логин и пароль зашифрованы).",
    },
}
_lang = "en"


def set_language(code):
    global _lang
    code = str(code or "en").strip().lower()[:2]
    if code not in STRINGS:
        print(f"{APP_ID}: unknown language {code!r}, using 'en' (available: en, ru)", file=sys.stderr)
        code = "en"
    _lang = code


def tr(key, **kw):
    return STRINGS[_lang][key].format(**kw)


# ---------------------------------------------------------------- encryption
# Standard library only. Construction: HMAC-SHA256 as a PRF in counter mode
# (stream cipher) + encrypt-then-MAC with HMAC-SHA256. The master key comes from
# a random 32-byte key file (mode 600) mixed with /etc/machine-id, so the
# config alone, or the config copied to another machine, is useless.
ENC_PREFIX = "enc:v1:"


def _write_private(path, data, exclusive=False):
    """Write a file readable only by the owner; atomic unless exclusive."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if exclusive:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _machine_id():
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            return Path(p).read_bytes().strip()
        except OSError:
            continue
    return b""


def _master_key(create):
    try:
        raw = KEY_PATH.read_bytes()
    except FileNotFoundError:
        if not create:
            raise ValueError("key file missing")
        raw = secrets.token_bytes(32)
        try:
            _write_private(KEY_PATH, raw, exclusive=True)
        except FileExistsError:  # created by a parallel process
            raw = KEY_PATH.read_bytes()
    if len(raw) < 32:
        raise ValueError("key file corrupted")
    return hmac.new(raw, b"v2raya-tray|" + _machine_id(), hashlib.sha256).digest()


def _subkey(master, label):
    return hmac.new(master, b"subkey|" + label, hashlib.sha256).digest()


def _keystream(key, nonce, n):
    out, counter = bytearray(), 0
    while len(out) < n:
        out += hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:n])


def encrypt(text):
    master = _master_key(create=True)
    nonce = secrets.token_bytes(16)
    pt = text.encode()
    ct = bytes(a ^ b for a, b in zip(pt, _keystream(_subkey(master, b"enc"), nonce, len(pt))))
    tag = hmac.new(_subkey(master, b"mac"), b"v1" + nonce + ct, hashlib.sha256).digest()
    return ENC_PREFIX + base64.urlsafe_b64encode(nonce + ct + tag).decode()


def decrypt(token):
    """Raises ValueError on any problem: bad format, wrong key, tampering."""
    master = _master_key(create=False)
    blob = base64.urlsafe_b64decode(token[len(ENC_PREFIX):])  # binascii.Error is a ValueError
    if len(blob) < 48:
        raise ValueError("truncated")
    nonce, ct, tag = blob[:16], blob[16:-32], blob[-32:]
    expected = hmac.new(_subkey(master, b"mac"), b"v1" + nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed")
    pt = bytes(a ^ b for a, b in zip(ct, _keystream(_subkey(master, b"enc"), nonce, len(ct))))
    return pt.decode()


# ---------------------------------------------------------------- config
def _read_config_file():
    try:
        data = json.loads(CONFIG_PATH.read_text())
    except FileNotFoundError:
        return {}
    except ValueError as e:
        sys.exit(f"{CONFIG_PATH}: invalid JSON: {e}")
    if not isinstance(data, dict):
        sys.exit(f"{CONFIG_PATH}: expected a JSON object")
    return data


def _save_config_file(file_cfg, username, password):
    out = dict(file_cfg)
    out["username"] = encrypt(username)
    out["password"] = encrypt(password)
    _write_private(CONFIG_PATH, (json.dumps(out, indent=2, ensure_ascii=False) + "\n").encode())


def load_config():
    file_cfg = _read_config_file()
    cfg = {**DEFAULTS, **file_cfg}
    set_language(cfg["language"])
    cfg["cred_error"] = None

    plain_in_file = False
    for key in ("username", "password"):
        value = cfg.get(key) or ""
        if value.startswith(ENC_PREFIX):
            try:
                cfg[key] = decrypt(value)
            except ValueError:
                cfg[key] = ""
                cfg["cred_error"] = tr("err_decrypt")
        elif value:
            plain_in_file = True  # old plaintext config: encrypt it in place

    if plain_in_file and not cfg["cred_error"]:
        try:
            _save_config_file(file_cfg, cfg["username"], cfg["password"])
        except OSError as e:
            print(f"{APP_ID}: could not encrypt {CONFIG_PATH}: {e}", file=sys.stderr)

    for key, env in (("url", "V2RAYA_URL"), ("username", "V2RAYA_USERNAME"), ("password", "V2RAYA_PASSWORD")):
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    if cfg["username"] and cfg["password"]:  # e.g. both given via environment
        cfg["cred_error"] = None
    cfg["url"] = cfg["url"].rstrip("/")
    return cfg


def run_setup():
    file_cfg = _read_config_file()
    lang = input(f"Language en/ru [{file_cfg.get('language', 'en')}]: ").strip() or file_cfg.get("language", "en")
    set_language(lang)
    file_cfg["language"] = _lang
    default_url = file_cfg.get("url", DEFAULTS["url"])
    file_cfg["url"] = (input(tr("setup_url", default=default_url)).strip() or default_url).rstrip("/")
    username = input(tr("setup_user")).strip()
    password = getpass.getpass(tr("setup_pass"))
    for key in ("interval", "show_label"):
        file_cfg.setdefault(key, DEFAULTS[key])
    _save_config_file(file_cfg, username, password)
    print(tr("setup_done", path=CONFIG_PATH))


# ---------------------------------------------------------------- status & API
ICONS = {
    "on": ("#2ea44f", '<path d="M8 12.5l3 3 5-6.5" fill="none" stroke="#fff" stroke-width="2.2" '
                      'stroke-linecap="round" stroke-linejoin="round"/>'),
    "off": ("#8b949e", '<path d="M8.5 12h7" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/>'),
    "paused": ("#d29922", '<path d="M9.5 8.5v7M14.5 8.5v7" fill="none" stroke="#fff" stroke-width="2.2" '
                          'stroke-linecap="round"/>'),
    "error": ("#cf222e", '<path d="M12 8v5" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/>'
                         '<circle cx="12" cy="16.2" r="1.2" fill="#fff"/>'),
}
SHIELD = "M12 2L4 5v6c0 5 3.5 9.5 8 11 4.5-1.5 8-6 8-11V5z"


class ApiError(Exception):
    pass


@dataclass
class Status:
    state: str                      # on | off | paused | error
    servers: list = field(default_factory=list)
    mode: str = ""
    detail: str = ""

    @property
    def label(self):
        if self.state == "on":
            if not self.servers:
                return tr("vpn_active")
            extra = f" +{len(self.servers) - 1}" if len(self.servers) > 1 else ""
            return tr("vpn_server", name=self.servers[0], extra=extra)
        return tr({"off": "vpn_off", "paused": "vpn_paused", "error": "vpn_error"}[self.state])


class V2rayAClient:
    def __init__(self, base_url, username, password, timeout=4, cred_error=None):
        self.base = base_url
        self.username = username
        self.password = password
        self.timeout = timeout
        self.cred_error = cred_error
        self.token = None

    def _request(self, method, path, body=None):
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = self.token
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:  # v2rayA answers 401 with a JSON body
            status, raw = e.code, e.read()
        try:
            payload = json.loads(raw)
        except ValueError:
            raise ApiError(tr("err_not_api", status=status))
        if not isinstance(payload, dict):
            raise ApiError(tr("err_unexpected", status=status))
        return status, payload

    @staticmethod
    def _is_first_run(payload):
        data = payload.get("data")
        return isinstance(data, dict) and data.get("first") is True

    def _login(self):
        if self.cred_error:
            raise ApiError(self.cred_error)
        if not self.username:
            raise ApiError(tr("err_no_creds"))
        self.token = None
        status, p = self._request("POST", "/api/login", {"username": self.username, "password": self.password})
        if self._is_first_run(p):
            raise ApiError(tr("err_first_run"))
        if p.get("code") != "SUCCESS":
            raise ApiError(tr("err_login", msg=p.get("message") or tr("err_wrong_pass")))
        self.token = p["data"]["token"]

    def _get(self, path):
        for _ in range(2):
            if not self.token:
                self._login()
            status, p = self._request("GET", path)
            # an expired token arrives either as HTTP 401 or as 200 + errorCode
            if status == 401 or p.get("errorCode") in ("SESSION_EXPIRED", "SESSION_INVALID"):
                if self._is_first_run(p):
                    raise ApiError(tr("err_first_run"))
                self.token = None
                continue
            if p.get("code") != "SUCCESS":
                raise ApiError(str(p.get("message") or tr("err_api")))
            return p["data"]
        raise ApiError(tr("err_auth"))

    def fetch(self):
        """Always returns a Status, never raises."""
        try:
            touch = self._get("/api/touch")
            try:
                setting = self._get("/api/setting").get("setting") or {}
            except ApiError:
                setting = {}  # the mode is an optional detail
            return parse_status(touch, setting)
        except ApiError as e:
            return Status("error", detail=str(e))
        except OSError as e:  # URLError, timeout, connection refused
            reason = getattr(e, "reason", e)
            return Status("error", detail=tr("err_unreachable", url=self.base, reason=reason))


def connected_server_names(touch):
    """Names of connected nodes. `sub` in connectedServer is 0-based, `id` is 1-based."""
    servers = touch.get("servers") or []
    subs = touch.get("subscriptions") or []
    selected, others = [], []
    for w in touch.get("connectedServer") or []:
        idx = w.get("id", 0) - 1
        name = None
        try:
            if w.get("_type") == "server":
                name = servers[idx]["name"]
            elif w.get("_type") == "subscriptionServer":
                name = subs[w["sub"]]["servers"][idx]["name"]
        except (IndexError, KeyError, TypeError):
            pass
        if idx < 0 or not name:
            continue
        (selected if w.get("selected") else others).append(name)
    # if the group pins one member, traffic goes only through it
    return selected or others


def describe_mode(setting):
    mode = setting.get("transparent")
    if not mode or mode == "close":
        return tr("mode_ports")
    return tr("mode_transparent", kind=setting.get("transparentType") or "?", mode=mode)


def parse_status(touch_data, setting):
    if touch_data.get("networkPaused"):
        state = "paused"
    elif touch_data.get("running"):
        state = "on"
    else:
        state = "off"
    names = connected_server_names(touch_data.get("touch") or {}) if state != "off" else []
    return Status(state, servers=names, mode=describe_mode(setting) if state != "off" else "")


# ---------------------------------------------------------------- tray UI
def write_icons():
    ICON_DIR.mkdir(parents=True, exist_ok=True)
    for name, (color, glyph) in ICONS.items():
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">'
               f'<path d="{SHIELD}" fill="{color}"/>{glyph}</svg>')
        (ICON_DIR / f"{APP_ID}-{name}.svg").write_text(svg)


def make_client(cfg):
    return V2rayAClient(cfg["url"], cfg["username"], cfg["password"], cred_error=cfg["cred_error"])


def run_tray(cfg):
    import gi

    gi.require_version("Gtk", "3.0")
    try:
        gi.require_version("AyatanaAppIndicator3", "0.1")
        from gi.repository import AyatanaAppIndicator3 as AppIndicator
    except (ValueError, ImportError):
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import AppIndicator3 as AppIndicator
    from gi.repository import GLib, Gtk

    write_icons()
    client = make_client(cfg)

    ind = AppIndicator.Indicator.new(APP_ID, f"{APP_ID}-off", AppIndicator.IndicatorCategory.APPLICATION_STATUS)
    ind.set_icon_theme_path(str(ICON_DIR))
    ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)

    state = {"busy": False, "last": None}

    def add_line(menu, text, sensitive=False):
        item = Gtk.MenuItem(label=text)
        item.set_sensitive(sensitive)
        menu.append(item)
        return item

    def build_menu(st):
        menu = Gtk.Menu()
        add_line(menu, st.label)
        if st.state == "error":
            add_line(menu, st.detail)
        elif st.state != "off":
            for name in st.servers:
                add_line(menu, f"  • {name}")
            if st.mode:
                add_line(menu, st.mode)
        menu.append(Gtk.SeparatorMenuItem())
        open_ui = add_line(menu, tr("menu_open"), True)
        open_ui.connect("activate", lambda *_: subprocess.Popen(["xdg-open", cfg["url"]]))
        refresh = add_line(menu, tr("menu_refresh"), True)
        refresh.connect("activate", lambda *_: tick())
        quit_item = add_line(menu, tr("menu_quit"), True)
        quit_item.connect("activate", lambda *_: Gtk.main_quit())
        menu.show_all()
        return menu

    def apply(st):
        state["busy"] = False
        if st != state["last"]:  # rebuild the menu only on changes
            state["last"] = st
            ind.set_icon_full(f"{APP_ID}-{st.state}", st.label)
            ind.set_title(st.label)
            if cfg["show_label"]:
                text = st.label if len(st.label) <= 32 else st.label[:31] + "…"
                ind.set_label(text, "v2rayA: " + "x" * 24)
            ind.set_menu(build_menu(st))
        return False

    def worker():
        GLib.idle_add(apply, client.fetch())

    def tick():
        if not state["busy"]:
            state["busy"] = True
            threading.Thread(target=worker, daemon=True).start()
        return True  # keep the timer running

    tick()
    GLib.timeout_add_seconds(max(1, int(cfg["interval"])), tick)
    Gtk.main()


def main():
    if "--setup" in sys.argv:
        run_setup()
        return
    cfg = load_config()
    if "--once" in sys.argv:  # diagnostics without a GUI
        st = make_client(cfg).fetch()
        print(st.label, "|", st.mode or st.detail)
        return
    try:
        run_tray(cfg)
    except (ImportError, ValueError) as e:
        sys.exit(tr("err_libs", err=e) + "\n"
                 "Debian/Ubuntu: sudo apt install python3-gi gir1.2-ayatanaappindicator3-0.1\n"
                 "Fedora: sudo dnf install python3-gobject libayatana-appindicator-gtk3\n"
                 "Arch: sudo pacman -S python-gobject libayatana-appindicator")


if __name__ == "__main__":
    main()
