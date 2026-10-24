#!/usr/bin/env python3
"""Tray indicator for v2rayA on Linux / Значок v2rayA в системном трее Linux.

Shows whether the v2rayA core is running and the node that is ACTIVE right now.
Data comes from the v2rayA REST API (POST /api/login, GET /api/touch, GET /api/setting)
and from its live WebSocket feed (/api/message) with per-node latency.
Credentials are stored encrypted (standard library only).
"""
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

APP_ID = "v2raya-tray"
CONFIG_PATH = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_ID / "config.json"
KEY_PATH = CONFIG_PATH.with_name("key")
ICON_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / APP_ID / "icons"

DEFAULTS = {
    "url": "http://127.0.0.1:2017",
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
        "group_title": "Group “{name}”",
        "active_unknown": "active node not detected yet (showing the first)",
        "member_down": "down",
        "member_pinned": "pinned",
        "unit_ms": "ms",
        "more_members": "… and {n} more",
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
        "group_title": "Группа «{name}»",
        "active_unknown": "активный узел пока не определён (показан первый)",
        "member_down": "недоступен",
        "member_pinned": "закреплён",
        "unit_ms": "мс",
        "more_members": "… и ещё {n}",
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


DEFAULT_GROUP = "proxy"   # the main outbound group of v2rayA
MAX_MEMBERS = 10          # menu lines per group


@dataclass
class Member:
    name: str
    alive: object = None   # True / False, or None when there is no observation
    delay: object = None   # milliseconds, or None
    active: bool = False


@dataclass
class Group:
    name: str
    members: list
    pinned: bool = False        # one member is pinned: the group routes through it alone
    active_known: bool = True   # False: could not tell which member is in use

    @property
    def active(self):
        return next((m for m in self.members if m.active), None)


@dataclass
class Status:
    state: str                      # on | off | paused | error
    groups: list = field(default_factory=list)
    mode: str = ""
    detail: str = ""

    @property
    def main(self):
        return self.groups[0] if self.groups else None

    @property
    def label(self):
        if self.state == "on":
            g = self.main
            if g is None or not g.members:
                return tr("vpn_active")
            if g.active:
                return tr("vpn_server", name=g.active.name, extra="")
            extra = f" +{len(g.members) - 1}" if len(g.members) > 1 else ""
            return tr("vpn_server", name=g.members[0].name, extra=extra)
        return tr({"off": "vpn_off", "paused": "vpn_paused", "error": "vpn_error"}[self.state])


def member_text(m, group, with_delay=True):
    text = ("● " if m.active else "    ") + m.name
    tags = []
    if m.active and group.pinned:
        tags.append(tr("member_pinned"))
    if m.alive is False:
        tags.append(tr("member_down"))
    elif with_delay and m.delay is not None and m.alive:
        tags.append(f"{m.delay} {tr('unit_ms')}")
    return text + (" — " + ", ".join(tags) if tags else "")


def menu_lines(st, with_delay=True):
    """Text lines of the menu header block. Without delays they only change when something structural does."""
    lines = [st.label]
    if st.state == "error":
        lines.append(st.detail)
        return lines
    if st.state == "off":
        return lines
    for g in st.groups:
        if len(st.groups) > 1 or g.name != DEFAULT_GROUP:
            lines.append(tr("group_title", name=g.name))
        if not g.active_known:
            lines.append(tr("active_unknown"))
        ordered = sorted(g.members, key=lambda m: not m.active)  # the active one goes first
        lines.extend(member_text(m, g, with_delay) for m in ordered[:MAX_MEMBERS])
        if len(ordered) > MAX_MEMBERS:
            lines.append(tr("more_members", n=len(ordered) - MAX_MEMBERS))
    if st.mode:
        lines.append(st.mode)
    return lines


class V2rayAClient:
    def __init__(self, base_url, username, password, timeout=4, cred_error=None):
        self.base = base_url
        self.username = username
        self.password = password
        self.timeout = timeout
        self.cred_error = cred_error
        self.token = None
        self._lock = threading.RLock()  # the poller and the WebSocket thread share the token

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

    def ensure_token(self):
        with self._lock:
            if not self.token:
                self._login()
            return self.token

    def invalidate_token(self, token=None):
        with self._lock:
            if token is None or self.token == token:
                self.token = None

    def _get(self, path):
        for _ in range(2):
            self.ensure_token()
            status, p = self._request("GET", path)
            # an expired token arrives either as HTTP 401 or as 200 + errorCode
            if status == 401 or p.get("errorCode") in ("SESSION_EXPIRED", "SESSION_INVALID"):
                if self._is_first_run(p):
                    raise ApiError(tr("err_first_run"))
                self.invalidate_token()
                continue
            if p.get("code") != "SUCCESS":
                raise ApiError(str(p.get("message") or tr("err_api")))
            return p["data"]
        raise ApiError(tr("err_auth"))

    def fetch(self, observed=None):
        """Always returns a Status, never raises. `observed(outbound)` gives live latency data or None."""
        try:
            touch = self._get("/api/touch")
            try:
                setting = self._get("/api/setting").get("setting") or {}
            except ApiError:
                setting = {}  # the mode is an optional detail
            return parse_status(touch, setting, observed)
        except ApiError as e:
            return Status("error", detail=str(e))
        except OSError as e:  # URLError, timeout, connection refused
            reason = getattr(e, "reason", e)
            return Status("error", detail=tr("err_unreachable", url=self.base, reason=reason))


# ---------------------------------------------------------------- which node is active
def node_key(w):
    """Identity of a node inside a touch / observatory entry. `sub` only counts for subscription nodes."""
    kind = w.get("_type")
    return (kind, w.get("sub", 0) if kind == "subscriptionServer" else 0, w.get("id"))


def _node_name(touch, w):
    """`sub` in connectedServer is 0-based, `id` is 1-based."""
    servers = touch.get("servers") or []
    subs = touch.get("subscriptions") or []
    idx = (w.get("id") or 0) - 1
    if idx < 0:
        return None
    try:
        if w.get("_type") == "server":
            return servers[idx]["name"] or None
        if w.get("_type") == "subscriptionServer":
            return subs[w["sub"]]["servers"][idx]["name"] or None
    except (IndexError, KeyError, TypeError):
        pass
    return None


def build_groups(touch, observed=None):
    """Connected nodes grouped by outbound, the main group ("proxy") first, with the ACTIVE member marked.

    Active member of a group:
      1. the pinned one (`selected`): the group routes through it alone;
      2. the only member;
      3. otherwise v2rayA balances with `leastping`: the alive member with the lowest delay,
         taken from the live observatory feed. Without fresh data it is unknown.
    """
    raw = {}   # outbound -> {"names", "keys", "pinned"}
    order = []
    for w in touch.get("connectedServer") or []:
        name = _node_name(touch, w)
        if not name:
            continue
        ob = w.get("outbound") or DEFAULT_GROUP
        if ob not in raw:
            raw[ob] = {"names": [], "keys": [], "pinned": None}
            order.append(ob)
        g = raw[ob]
        if w.get("selected") and g["pinned"] is None:
            g["pinned"] = len(g["names"])
        g["names"].append(name)
        g["keys"].append(node_key(w))
    if DEFAULT_GROUP in order:
        order.remove(DEFAULT_GROUP)
        order.insert(0, DEFAULT_GROUP)

    groups = []
    for ob in order:
        g = raw[ob]
        members = [Member(n) for n in g["names"]]
        snap = observed(ob) if observed else None
        if snap:
            for m, key in zip(members, g["keys"]):
                if key in snap:
                    m.alive, m.delay = snap[key]
        known = True
        if g["pinned"] is not None:
            members[g["pinned"]].active = True
        elif len(members) == 1:
            members[0].active = True
        else:
            alive = [m for m in members if m.alive]
            if alive:
                min(alive, key=lambda m: m.delay if m.delay is not None else float("inf")).active = True
            else:
                known = False
        groups.append(Group(ob, members, pinned=g["pinned"] is not None, active_known=known))
    return groups


def describe_mode(setting):
    mode = setting.get("transparent")
    if not mode or mode == "close":
        return tr("mode_ports")
    return tr("mode_transparent", kind=setting.get("transparentType") or "?", mode=mode)


def parse_status(touch_data, setting, observed=None):
    if touch_data.get("networkPaused"):
        state = "paused"
    elif touch_data.get("running"):
        state = "on"
    else:
        state = "off"
    if state == "off":
        return Status(state)
    groups = build_groups(touch_data.get("touch") or {}, observed)
    return Status(state, groups=groups, mode=describe_mode(setting))


# ---------------------------------------------------------------- live feed (minimal WebSocket client)
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_MAX_FRAME = 8 * 1024 * 1024


class WsError(Exception):
    pass


class WsHandshakeError(WsError):
    def __init__(self, status):
        super().__init__(f"handshake failed: HTTP {status}")
        self.status = status


def ws_connect(base_url, path, token, timeout=10):
    """Open a WebSocket (RFC 6455) to base_url + path. Returns (socket, bytes read past the handshake)."""
    u = urllib.parse.urlsplit(base_url)
    secure = u.scheme == "https"
    port = u.port or (443 if secure else 80)
    sock = socket.create_connection((u.hostname, port), timeout=timeout)
    try:
        if secure:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
        key = base64.b64encode(os.urandom(16)).decode()
        host = u.hostname if not u.port else f"{u.hostname}:{u.port}"
        quoted = urllib.parse.quote(token, safe="")
        target = f"{u.path.rstrip('/')}{path}?token={quoted}&Authorization={quoted}"
        sock.sendall((f"GET {target} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                      f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                      f"Sec-WebSocket-Version: 13\r\nAuthorization: {token}\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise WsError("connection closed during handshake")
            buf += chunk
            if len(buf) > 65536:
                raise WsError("handshake response too large")
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            raise WsError("bad handshake response")
        if status != 101:
            raise WsHandshakeError(status)
        headers = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        if headers.get("sec-websocket-accept") != accept:
            raise WsError("bad Sec-WebSocket-Accept")
        return sock, rest
    except BaseException:
        sock.close()
        raise


class WsReader:
    """Reads complete text messages; answers pings; a client must mask what it sends."""

    def __init__(self, sock, initial=b""):
        self.sock = sock
        self.buf = bytearray(initial)
        self.last_rx = time.monotonic()

    def _read(self, n, at_boundary=False):
        deadline = time.monotonic() + 30
        while len(self.buf) < n:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                if at_boundary and not self.buf:
                    raise  # idle between frames: let the caller decide
                if time.monotonic() > deadline:
                    raise WsError("stalled in the middle of a frame")
                continue
            if not chunk:
                raise WsError("connection closed")
            self.buf += chunk
            self.last_rx = time.monotonic()
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def send(self, opcode, payload=b""):
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes([0x80 | opcode, 0x80 | len(payload)]) + mask + masked)  # control frames: <= 125 bytes

    def recv_text(self):
        parts, started = [], False
        while True:
            b1, b2 = self._read(2, at_boundary=True)
            fin, rsv, opcode = b1 & 0x80, b1 & 0x70, b1 & 0x0F
            if rsv:
                raise WsError("compressed frames are not supported")
            length = b2 & 0x7F
            if length == 126:
                (length,) = struct.unpack(">H", self._read(2))
            elif length == 127:
                (length,) = struct.unpack(">Q", self._read(8))
            if length > WS_MAX_FRAME:
                raise WsError("frame too large")
            mask = self._read(4) if b2 & 0x80 else None
            payload = self._read(length) if length else b""
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:
                raise WsError("closed by server")
            if opcode == 0x9:
                self.send(0xA, payload[:125])
            elif opcode == 0xA:
                pass
            elif opcode in (0x1, 0x0):
                if opcode == 0x1:
                    parts, started = [], True
                if not started:
                    raise WsError("unexpected continuation frame")
                parts.append(payload)
                if fin:
                    return b"".join(parts).decode("utf-8")


class ObservatoryFeed:
    """Background thread that keeps the latest per-node latency published by v2rayA.

    `snapshot(outbound)` returns {node_key: (alive, delay_ms)} or None when there is no fresh data.
    """
    STALE_AFTER = 20  # seconds; v2rayA publishes about once a second while the core runs

    def __init__(self, client):
        self.client = client
        self._lock = threading.Lock()
        self._data = {}
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, name="observatory-feed", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def snapshot(self, outbound):
        with self._lock:
            entry = self._data.get(outbound)
        if entry is None or time.monotonic() - entry[0] > self.STALE_AFTER:
            return None
        return entry[1]

    def handle(self, text):
        try:
            msg = json.loads(text)
            if msg.get("type") != "observatory":
                return False
            body = msg["body"]
            statuses = {}
            for st in body.get("outboundStatus") or []:
                which = st.get("which")
                if isinstance(which, dict):
                    statuses[node_key(which)] = (bool(st.get("alive")), st.get("delay"))
            with self._lock:
                self._data[body["outboundName"]] = (time.monotonic(), statuses)
            return True
        except (ValueError, KeyError, TypeError, AttributeError):
            return False  # a malformed message must never kill the feed

    def _session(self):
        token = self.client.ensure_token()
        try:
            sock, rest = ws_connect(self.client.base, "/api/message", token)
        except WsHandshakeError as e:
            if e.status == 401:
                self.client.invalidate_token(token)
            raise
        got_data = False
        try:
            sock.settimeout(15)
            reader = WsReader(sock, rest)
            while not self._stop.is_set():
                try:
                    text = reader.recv_text()
                except socket.timeout:
                    if time.monotonic() - reader.last_rx > 45:
                        raise WsError("no data from the server")
                    reader.send(0x9)  # keep-alive ping
                    continue
                got_data = self.handle(text) or got_data
        finally:
            sock.close()
        return got_data

    def _run(self):
        backoff = 2
        while not self._stop.is_set():
            try:
                if self._session():
                    backoff = 2
            except (WsError, ApiError, OSError, ValueError):
                pass
            self._stop.wait(backoff)
            backoff = min(backoff * 2, 30)


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
    feed = ObservatoryFeed(client)
    feed.start()

    ind = AppIndicator.Indicator.new(APP_ID, f"{APP_ID}-off", AppIndicator.IndicatorCategory.APPLICATION_STATUS)
    ind.set_icon_theme_path(str(ICON_DIR))
    ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)

    state = {"busy": False, "last": None, "sig": None, "items": []}

    def add_line(menu, text, sensitive=False):
        item = Gtk.MenuItem(label=text)
        item.set_sensitive(sensitive)
        menu.append(item)
        return item

    def build_menu(st):
        menu = Gtk.Menu()
        state["items"] = [add_line(menu, text) for text in menu_lines(st)]
        menu.append(Gtk.SeparatorMenuItem())
        open_ui = add_line(menu, tr("menu_open"), True)
        open_ui.connect("activate", lambda *_: subprocess.Popen(["xdg-open", cfg["url"]]))
        refresh = add_line(menu, tr("menu_refresh"), True)
        refresh.connect("activate", lambda *_: tick())
        quit_item = add_line(menu, tr("menu_quit"), True)
        quit_item.connect("activate", lambda *_: (feed.stop(), Gtk.main_quit()))
        menu.show_all()
        return menu

    def apply(st):
        state["busy"] = False
        if st == state["last"]:
            return False
        state["last"] = st
        # signature without latencies: when only the numbers moved, relabel the items in place
        # instead of rebuilding, which would close a menu the user has open
        sig = (st.state, tuple(menu_lines(st, with_delay=False)))
        if sig == state["sig"]:
            for item, text in zip(state["items"], menu_lines(st)):
                item.set_label(text)
            return False
        state["sig"] = sig
        # The menu goes first: libayatana-appindicator creates its D-Bus object path only once a menu
        # exists, and set_title() emits a signal on that path (a GLib-GIO-CRITICAL warning otherwise).
        ind.set_menu(build_menu(st))
        ind.set_icon_full(f"{APP_ID}-{st.state}", st.label)
        ind.set_title(st.label)
        if cfg["show_label"]:
            text = st.label if len(st.label) <= 32 else st.label[:31] + "…"
            ind.set_label(text, "v2rayA: " + "x" * 24)
        return False

    def worker():
        GLib.idle_add(apply, client.fetch(feed.snapshot))

    def tick():
        if not state["busy"]:
            state["busy"] = True
            threading.Thread(target=worker, daemon=True).start()
        return True  # keep the timer running

    tick()
    GLib.timeout_add_seconds(max(1, int(cfg["interval"])), tick)
    Gtk.main()


def run_once(cfg):
    """Diagnostics without a GUI: print the status; wait briefly for live data if the active node is unknown."""
    client = make_client(cfg)
    feed = ObservatoryFeed(client)
    feed.start()
    st = client.fetch(feed.snapshot)
    deadline = time.monotonic() + 4
    while st.state == "on" and any(not g.active_known for g in st.groups) and time.monotonic() < deadline:
        time.sleep(0.5)
        st = client.fetch(feed.snapshot)
    feed.stop()
    print("\n".join(menu_lines(st)))


def main():
    if "--setup" in sys.argv:
        run_setup()
        return
    cfg = load_config()
    if "--once" in sys.argv:
        run_once(cfg)
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
