"""mailbox.py — Pluggable OTP & verification link adapters (REST OpenAPI inbox, IMAP catch-all, or custom domain pool)."""
from __future__ import annotations

import email
import hashlib
import imaplib
import os
import random
import re
import time
import requests

from .bundle import load_dotenv_file

load_dotenv_file()

DEFAULT_MAILBOX_API = os.environ.get("MAILBOX_API_URL", "http://127.0.0.1:8789")
UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) "
    "Gecko/20100101 Firefox/136.0"
)

OTP_PATTERNS = (
    r"\b(\d{8})\b",  # GitHub 8-digit launch code
    r"\b(\d{6})\b",  # Standard 6-digit OTP
)


def make_credentials(seed: str) -> dict:
    h = hashlib.sha256(seed.encode()).hexdigest()
    words = (
        "novak", "rava", "kelby", "orin", "zephyr", "marlow", "quill", "sable",
        "tenzin", "fable", "gable", "harlow", "irwin", "jasper", "keaton",
        "landry", "moss", "nolan", "otter", "pascal", "quinn", "rivers", "silas",
        "tobin", "ulric", "vance", "wren", "xander", "yates", "zane",
    )
    w = words[int(h[:4], 16) % len(words)]
    suffix = h[4:10]
    username = f"{w}{suffix}"
    pw_num = int(h[10:14], 16) % 9000 + 1000
    password = f"GnawWire{pw_num}!{h[14:18]}"
    return {"username": username, "password": password, "handle": f"{w}{h[16:22]}"}


class RestMailboxAdapter:
    """Universal adapter for OpenAPI-style disposable inbox services (POST /api/inbox, GET /api/inbox/{addr}/messages)."""

    def __init__(self, base: str | None = None, timeout: int = 25):
        load_dotenv_file()
        self.base = (base or os.environ.get("MAILBOX_API_URL") or DEFAULT_MAILBOX_API).rstrip("/")
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": UA, "Accept": "application/json"})

    def create_inbox(self, seed: str, index: int = 0, ttl: str = "30d") -> dict:
        creds = make_credentials(seed)
        for attempt in range(6):
            name = f"{creds['handle']}{attempt if attempt else ''}"
            r = self.s.post(
                f"{self.base}/api/inbox",
                json={"name": name, "ttl": ttl},
                timeout=self.timeout,
            )
            if r.status_code == 409:
                continue
            r.raise_for_status()
            data = r.json()
            return {
                "address": data["address"],
                "token": data["token"],
                "expires_at": data.get("expiresAt"),
                "username": creds["username"],
                "password": creds["password"],
                "provider": "rest",
            }
        r = self.s.post(f"{self.base}/api/inbox", json={"ttl": ttl}, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        return {
            "address": data["address"],
            "token": data["token"],
            "expires_at": data.get("expiresAt"),
            "username": creds["username"],
            "password": creds["password"],
            "provider": "rest",
        }

    def list_messages(self, address: str, token: str, limit: int = 50) -> list[dict]:
        r = self.s.get(
            f"{self.base}/api/inbox/{address}/messages",
            params={"limit": limit},
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json().get("messages", [])

    def get_message(self, address: str, token: str, msg_id: str) -> dict:
        r = self.s.get(
            f"{self.base}/api/inbox/{address}/messages/{msg_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def get_raw_message(self, address: str, token: str, msg_id: str) -> str:
        r = self.s.get(
            f"{self.base}/api/inbox/{address}/messages/{msg_id}/raw",
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.timeout,
        )
        if r.status_code != 200:
            return ""
        return r.text

    def poll_otp(
        self,
        address: str,
        token: str,
        timeout_sec: int = 180,
        poll_sec: float = 5.0,
        patterns: tuple[str, ...] = OTP_PATTERNS,
        exclude_codes: set[str] | None = None,
    ) -> tuple[str | None, dict | None]:
        """Poll dedicated inbox without post-signup timestamp truncation."""
        compiled = [re.compile(p) for p in patterns]
        excluded = set(exclude_codes or ())
        seen: set[str] = set()
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            try:
                for m in self.list_messages(address, token):
                    mid = m["id"]
                    if mid in seen:
                        continue
                    seen.add(mid)
                    detail = self.get_message(address, token, mid)
                    raw = (detail.get("body") or "") + " " + (detail.get("html") or "")
                    clean = re.sub(r"<[^>]+>", " ", raw)
                    for pat in compiled:
                        hit = pat.search(clean)
                        if hit and hit.group(1) not in excluded:
                            return hit.group(1), detail
            except requests.RequestException:
                pass
            time.sleep(poll_sec)
        return None, None


class ImapCatchAllAdapter:
    """Universal IMAP catch-all mailbox adapter supporting multi-domain round-robin rotation."""

    def __init__(
        self,
        host: str | None = None,
        user: str | None = None,
        password: str | None = None,
        domains: list[str] | None = None,
        port: int = 993,
    ):
        load_dotenv_file()
        self.host = host or os.environ.get("IMAP_HOST", "imap.example.test")
        self.user = user or os.environ.get("IMAP_USER", "catchall@example.test")
        self.password = password or os.environ.get("IMAP_PASS", "")
        raw_doms = os.environ.get("CATCHALL_DOMAINS", "alpha.example.test,beta.example.test")
        self.domains = domains or [d.strip() for d in raw_doms.split(",") if d.strip()]
        self.port = port

    def create_inbox(self, seed: str, index: int = 0, ttl: str = "30d") -> dict:
        creds = make_credentials(seed)
        dom = self.domains[index % len(self.domains)]
        return {
            "address": f"{creds['handle']}@{dom}",
            "token": f"imap:{self.user}",
            "expires_at": None,
            "username": creds["username"],
            "password": creds["password"],
            "provider": "imap",
        }

    def poll_otp(
        self,
        address: str,
        token: str = "",
        timeout_sec: int = 180,
        poll_sec: float = 5.0,
        patterns: tuple[str, ...] = OTP_PATTERNS,
        exclude_codes: set[str] | None = None,
    ) -> tuple[str | None, dict | None]:
        compiled = [re.compile(p) for p in patterns]
        excluded = set(exclude_codes or ())
        target = address.lower()
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            try:
                with imaplib.IMAP4_SSL(self.host, self.port) as M:
                    M.login(self.user, self.password)
                    M.select("INBOX", readonly=True)
                    _, data = M.search(None, "ALL")
                    ids = (data[0] or b"").split()[-25:]
                    for num in reversed(ids):
                        num_str = num.decode("ascii", errors="ignore") if isinstance(num, bytes) else str(num)
                        _, msg_data = M.fetch(num_str, "(RFC822)")
                        if not msg_data or not isinstance(msg_data[0], tuple):
                            continue
                        raw_bytes = msg_data[0][1]
                        if not isinstance(raw_bytes, (bytes, bytearray)):
                            continue
                        msg = email.message_from_bytes(raw_bytes)
                        to_hdr = (msg.get("To") or "").lower()
                        if target not in to_hdr:
                            continue
                        parts = []
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() in ("text/plain", "text/html"):
                                    payload = part.get_payload(decode=True)
                                    if isinstance(payload, (bytes, bytearray)):
                                        parts.append(payload.decode("utf-8", errors="ignore"))
                        else:
                            payload = msg.get_payload(decode=True)
                            if isinstance(payload, (bytes, bytearray)):
                                parts.append(payload.decode("utf-8", errors="ignore"))
                        clean = re.sub(r"<[^>]+>", " ", " ".join(parts))
                        for pat in compiled:
                            hit = pat.search(clean)
                            if hit and hit.group(1) not in excluded:
                                return hit.group(1), {"subject": msg.get("Subject", "")}
            except Exception:
                pass
            time.sleep(poll_sec)
        return None, None


class SqliteInboxAdapter:
    """BYOP SQLite mailbox adapter reading from a local inbox_messages(recipient, subject, body, received_at) table."""

    def __init__(self, db_path: str | None = None, domains: list[str] | None = None):
        load_dotenv_file()
        self.db_path = db_path or os.environ.get("MAILBOX_DB_PATH", "./inbox.db")
        raw_doms = os.environ.get("CATCHALL_DOMAINS", "alpha.example.test,beta.example.test")
        self.domains = domains or [d.strip() for d in raw_doms.split(",") if d.strip()]

    def create_inbox(self, seed: str, index: int = 0, ttl: str = "30d") -> dict:
        creds = make_credentials(seed)
        dom = self.domains[index % len(self.domains)]
        return {
            "address": f"{creds['handle']}@{dom}",
            "token": f"sqlite:{self.db_path}",
            "domain": dom,
            "expires_at": None,
            "username": creds["username"],
            "password": creds["password"],
            "provider": "sqlite",
        }

    def poll_otp(
        self,
        address: str,
        token: str | None = None,
        timeout_sec: int = 180,
        poll_sec: float = 2.0,
        patterns: tuple[str, ...] = OTP_PATTERNS,
        exclude_codes: set[str] | None = None,
    ) -> tuple[str | None, dict | None]:
        import sqlite3

        compiled = [re.compile(p) for p in patterns]
        excluded = set(exclude_codes or ())
        target = address.lower()
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            try:
                con = sqlite3.connect(self.db_path, timeout=10)
                con.row_factory = sqlite3.Row
                rows = con.execute(
                    "SELECT * FROM inbox_messages ORDER BY id DESC LIMIT 50"
                ).fetchall()
                con.close()
                for r in rows:
                    d = dict(r)
                    rcpt = str(d.get("recipient") or d.get("to_addr") or d.get("address") or "").lower()
                    if target not in rcpt:
                        continue
                    raw = str(d.get("body") or "") + " " + str(d.get("html") or "") + " " + str(d.get("subject") or "")
                    clean = re.sub(r"<[^>]+>", " ", raw)
                    for pat in compiled:
                        hit = pat.search(clean)
                        if hit and hit.group(1) not in excluded:
                            return hit.group(1), {"subject": d.get("subject", "")}
            except Exception:
                pass
            time.sleep(poll_sec)
        return None, None


class ManualMailboxAdapter:
    """BYOP Manual mailbox adapter for operator-supplied addresses and OTPs."""

    def __init__(self, domains: list[str] | None = None):
        load_dotenv_file()
        raw_doms = os.environ.get("CATCHALL_DOMAINS", "alpha.example.test,beta.example.test")
        self.domains = domains or [d.strip() for d in raw_doms.split(",") if d.strip()]

    def create_inbox(self, seed: str, index: int = 0, ttl: str = "30d") -> dict:
        creds = make_credentials(seed)
        dom = self.domains[index % len(self.domains)]
        return {
            "address": f"{creds['handle']}@{dom}",
            "token": "manual",
            "domain": dom,
            "expires_at": None,
            "username": creds["username"],
            "password": creds["password"],
            "provider": "manual",
        }

    def poll_otp(
        self,
        address: str,
        token: str | None = None,
        timeout_sec: int = 180,
        poll_sec: float = 2.0,
        patterns: tuple[str, ...] = OTP_PATTERNS,
        exclude_codes: set[str] | None = None,
    ) -> tuple[str | None, dict | None]:
        excluded = set(exclude_codes or ())
        otp = os.environ.get("MANUAL_OTP", "").strip()
        if otp and otp not in excluded:
            return otp, {"subject": "manual_env"}
        return None, None


class GmailDotAdapter(ImapCatchAllAdapter):
    """BYOP Gmail dot-alias IMAP adapter (generates deterministic dotted aliases from GMAIL_ADDRESS)."""

    def __init__(
        self,
        address: str | None = None,
        app_password: str | None = None,
        host: str = "imap.gmail.com",
        port: int = 993,
    ):
        load_dotenv_file()
        base_addr = (address or os.environ.get("GMAIL_ADDRESS") or "user@gmail.com").strip().lower()
        app_pw = (app_password or os.environ.get("GMAIL_APP_PASSWORD") or "").replace(" ", "")
        local, _, dom = base_addr.partition("@")
        self.clean_local = local.replace(".", "")
        self.gmail_domain = dom or "gmail.com"
        super().__init__(host=host, user=base_addr, password=app_pw, domains=[self.gmail_domain], port=port)

    def _dot_variant(self, seed: str, index: int = 0) -> str:
        s = self.clean_local
        if len(s) <= 1:
            return f"{s}@{self.gmail_domain}"
        slots = len(s) - 1
        h = int(hashlib.sha256(f"{seed}:{index}".encode()).hexdigest()[:8], 16)
        mask = (h % ((1 << slots) - 1)) + 1
        out = [s[0]]
        for i in range(slots):
            if (mask >> i) & 1:
                out.append(".")
            out.append(s[i + 1])
        return f"{''.join(out)}@{self.gmail_domain}"

    def create_inbox(self, seed: str, index: int = 0, ttl: str = "30d") -> dict:
        creds = make_credentials(seed)
        alias = self._dot_variant(seed, index=index)
        return {
            "address": alias,
            "token": f"gmail_dot:{self.user}",
            "domain": self.gmail_domain,
            "expires_at": None,
            "username": creds["username"],
            "password": creds["password"],
            "provider": "gmail_dot",
        }


MAILBOX_DRIVERS = ("forwarded_rest", "rest", "imap", "gmail_dot", "sqlite", "manual")


def get_mailbox_driver(driver_name: str | None = None):
    """Instantiate the configured BYOP mailbox driver."""
    load_dotenv_file()
    kind = (driver_name or os.environ.get("MAILBOX_DRIVER") or "forwarded_rest").lower()
    if kind in ("forwarded_rest", "catchall"):
        return ForwardedRestCatchAllAdapter()
    if kind == "rest":
        return RestMailboxAdapter()
    if kind == "imap":
        return ImapCatchAllAdapter()
    if kind == "gmail_dot":
        return GmailDotAdapter()
    if kind == "sqlite":
        return SqliteInboxAdapter()
    if kind == "manual":
        return ManualMailboxAdapter()
    raise ValueError(f"Unsupported MAILBOX_DRIVER '{kind}'. Valid drivers: {', '.join(MAILBOX_DRIVERS)}")


class ForwardedRestCatchAllAdapter:
    """Universal adapter for catch-all custom domains forwarded to per-domain or master REST inboxes."""

    def __init__(
        self,
        master_address: str | None = None,
        master_token: str | None = None,
        domains: list[str] | None = None,
        route_map: dict[str, dict] | None = None,
        base: str | None = None,
    ):
        import json

        load_dotenv_file()
        self.rest = RestMailboxAdapter(base=base)
        self.master_address = master_address or os.environ.get("CATCHALL_MASTER_ADDRESS", "master@example.test")
        self.master_token = master_token or os.environ.get("CATCHALL_MASTER_TOKEN", "master_token")
        raw_map = os.environ.get("CATCHALL_ROUTE_MAP_JSON", "")
        if route_map is not None:
            self.route_map = route_map
        elif raw_map:
            try:
                self.route_map = json.loads(raw_map)
            except Exception:
                self.route_map = {}
        else:
            self.route_map = {}
        raw_doms = os.environ.get("CATCHALL_DOMAINS", "alpha.example.test,beta.example.test")
        self.domains = domains or list(self.route_map.keys()) or [d.strip() for d in raw_doms.split(",") if d.strip()]

    def _route_for_domain(self, domain: str) -> tuple[str, str]:
        entry = self.route_map.get(domain) or {}
        return (
            entry.get("address") or self.master_address,
            entry.get("token") or self.master_token,
        )

    def create_inbox(self, seed: str, index: int = 0, ttl: str = "30d") -> dict:
        creds = make_credentials(seed)
        dom = self.domains[index % len(self.domains)]
        m_addr, m_tok = self._route_for_domain(dom)
        return {
            "address": f"{creds['handle']}@{dom}",
            "token": m_tok,
            "master_address": m_addr,
            "domain": dom,
            "expires_at": None,
            "username": creds["username"],
            "password": creds["password"],
            "provider": "forwarded_rest",
        }

    def poll_otp(
        self,
        address: str,
        token: str | None = None,
        timeout_sec: int = 180,
        poll_sec: float = 5.0,
        patterns: tuple[str, ...] = OTP_PATTERNS,
        exclude_codes: set[str] | None = None,
    ) -> tuple[str | None, dict | None]:
        """Poll the domain's mapped REST inbox and filter messages matching recipient address."""
        compiled = [re.compile(p) for p in patterns]
        excluded = set(exclude_codes or ())
        target = address.lower()
        dom = target.split("@", 1)[1] if "@" in target else ""
        m_addr, m_tok = self._route_for_domain(dom)
        tok = token or m_tok
        seen: set[str] = set()
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            try:
                for m in self.rest.list_messages(m_addr, tok):
                    mid = m["id"]
                    if mid in seen:
                        continue
                    seen.add(mid)
                    detail = self.rest.get_message(m_addr, tok, mid)
                    raw = (
                        str(detail.get("toAlias") or "")
                        + " "
                        + str(detail.get("body") or "")
                        + " "
                        + str(detail.get("html") or "")
                    )
                    if target not in raw.lower():
                        if detail.get("hasRaw"):
                            raw_mime = self.rest.get_raw_message(m_addr, tok, mid)
                            if target not in raw_mime.lower():
                                continue
                        else:
                            continue
                    clean = re.sub(r"<[^>]+>", " ", str(detail.get("body") or "") + " " + str(detail.get("html") or ""))
                    for pat in compiled:
                        hit = pat.search(clean)
                        if hit and hit.group(1) not in excluded:
                            return hit.group(1), detail
            except requests.RequestException:
                pass
            time.sleep(poll_sec)
        return None, None
