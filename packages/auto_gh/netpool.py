"""netpool.py — Pluggable proxy allocator (URI template, static list file, or direct) + GeoIP/timezone resolver."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlparse
import requests

from .bundle import load_dotenv_file
from .store import ip_used_recently, record_ip

load_dotenv_file()

DEFAULT_TEMPLATE = os.environ.get(
    "PROXY_TEMPLATE",
    "http://{user}__cr.{country};sessttl.{ttl}:{password}@{host}:{port}",
)
DEFAULT_HOST = os.environ.get("PROXY_HOST", "proxy.example.test")
DEFAULT_USER = os.environ.get("PROXY_USER", "proxy_user")
DEFAULT_PASS = os.environ.get("PROXY_PASS", "proxy_pass")
PORT_MIN = int(os.environ.get("PROXY_PORT_MIN", "10000"))
PORT_MAX = int(os.environ.get("PROXY_PORT_MAX", "29999"))
PORT_SPAN = max(1, PORT_MAX - PORT_MIN + 1)

# Whitelisted APAC regions for downstream CBAI compatibility
COUNTRIES = ("sg", "id", "jp", "th", "my", "ph", "hk")

COUNTRY_LOCALE_FALLBACK = {
    "sg": ("en-SG", "Asia/Singapore"),
    "id": ("id-ID", "Asia/Jakarta"),
    "jp": ("ja-JP", "Asia/Tokyo"),
    "th": ("th-TH", "Asia/Bangkok"),
    "my": ("en-MY", "Asia/Kuala_Lumpur"),
    "ph": ("en-PH", "Asia/Manila"),
    "hk": ("en-HK", "Asia/Hong_Kong"),
    "us": ("en-US", "America/New_York"),
}


@dataclass
class StickySlot:
    port: int
    country: str
    ttl_minutes: int
    server: str
    username: str
    password: str
    exit_ip: str = ""
    timezone: str = ""
    locale: str = "en-SG"
    isp: str = ""

    @property
    def url(self) -> str:
        if not self.server:
            return ""
        if self.username and self.password:
            return f"http://{self.username}:{self.password}@{self.host_port}"
        return self.server

    @property
    def host_port(self) -> str:
        return self.server.replace("http://", "").replace("https://", "")

    def playwright_proxy(self) -> dict | None:
        if not self.server:
            return None
        d = {"server": self.server}
        if self.username:
            d["username"] = self.username
        if self.password:
            d["password"] = self.password
        return d

    @classmethod
    def from_url(cls, proxy_url: str, country: str = "sg", ttl_minutes: int = 30) -> "StickySlot":
        parsed = urlparse(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
        scheme = parsed.scheme or "http"
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8080
        loc, tz = COUNTRY_LOCALE_FALLBACK.get(country.lower(), ("en-US", "UTC"))
        return cls(
            port=port,
            country=country.lower(),
            ttl_minutes=ttl_minutes,
            server=f"{scheme}://{host}:{port}",
            username=parsed.username or "",
            password=parsed.password or "",
            timezone=tz,
            locale=loc,
        )


class StickyPortPool:
    """BYOP Proxy Pool supporting PROXY_DRIVER = template | file | single | direct."""

    def __init__(
        self,
        host: str | None = None,
        base_user: str | None = None,
        password: str | None = None,
        template: str | None = None,
        proxy_file: str | Path | None = None,
        proxy_url: str | None = None,
        driver: str | None = None,
        countries: tuple[str, ...] = COUNTRIES,
    ):
        load_dotenv_file()
        self.driver = (driver or os.environ.get("PROXY_DRIVER") or "").lower()
        self.host = host or os.environ.get("PROXY_HOST") or DEFAULT_HOST
        raw_user = base_user or os.environ.get("PROXY_USER") or DEFAULT_USER
        self.base_user = raw_user.split(";")[0].split("__")[0]
        self.password = password or os.environ.get("PROXY_PASS") or DEFAULT_PASS
        self.template = template or os.environ.get("PROXY_TEMPLATE") or DEFAULT_TEMPLATE
        self.single_url = proxy_url or os.environ.get("PROXY_URL") or ""
        self.countries = countries
        self.static_list = self._load_static(proxy_file or os.environ.get("PROXY_FILE"))
        if not self.driver:
            if self.static_list:
                self.driver = "file"
            elif self.single_url:
                self.driver = "single"
            else:
                self.driver = "template"

    @staticmethod
    def _load_static(path: str | Path | None) -> list[str]:
        if not path:
            return []
        p = Path(path)
        if not p.is_file():
            return []
        text = p.read_text(encoding="utf-8").strip()
        if p.suffix == ".json":
            data = json.loads(text)
            items = data.get("proxies", data) if isinstance(data, dict) else data
            return [x["url"] if isinstance(x, dict) else str(x) for x in items]
        return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]

    def build_slot(self, port: int, country: str = "sg", ttl_minutes: int = 30) -> StickySlot:
        cc = country.lower()
        ttl = max(1, min(int(ttl_minutes), 120))
        loc, tz = COUNTRY_LOCALE_FALLBACK.get(cc, ("en-US", "UTC"))
        if self.driver == "direct":
            return StickySlot(
                port=0,
                country=cc,
                ttl_minutes=ttl,
                server="",
                username="",
                password="",
                timezone=tz,
                locale=loc,
            )
        if self.driver == "single" and self.single_url:
            return StickySlot.from_url(self.single_url, country=cc, ttl_minutes=ttl)
        if self.static_list:
            chosen = self.static_list[(port - PORT_MIN) % len(self.static_list)]
            return StickySlot.from_url(chosen, country=cc, ttl_minutes=ttl)
        if not (PORT_MIN <= port <= PORT_MAX):
            port = PORT_MIN + ((port - PORT_MIN) % PORT_SPAN)
        rendered = self.template.format(
            user=self.base_user,
            password=self.password,
            host=self.host,
            port=port,
            country=cc,
            ttl=ttl,
        )
        return StickySlot.from_url(rendered, country=cc, ttl_minutes=ttl)

    def slot_for_seed(self, seed: str, index: int = 0, ttl_minutes: int = 30) -> StickySlot:
        digest = int(hashlib.sha256(f"{seed}:{index}".encode()).hexdigest()[:12], 16)
        port = PORT_MIN + (digest % PORT_SPAN)
        cc = self.countries[index % len(self.countries)]
        return self.build_slot(port=port, country=cc, ttl_minutes=ttl_minutes)

    def probe_slot(
        self,
        slot: StickySlot,
        timeout: int = 12,
        ipinfo_url: str = "https://ipinfo.io/json",
    ) -> StickySlot:
        proxies = {"http": slot.url, "https": slot.url} if slot.url else None
        r = requests.get(ipinfo_url, proxies=proxies, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        slot.exit_ip = data.get("ip", "")
        if data.get("timezone"):
            slot.timezone = data["timezone"]
        slot.isp = data.get("org", "")
        cc = (data.get("country") or slot.country).lower()
        slot.locale = COUNTRY_LOCALE_FALLBACK.get(cc, (slot.locale, slot.timezone))[0]
        return slot

    def allocate_clean_slot(
        self,
        con,
        seed: str,
        country: str | None = None,
        ttl_minutes: int = 30,
        max_attempts: int = 8,
        ipinfo_url: str = "https://ipinfo.io/json",
    ) -> StickySlot:
        base_slot = self.slot_for_seed(seed, ttl_minutes=ttl_minutes)
        cc = (country or base_slot.country).lower()
        for attempt in range(max_attempts):
            port = PORT_MIN + ((base_slot.port - PORT_MIN + attempt) % PORT_SPAN)
            slot = self.build_slot(port=port, country=cc, ttl_minutes=ttl_minutes)
            try:
                self.probe_slot(slot, ipinfo_url=ipinfo_url)
            except Exception:
                continue
            if not slot.exit_ip:
                continue
            if not ip_used_recently(con, slot.exit_ip):
                record_ip(con, slot.exit_ip, slot.port, slot.country)
                return slot
        raise RuntimeError(f"Failed to allocate clean sticky IP after {max_attempts} ports")
