"""bundle.py — Standardized SessionBundle JSON contract and .env loader for Unix-pipe composition."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import sys
from typing import TextIO


def load_dotenv_file(path: str | Path | None = None) -> None:
    """Load key=value pairs from .env without overriding already-set environment variables."""
    candidates = [Path(path)] if path else [Path.cwd() / ".env", Path(__file__).resolve().parents[2] / ".env"]
    for p in candidates:
        if not p.is_file():
            continue
        for raw_line in p.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("'").strip('"')
            if k and k not in os.environ:
                os.environ[k] = v
        break


@dataclass
class SessionBundle:
    version: str = "1.0"
    provider: str = "github"
    account_id: int | None = None
    username: str = ""
    email: str = ""
    created_at: str = ""
    verified_at: str | None = None
    country: str = "sg"
    timezone: str = "Asia/Singapore"
    locale: str = "en-SG"
    exit_ip: str = ""
    proxy_url: str = ""
    storage_state_path: str = ""
    cookies: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> "SessionBundle":
        valid = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid)

    @classmethod
    def from_row(cls, row: dict, proxy_url: str = "") -> "SessionBundle":
        cookies: dict[str, str] = {}
        st_path = row.get("storage_state") or ""
        if st_path and Path(st_path).is_file():
            try:
                raw = json.loads(Path(st_path).read_text(encoding="utf-8"))
                for c in raw.get("cookies", []):
                    if c.get("name") and c.get("value"):
                        cookies[c["name"]] = c["value"]
            except Exception:
                pass
        return cls(
            account_id=row.get("id"),
            username=row.get("username") or "",
            email=row.get("email") or "",
            created_at=row.get("created_at") or "",
            verified_at=row.get("verified_at"),
            country=row.get("proxy_country") or "sg",
            timezone=row.get("timezone") or "Asia/Singapore",
            locale=row.get("locale") or "en-SG",
            exit_ip=row.get("exit_ip") or "",
            proxy_url=proxy_url,
            storage_state_path=st_path,
            cookies=cookies,
        )


def emit_bundles(bundles: list[SessionBundle], stream: TextIO = sys.stdout, jsonl: bool = True) -> None:
    if jsonl:
        for b in bundles:
            stream.write(b.to_json() + "\n")
    else:
        stream.write(json.dumps([b.to_dict() for b in bundles], indent=2) + "\n")
    stream.flush()
