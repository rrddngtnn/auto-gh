"""store.py — SQLite WAL state store for GitHub accounts, sticky proxy history, and 5-hour aging queue."""
from __future__ import annotations

import datetime
import sqlite3
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[2] / "auto_gh.db"

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    seed            TEXT UNIQUE NOT NULL,
    username        TEXT UNIQUE NOT NULL,
    email           TEXT UNIQUE NOT NULL,
    email_token     TEXT,
    email_provider  TEXT DEFAULT 'rest',
    password        TEXT NOT NULL,
    proxy_port      INTEGER NOT NULL,
    proxy_country   TEXT NOT NULL,
    exit_ip         TEXT,
    timezone        TEXT,
    locale          TEXT DEFAULT 'en-SG',
    storage_state   TEXT,
    status          TEXT DEFAULT 'staged',
    created_at      TEXT NOT NULL,
    verified_at     TEXT,
    cbai_paired_at  TEXT,
    kiro_paired_at  TEXT,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS ip_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    exit_ip     TEXT NOT NULL,
    proxy_port  INTEGER NOT NULL,
    country     TEXT,
    account_id  INTEGER REFERENCES accounts(id),
    seen_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER,
    kind        TEXT NOT NULL,
    detail      TEXT,
    ts          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_acc_status ON accounts(status, created_at);
CREATE INDEX IF NOT EXISTS ix_ip_exit ON ip_history(exit_ip, seen_at);
"""


def utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def open_db(path: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    con = sqlite3.connect(str(path), timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    con.commit()
    return con


def log_event(con: sqlite3.Connection, account_id: int | None, kind: str, detail: str = "") -> None:
    con.execute(
        "INSERT INTO events(account_id, kind, detail, ts) VALUES (?, ?, ?, ?)",
        (account_id, kind, detail[:500], utcnow()),
    )
    con.commit()


def ip_used_recently(con: sqlite3.Connection, exit_ip: str, days: int = 7, max_uses: int = 1) -> bool:
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    cnt = con.execute(
        "SELECT COUNT(*) FROM ip_history WHERE exit_ip = ? AND seen_at >= ?",
        (exit_ip, cutoff),
    ).fetchone()[0]
    return cnt >= max_uses


def record_ip(con: sqlite3.Connection, exit_ip: str, port: int, country: str, account_id: int | None = None) -> None:
    con.execute(
        "INSERT INTO ip_history(exit_ip, proxy_port, country, account_id, seen_at) VALUES (?, ?, ?, ?, ?)",
        (exit_ip, port, country, account_id, utcnow()),
    )
    con.commit()


def list_aged_ready(con: sqlite3.Connection, min_age_minutes: int = 305) -> list[dict]:
    """Return verified GitHub accounts aged >= min_age_minutes (default 5h05m) ready for CBAI pairing."""
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=min_age_minutes)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = con.execute(
        "SELECT * FROM accounts WHERE status = 'verified' "
        "AND verified_at IS NOT NULL AND verified_at <= ? AND cbai_paired_at IS NULL "
        "ORDER BY verified_at ASC",
        (cutoff,),
    ).fetchall()
    return [dict(r) for r in rows]


def summary_counts(con: sqlite3.Connection) -> dict:
    total = con.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
    by_status = {
        r["status"]: r["c"]
        for r in con.execute("SELECT status, COUNT(*) AS c FROM accounts GROUP BY status").fetchall()
    }
    cbai_ready = len(list_aged_ready(con))
    unique_ips = con.execute("SELECT COUNT(DISTINCT exit_ip) FROM ip_history").fetchone()[0]
    return {
        "total_accounts": total,
        "by_status": by_status,
        "aged_ready_for_cbai": cbai_ready,
        "unique_exit_ips": unique_ips,
    }
