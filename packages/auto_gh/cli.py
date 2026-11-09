"""cli.py — CLI entry point for auto-gh (proxy pool, mailbox adapter, session bundle emitter, and 5h aging queue)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from .browser_profile import login_github_session, save_github_cookie_state, signup_github_session
from .bundle import SessionBundle, emit_bundles, load_dotenv_file
from .dns_doctor import audit_domain_pool
from .mailbox import MAILBOX_DRIVERS, get_mailbox_driver
from .netpool import StickyPortPool
from .panel import run_panel_server
from .store import list_aged_ready, log_event, open_db, summary_counts, utcnow


def cmd_status(args) -> None:
    con = open_db()
    print(json.dumps(summary_counts(con), indent=2))


def cmd_alloc_proxy(args) -> None:
    con = open_db()
    pool = StickyPortPool()
    seed = args.seed or f"seed-{int(time.time())}"
    slot = pool.allocate_clean_slot(con, seed=seed, country=args.country, ttl_minutes=args.ttl)
    print(
        json.dumps(
            {
                "port": slot.port,
                "country": slot.country,
                "ttl_minutes": slot.ttl_minutes,
                "exit_ip": slot.exit_ip,
                "timezone": slot.timezone,
                "locale": slot.locale,
                "isp": slot.isp,
                "server": slot.server,
                "username": slot.username,
            },
            indent=2,
        )
    )


def cmd_inbox_create(args) -> None:
    seed = args.seed or f"mail-{int(time.time())}"
    mb = get_mailbox_driver(args.mode)
    res = mb.create_inbox(seed, index=args.index, ttl=args.ttl)
    print(json.dumps(res, indent=2))


def cmd_stage_batch(args) -> None:
    """Allocate clean sticky proxy ports + BYOP mailbox addresses and stage accounts in SQLite."""
    con = open_db()
    pool = StickyPortPool()
    mb = get_mailbox_driver(args.mode)
    existing_count = con.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]

    staged = []
    for i in range(args.count):
        idx = existing_count + i
        seed = f"{int(time.time())}-{idx}"
        cc = pool.countries[idx % len(pool.countries)] if not args.country else args.country
        if args.probe_proxy:
            slot = pool.allocate_clean_slot(con, seed=seed, country=cc, ttl_minutes=args.ttl)
        else:
            slot = pool.slot_for_seed(seed, index=idx, ttl_minutes=args.ttl)
            if args.country:
                slot = pool.build_slot(port=slot.port, country=args.country, ttl_minutes=args.ttl)

        inbox = mb.create_inbox(seed, index=idx, ttl="30d")
        now = utcnow()
        cur = con.execute(
            """
            INSERT INTO accounts (
                seed, username, email, email_token, email_provider, password,
                proxy_port, proxy_country, exit_ip, timezone, locale, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'staged', ?)
            """,
            (
                seed,
                inbox["username"],
                inbox["address"],
                inbox["token"],
                inbox["provider"],
                inbox["password"],
                slot.port,
                slot.country,
                slot.exit_ip,
                slot.timezone,
                slot.locale,
                now,
            ),
        )
        acc_id = cur.lastrowid
        log_event(con, acc_id, "staged", f"email={inbox['address']} port={slot.port} cc={slot.country}")
        staged.append(
            {
                "id": acc_id,
                "username": inbox["username"],
                "email": inbox["address"],
                "password": inbox["password"],
                "proxy_port": slot.port,
                "country": slot.country,
                "exit_ip": slot.exit_ip,
                "timezone": slot.timezone,
            }
        )
    print(json.dumps({"staged_count": len(staged), "accounts": staged}, indent=2))


def cmd_inbox_poll(args) -> None:
    mb = get_mailbox_driver(args.mode)
    code, msg = mb.poll_otp(args.address, args.token, timeout_sec=args.timeout)
    print(json.dumps({"otp": code, "subject": msg.get("subject") if msg else None}, indent=2))


def cmd_aging_queue(args) -> None:
    con = open_db()
    rows = list_aged_ready(con, min_age_minutes=args.min_minutes)
    print(json.dumps({"ready_count": len(rows), "accounts": rows}, indent=2))


def cmd_export_sessions(args) -> None:
    con = open_db()
    pool = StickyPortPool()
    if args.aged_only:
        rows = list_aged_ready(con, min_age_minutes=args.min_minutes)
    elif args.account_id is not None:
        r = con.execute("SELECT * FROM accounts WHERE id = ?", (args.account_id,)).fetchone()
        rows = [dict(r)] if r else []
    else:
        rows = [dict(r) for r in con.execute("SELECT * FROM accounts WHERE status = 'verified' ORDER BY id").fetchall()]

    bundles = []
    for row in rows:
        slot = pool.build_slot(port=row["proxy_port"], country=row["proxy_country"])
        bundles.append(SessionBundle.from_row(row, proxy_url=slot.url))
    emit_bundles(bundles, stream=sys.stdout, jsonl=not args.pretty)


def main(argv: list[str] | None = None) -> int:
    load_dotenv_file()
    p = argparse.ArgumentParser(prog="auto-gh")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_st = sub.add_parser("status", help="Show SQLite account and IP pool summary")
    s_st.set_defaults(func=cmd_status)

    s_ap = sub.add_parser("alloc-proxy", help="Allocate and verify a clean sticky proxy port")
    s_ap.add_argument("--seed", default="")
    s_ap.add_argument("--country", default="sg")
    s_ap.add_argument("--ttl", type=int, default=30)
    s_ap.set_defaults(func=cmd_alloc_proxy)

    s_ic = sub.add_parser("inbox-create", help="Create a dedicated or catch-all inbox + deterministic credentials")
    s_ic.add_argument("--seed", default="")
    s_ic.add_argument("--mode", choices=(*MAILBOX_DRIVERS, "catchall"), default="")
    s_ic.add_argument("--index", type=int, default=0)
    s_ic.add_argument("--ttl", default="30d")
    s_ic.set_defaults(func=cmd_inbox_create)

    s_sb = sub.add_parser("stage-batch", help="Stage a batch of accounts with BYOP mailbox and sticky proxy drivers")
    s_sb.add_argument("--count", type=int, default=4)
    s_sb.add_argument("--mode", choices=(*MAILBOX_DRIVERS, "catchall"), default="")
    s_sb.add_argument("--country", default="")
    s_sb.add_argument("--ttl", type=int, default=30)
    s_sb.add_argument("--probe-proxy", action="store_true", help="Probe ipinfo.io live on each allocated port")
    s_sb.set_defaults(func=cmd_stage_batch)

    s_ip = sub.add_parser("inbox-poll", help="Poll an inbox for 6/8-digit OTP")
    s_ip.add_argument("--address", required=True)
    s_ip.add_argument("--token", default="")
    s_ip.add_argument("--mode", choices=(*MAILBOX_DRIVERS, "catchall"), default="")
    s_ip.add_argument("--timeout", type=int, default=60)
    s_ip.set_defaults(func=cmd_inbox_poll)

    s_dr = sub.add_parser("doctor", help="Inspect declared BYOP drivers (proxy, mailbox, browser) and readiness")
    s_dr.set_defaults(func=cmd_doctor)

    s_aq = sub.add_parser("aging-queue", help="List verified accounts aged >= 5h05m ready for CBAI pairing")
    s_aq.add_argument("--min-minutes", type=int, default=305)
    s_aq.set_defaults(func=cmd_aging_queue)

    s_ex = sub.add_parser("export-sessions", help="Emit standardized SessionBundle JSON/JSONL to stdout for piping to auto-kr / auto-cb")
    s_ex.add_argument("--account-id", type=int, default=None)
    s_ex.add_argument("--aged-only", action="store_true")
    s_ex.add_argument("--min-minutes", type=int, default=305)
    s_ex.add_argument("--pretty", action="store_true")
    s_ex.set_defaults(func=cmd_export_sessions)

    s_dc = sub.add_parser("domain-check", help="Run read-only DoH DNS legitimacy & cross-domain correlation audit")
    s_dc.add_argument("--domains", default="", help="Comma-separated domains (defaults to CATCHALL_DOMAINS in .env)")
    s_dc.set_defaults(func=cmd_domain_check)

    s_pn = sub.add_parser("panel", help="Launch standalone dark-themed HTTP control panel")
    s_pn.add_argument("--host", default="127.0.0.1")
    s_pn.add_argument("--port", type=int, default=8790)
    s_pn.set_defaults(func=cmd_panel)

    s_ic2 = sub.add_parser("import-cookie", help="Save GitHub user_session / Cookie header / storage_state JSON for an account")
    s_ic2.add_argument("--account-id", type=int, required=True)
    s_ic2.add_argument("--cookie", required=True, help="Raw user_session value, Cookie header, or JSON")
    s_ic2.set_defaults(func=cmd_import_cookie)

    s_lg = sub.add_parser("login-session", help="Log into github.com/login via Camoufox + sticky proxy + auto OTP poll and save storage_state")
    s_lg.add_argument("--account-id", type=int, required=True)
    s_lg.add_argument("--headless", action="store_true")
    s_lg.set_defaults(func=cmd_login_session)

    s_su = sub.add_parser("signup", help="Execute end-to-end automated GitHub registration + OTP verification + session capture")
    s_su.add_argument("--account-id", type=int, required=True)
    s_su.add_argument("--headless", action="store_true")
    s_su.add_argument("--otp-timeout", type=int, default=120)
    s_su.set_defaults(func=cmd_signup)

    args = p.parse_args(argv)
    args.func(args)
    return 0


def cmd_domain_check(args) -> None:
    doms = [d.strip() for d in args.domains.split(",") if d.strip()] if args.domains else None
    print(json.dumps(audit_domain_pool(domains=doms), indent=2))


def cmd_panel(args) -> None:
    run_panel_server(host=args.host, port=args.port)


def cmd_import_cookie(args) -> None:
    con = open_db()
    row = con.execute("SELECT * FROM accounts WHERE id = ?", (args.account_id,)).fetchone()
    if not row:
        raise SystemExit(f"Account #{args.account_id} not found")
    st_path = save_github_cookie_state(row["username"], args.cookie)
    ver_at = row["verified_at"] or utcnow()
    con.execute(
        "UPDATE accounts SET storage_state = ?, status = 'verified', verified_at = ? WHERE id = ?",
        (str(st_path), ver_at, args.account_id),
    )
    con.commit()
    log_event(con, args.account_id, "cookie_imported", str(st_path))
    print(json.dumps({"ok": True, "account_id": args.account_id, "storage_state": str(st_path)}, indent=2))


def cmd_login_session(args) -> None:
    con = open_db()
    row = con.execute("SELECT * FROM accounts WHERE id = ?", (args.account_id,)).fetchone()
    if not row:
        raise SystemExit(f"Account #{args.account_id} not found")
    pool = StickyPortPool()
    slot = pool.build_slot(port=row["proxy_port"], country=row["proxy_country"])
    pool.probe_slot(slot, timeout=8)
    mb = get_mailbox_driver(row["email_provider"])
    res = login_github_session(dict(row), slot, mailbox_driver=mb, headless=args.headless)
    if res.get("ok"):
        ver_at = row["verified_at"] or utcnow()
        con.execute(
            "UPDATE accounts SET storage_state = ?, status = 'verified', verified_at = ? WHERE id = ?",
            (res["storage_state"], ver_at, args.account_id),
        )
        con.commit()
        log_event(con, args.account_id, "session_saved", res["storage_state"])
    print(json.dumps(res, indent=2))


def cmd_signup(args) -> None:
    import shutil
    import subprocess

    if os.name == "posix" and not args.headless and not os.environ.get("DISPLAY") and shutil.which("xvfb-run"):
        cmd = [
            "xvfb-run",
            "-a",
            sys.executable,
            "-m",
            "auto_gh.cli",
            "signup",
            "--account-id",
            str(args.account_id),
            "--otp-timeout",
            str(args.otp_timeout),
        ]
        proc = subprocess.run(cmd)
        raise SystemExit(proc.returncode)

    con = open_db()
    row = con.execute("SELECT * FROM accounts WHERE id = ?", (args.account_id,)).fetchone()
    if not row:
        raise SystemExit(f"Account #{args.account_id} not found")
    pool = StickyPortPool()
    slot = pool.build_slot(port=row["proxy_port"], country=row["proxy_country"])
    pool.probe_slot(slot, timeout=8)
    mb = get_mailbox_driver(row["email_provider"])
    res = signup_github_session(
        dict(row),
        slot,
        mailbox_driver=mb,
        headless=args.headless,
        otp_timeout_sec=args.otp_timeout,
    )
    if res.get("ok"):
        ver_at = utcnow()
        con.execute(
            "UPDATE accounts SET username = ?, storage_state = ?, status = 'verified', verified_at = ? WHERE id = ?",
            (res["username"], res["storage_state"], ver_at, args.account_id),
        )
        con.commit()
        log_event(con, args.account_id, "signup_verified", f"user={res['username']} state={res['storage_state']}")
    elif res.get("stage") == "suspended":
        con.execute(
            "UPDATE accounts SET username = ?, status = 'suspended' WHERE id = ?",
            (res["username"], args.account_id),
        )
        con.commit()
        log_event(con, args.account_id, "signup_suspended", f"user={res['username']} url={res.get('url')}")
    else:
        log_event(con, args.account_id, "signup_attempt", f"stage={res.get('stage')} url={res.get('url')}")
    print(json.dumps(res, indent=2), flush=True)


def cmd_doctor(args) -> None:
    pool = StickyPortPool()
    mb_driver = os.environ.get("MAILBOX_DRIVER", "forwarded_rest")
    doms = [d.strip() for d in os.environ.get("CATCHALL_DOMAINS", "").split(",") if d.strip()]
    print(
        json.dumps(
            {
                "ok": True,
                "declared_contracts": {
                    "proxy_driver": {
                        "active": pool.driver,
                        "supported": ["template", "file", "single", "direct"],
                        "host_configured": pool.host != "proxy.example.test",
                    },
                    "mailbox_driver": {
                        "active": mb_driver,
                        "supported": list(MAILBOX_DRIVERS),
                        "catchall_domain_count": len(doms),
                    },
                    "emitter_contract": {
                        "format": "SessionBundle JSONL (v1.0)",
                        "consumers": ["auto-kr", "auto-cb", "custom-stdin-consumer"],
                    },
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
