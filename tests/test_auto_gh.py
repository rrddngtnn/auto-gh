import io
import json
import os
import tempfile

from auto_gh.browser_profile import build_camoufox_config
from auto_gh.bundle import SessionBundle, emit_bundles
from auto_gh.dns_doctor import audit_domain_pool
from auto_gh.mailbox import (
    ForwardedRestCatchAllAdapter,
    GmailDotAdapter,
    ImapCatchAllAdapter,
    ManualMailboxAdapter,
    RestMailboxAdapter,
    SqliteInboxAdapter,
    get_mailbox_driver,
    make_credentials,
)
from auto_gh.netpool import StickyPortPool, StickySlot
from auto_gh.panel import handle_api_request
from auto_gh.store import ip_used_recently, list_aged_ready, open_db, record_ip, summary_counts


def test_store_and_identity():
    with tempfile.TemporaryDirectory() as tmp:
        con = open_db(os.path.join(tmp, "test.db"))
        c1 = make_credentials("seed-alpha-1")
        c2 = make_credentials("seed-alpha-1")
        assert c1 == c2 and len(c1["username"]) >= 8
        assert not ip_used_recently(con, "198.51.100.42")
        record_ip(con, "198.51.100.42", 10001, "sg")
        assert ip_used_recently(con, "198.51.100.42")
        assert summary_counts(con)["unique_exit_ips"] == 1
        assert list_aged_ready(con) == []


def test_netpool_templates_and_static_list():
    pool = StickyPortPool(
        host="proxy.example.test",
        base_user="acct123",
        password="secret",
        template="http://{user}__cr.{country};sessttl.{ttl}:{password}@{host}:{port}",
    )
    slot = pool.build_slot(port=10025, country="sg", ttl_minutes=30)
    assert slot.port == 10025
    assert slot.username == "acct123__cr.sg;sessttl.30"
    assert slot.server == "http://proxy.example.test:10025"
    cfg = build_camoufox_config(slot)
    assert cfg["webGl:renderer"] == "Intel(R) HD Graphics 400, or similar"
    assert cfg["timezone"] == "Asia/Singapore"

    with tempfile.TemporaryDirectory() as tmp:
        pfile = os.path.join(tmp, "proxies.txt")
        with open(pfile, "w", encoding="utf-8") as f:
            f.write("http://u1:p1@192.0.2.10:8080\nhttp://u2:p2@192.0.2.11:8080\n")
        spool = StickyPortPool(proxy_file=pfile)
        s0 = spool.build_slot(10000, country="jp")
        assert s0.server == "http://192.0.2.10:8080" and s0.username == "u1"


def test_session_bundle_pipe_contract():
    b = SessionBundle(
        account_id=7,
        username="dev-zen-12345",
        email="zen@alpha.example.test",
        country="sg",
        exit_ip="198.51.100.7",
        proxy_url="http://u:p@proxy.example.test:10007",
    )
    buf = io.StringIO()
    emit_bundles([b], stream=buf, jsonl=True)
    parsed = SessionBundle.from_dict(json.loads(buf.getvalue().strip()))
    assert parsed.username == "dev-zen-12345"
    assert parsed.exit_ip == "198.51.100.7"


def test_imap_catchall_domain_rotation():
    imap = ImapCatchAllAdapter(domains=["d1.example.test", "d2.example.test"])
    i0 = imap.create_inbox("seed-1", index=0)
    i1 = imap.create_inbox("seed-1", index=1)
    assert i0["address"].endswith("@d1.example.test")
    assert i1["address"].endswith("@d2.example.test")
    fwd = ForwardedRestCatchAllAdapter(
        master_address="master@example.test",
        master_token="tok_123",
        domains=["a.example.test", "b.example.test"],
    )
    f0 = fwd.create_inbox("seed-2", index=0)
    f1 = fwd.create_inbox("seed-2", index=1)
    assert f0["domain"] == "a.example.test" and f1["domain"] == "b.example.test"
    assert f0["provider"] == "forwarded_rest"

    # Test SqliteInboxAdapter & ManualMailboxAdapter & direct proxy driver
    direct_pool = StickyPortPool(driver="direct")
    dslot = direct_pool.build_slot(10000, country="sg")
    assert dslot.url == "" and dslot.playwright_proxy() is None

    man = ManualMailboxAdapter(domains=["manual.example.test"])
    m0 = man.create_inbox("seed-3", index=0)
    assert m0["provider"] == "manual" and m0["address"].endswith("@manual.example.test")

    gdot = GmailDotAdapter(address="sampleuser@gmail.com", app_password="abcd efgh ijkl mnop")
    g0 = gdot.create_inbox("seed-g0", index=0)
    g1 = gdot.create_inbox("seed-g1", index=1)
    assert g0["provider"] == "gmail_dot" and g0["address"].endswith("@gmail.com")
    assert "." in g0["address"].split("@")[0]
    assert g0["address"].split("@")[0].replace(".", "") == "sampleuser"
    assert g0["address"] != g1["address"]

    with tempfile.TemporaryDirectory() as tmp:
        mdb = os.path.join(tmp, "mail.db")
        import sqlite3
        con = sqlite3.connect(mdb)
        con.execute("CREATE TABLE inbox_messages (id INTEGER PRIMARY KEY, recipient TEXT, subject TEXT, body TEXT)")
        con.execute(
            "INSERT INTO inbox_messages(recipient, subject, body) VALUES (?, ?, ?)",
            (f0["address"], "Verify GitHub", "Your launch code is 87654321"),
        )
        con.commit()
        con.close()
        sq_mb = SqliteInboxAdapter(db_path=mdb, domains=["a.example.test"])
        otp, meta = sq_mb.poll_otp(f0["address"], timeout_sec=2, poll_sec=0.1)
        assert otp == "87654321" and meta["subject"] == "Verify GitHub"


def test_dns_doctor_and_panel_api():
    def _mock_resolver(qname: str, rtype: str) -> list[str]:
        if qname.startswith("_dmarc."):
            return ["v=DMARC1; p=quarantine"]
        if rtype == "A":
            return ["192.0.2.1"]
        if rtype == "MX":
            return ["10 mx1.forwardemail.net."]
        if rtype == "TXT":
            return ["v=spf1 a mx -all", "forward-email=shared@example.test"]
        return []

    report = audit_domain_pool(["d1.example.test", "d2.example.test"], resolver=_mock_resolver)
    assert report["domain_count"] == 2
    assert "shared@example.test" in report["shared_forward_targets"]
    assert "cross_domain_shared_forward_target" in report["domains"][0]["warnings"]

    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "panel.db")
        code, _, html = handle_api_request("GET", "/", db_path=db_path, resolver=_mock_resolver)
        assert code == 200 and "Identity &amp; Aging Control Panel" in html
        code, _, st_body = handle_api_request(
            "POST",
            "/api/stage",
            body=json.dumps({"count": 2, "mode": "catchall", "probe_proxy": False}),
            db_path=db_path,
            resolver=_mock_resolver,
        )
        assert code == 201 and json.loads(st_body)["staged_count"] == 2
        code, _, m_body = handle_api_request(
            "POST",
            "/api/accounts/status",
            body=json.dumps({"account_id": 1, "status": "verified"}),
            db_path=db_path,
            resolver=_mock_resolver,
        )
        assert code == 200 and json.loads(m_body)["ok"] is True
        code, _, acc_body = handle_api_request("GET", "/api/accounts", db_path=db_path, resolver=_mock_resolver)
        accs = json.loads(acc_body)["accounts"]
        assert len(accs) == 2 and any(a["kiro_ready"] is True for a in accs)
        code, _, ck_body = handle_api_request(
            "POST",
            "/api/import-cookie",
            body=json.dumps({"account_id": 2, "cookie": "user_session=mock_sess_123; logged_in=yes"}),
            db_path=db_path,
            resolver=_mock_resolver,
        )
        assert code == 200 and json.loads(ck_body)["ok"] is True


if __name__ == "__main__":
    test_store_and_identity()
    test_netpool_templates_and_static_list()
    test_session_bundle_pipe_contract()
    test_imap_catchall_domain_rotation()
    test_dns_doctor_and_panel_api()
    print("[PASS] auto-gh offline suite passed (5/5)")
