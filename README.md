# auto-gh

Universal GitHub session manager, BYOP proxy allocator (`template` / `file` / `single` / `direct`), BYOP mailbox OTP poller (`forwarded_rest` / `rest` / `imap` / `sqlite` / `manual`), Camoufox profile runner, and standardized `SessionBundle` JSON/JSONL emitter.

## Architecture

`auto-gh` decouples proxy rotation, inbox OTP extraction, and browser profile persistence from downstream OAuth consumers (`auto-kr`, `auto-cb`) via a standardized JSONL pipe contract (`SessionBundle`).

```text
┌───────────────────────────────────────────────────────────┐
│                         auto-gh                           │
│  StickyPortPool (URI template / static list)              │
│  MailboxAdapter (REST OpenAPI / IMAP Catch-All)           │
│  Camoufox Profile Runner + SQLite WAL Store               │
└─────────────────────────────┬─────────────────────────────┘
                              │ stdout JSONL (SessionBundle)
                ┌─────────────┴─────────────┐
                ▼                           ▼
        ┌───────────────┐           ┌───────────────┐
        │    auto-kr    │           │    auto-cb    │
        └───────────────┘           └───────────────┘
```

## Modules

| Module | Path | Responsibility |
|---|---|---|
| `bundle` | `packages/auto_gh/bundle.py` | Standardized `SessionBundle` JSON/JSONL serializer and `.env` loader |
| `store` | `packages/auto_gh/store.py` | SQLite WAL persistence (`accounts`, `ip_history`, `events`), 7-day exit-IP guard, and `>= 305` min aging query |
| `netpool` | `packages/auto_gh/netpool.py` | Pluggable proxy allocator supporting dynamic URI templates (`PROXY_TEMPLATE`) and static proxy lists (`PROXY_FILE`) |
| `mailbox` | `packages/auto_gh/mailbox.py` | BYOP mailbox driver registry (`forwarded_rest`, `rest`, `imap`, `gmail_dot`, `sqlite`, `manual`) and MIME header OTP extractor |
| `browser_profile` | `packages/auto_gh/browser_profile.py` | Camoufox profile builder (`BROWSER_OS=macos|linux`), signup/login runner, and `sessions/<username>.json` persistence |
| `dns_doctor` | `packages/auto_gh/dns_doctor.py` | Read-only DoH DNS legitimacy & cross-domain correlation auditor (`A`, `MX`, `SPF`, `DMARC`, `forward-email=` leak check) |
| `panel` | `packages/auto_gh/panel.py` | Standalone zero-dependency HTTP Control Panel & REST API (`127.0.0.1:8790`) |
| `cli` | `packages/auto_gh/cli.py` | CLI (`status`, `alloc-proxy`, `inbox-create`, `stage-batch`, `inbox-poll`, `signup`, `login-session`, `import-cookie`, `aging-queue`, `export-sessions`, `domain-check`, `panel`, `doctor`) |

## Quickstart

```bash
cp .env.example .env
make test
make hygiene
make status
make domain-check
make panel PORT=8790
make export-sessions
```
