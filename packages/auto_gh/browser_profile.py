"""browser_profile.py — Camoufox profile launcher, GeoIP config builder, bandwidth filter, and session state persistence."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path

from .netpool import StickySlot

BASE_DIR = Path(__file__).resolve().parents[2]
SESSIONS_DIR = BASE_DIR / "sessions"

# Verified profile parameters compatible with Camoufox webgl_data.db
MACOS_BASE_CONFIG = {
    "navigator.userAgent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) "
        "Gecko/20100101 Firefox/136.0"
    ),
    "navigator.platform": "MacIntel",
    "navigator.oscpu": "Intel Mac OS X 10.15",
    "webGl:vendor": "Intel Inc.",
    "webGl:renderer": "Intel(R) HD Graphics 400, or similar",
}

LINUX_BASE_CONFIG = {
    "navigator.userAgent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) "
        "Gecko/20100101 Firefox/136.0"
    ),
    "navigator.platform": "Linux x86_64",
    "navigator.oscpu": "Linux x86_64",
}

BLOCKED_MEDIA_EXTENSIONS = (".woff2", ".ttf", ".otf", ".mp4", ".webm")
BLOCKED_IMAGE_PATTERNS = (
    "/images/signup/tres-amigos",
    "/images/signup/bg-darkest",
    "collector.github.com",
    "browser.events.data.microsoft.com",
)


def configure_runtime_env() -> None:
    lib_dir = os.path.expanduser("~/.local/lib/chromium-deps")
    cur_ld = os.environ.get("LD_LIBRARY_PATH", "")
    if lib_dir not in cur_ld.split(":"):
        os.environ["LD_LIBRARY_PATH"] = f"{lib_dir}:{cur_ld}" if cur_ld else lib_dir
    for var in (
        "MOZ_DISABLE_CONTENT_SANDBOX",
        "MOZ_DISABLE_GMP_SANDBOX",
        "MOZ_DISABLE_GPU_SANDBOX",
        "MOZ_DISABLE_RDD_SANDBOX",
        "MOZ_DISABLE_SOCKET_PROCESS_SANDBOX",
    ):
        os.environ[var] = "1"


def build_camoufox_config(slot: StickySlot, target_os: str | None = None) -> dict:
    os_name = (target_os or os.environ.get("BROWSER_OS") or "macos").lower()
    lang, _, region = slot.locale.partition("-")
    cfg = dict(LINUX_BASE_CONFIG if os_name == "linux" else MACOS_BASE_CONFIG)
    cfg.update(
        {
            "timezone": slot.timezone or "Asia/Singapore",
            "locale:language": lang or "en",
            "locale:region": region or slot.country.upper() or "SG",
        }
    )
    return cfg


def session_file_for(username: str) -> Path:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    return SESSIONS_DIR / f"{username}.json"


def save_github_cookie_state(username: str, cookie_input: str | dict) -> Path:
    """Persist a GitHub session (raw user_session value, Cookie header, or storage_state JSON) to sessions/<username>.json."""
    import json

    st_path = session_file_for(username)
    if isinstance(cookie_input, dict) and "cookies" in cookie_input:
        state_obj = cookie_input
    else:
        raw = str(cookie_input).strip()
        if raw.startswith("{"):
            parsed = json.loads(raw)
            if "cookies" in parsed:
                st_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
                return st_path
            kv = {str(k): str(v) for k, v in parsed.items()}
        elif "=" in raw or ";" in raw:
            kv = {}
            for part in raw.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    kv[k.strip()] = v.strip()
        else:
            kv = {
                "user_session": raw,
                "__Host-user_session_same_site": raw,
                "logged_in": "yes",
                "dotcom_user": username,
            }
        if "user_session" in kv and "__Host-user_session_same_site" not in kv:
            kv["__Host-user_session_same_site"] = kv["user_session"]
        kv.setdefault("logged_in", "yes")
        kv.setdefault("dotcom_user", username)
        cookies_list = []
        for name, val in kv.items():
            cookies_list.append(
                {
                    "name": name,
                    "value": val,
                    "domain": "github.com" if name.startswith("__Host-") else ".github.com",
                    "path": "/",
                    "expires": -1,
                    "httpOnly": name in ("user_session", "__Host-user_session_same_site"),
                    "secure": True,
                    "sameSite": "Lax",
                }
            )
        state_obj = {"cookies": cookies_list, "origins": []}
    st_path.write_text(json.dumps(state_obj, indent=2), encoding="utf-8")
    return st_path


def login_github_session(
    row: dict,
    slot: StickySlot,
    mailbox_driver=None,
    headless: bool = False,
) -> dict:
    """Log into github.com/login with Camoufox, auto-fill email device OTP if prompted, and save storage_state.json."""
    username = row["username"]
    st_path = session_file_for(username)
    with launch_profile_session(slot, storage_state_path=st_path, headless=headless) as (ctx, page):
        page.goto("https://github.com/login", wait_until="domcontentloaded", timeout=45000)
        page.wait_for_timeout(1500)
        if page.locator("input#login_field").count() > 0:
            page.locator("input#login_field").fill(row.get("email") or username)
            page.locator("input#password").fill(row["password"])
            page.wait_for_timeout(400)
            page.locator("input[type='submit'][name='commit'], button[type='submit']").first.click()
            page.wait_for_timeout(4000)

        otp_used = None
        if ("verified-device" in page.url or "two-factor" in page.url) and mailbox_driver is not None:
            code, _ = mailbox_driver.poll_otp(
                row["email"], row.get("email_token") or "", timeout_sec=35, poll_sec=2.0
            )
            if code:
                otp_used = code
                otp_in = page.locator("input#otp, input[name='otp']")
                if otp_in.count() > 0:
                    otp_in.first.fill(code)
                    page.wait_for_timeout(500)
                    btn = page.locator("button[type='submit']")
                    if btn.count() > 0:
                        btn.first.click()
                    page.wait_for_timeout(4000)

        cookies = {c.get("name", ""): c.get("value", "") for c in ctx.cookies() if "github.com" in c.get("domain", "")}
        logged_in = cookies.get("logged_in") == "yes" or "user_session" in cookies
        return {
            "ok": logged_in,
            "username": username,
            "url": page.url,
            "otp_used": otp_used,
            "storage_state": str(st_path) if logged_in else "",
            "cookie_names": sorted(cookies.keys()),
        }


def _sequential_fill(page, selector: str, value: str, delay_ms: int = 45) -> None:
    loc = page.locator(selector).first
    loc.fill(value, timeout=8000)
    try:
        loc.blur(timeout=4000)
    except Exception:
        loc.evaluate("el => el.blur()")


def _fill_launch_code(page, code: str, log_fn=None) -> None:
    import re
    import time

    digits = re.sub(r"\D", "", str(code))
    code_str = digits if len(digits) >= 6 else str(code).strip()
    try:
        page.wait_for_selector(
            "input[id^='launch-code-'], #otp, input[name='otp'], input[autocomplete='one-time-code']",
            state="visible",
            timeout=15000,
        )
    except Exception:
        pass

    inputs_info = page.evaluate(
        """() => Array.from(document.querySelectorAll('input')).map(i => ({
            id: i.id, name: i.name, type: i.type, visible: i.offsetParent !== null
        })).filter(x => x.visible)"""
    )
    if log_fn:
        log_fn(f"verify page visible inputs: {inputs_info}")

    boxes = page.locator("input[id^='launch-code-']")
    if boxes.count() >= len(code_str):
        for idx, ch in enumerate(code_str):
            boxes.nth(idx).fill(ch, timeout=5000)
            time.sleep(0.15)
        if log_fn:
            log_fn(f"filled {len(code_str)} launch-code boxes")
        return

    otp_in = page.locator("#otp, input[name='otp'], input[autocomplete='one-time-code']").first
    if otp_in.count() > 0:
        otp_in.fill(code_str, timeout=5000)
        page.wait_for_timeout(400)
        btn = page.locator("form button[type='submit'], button[type='submit']").first
        if btn.count() > 0 and btn.is_visible():
            btn.click(timeout=5000)


def _is_verify_screen(page) -> bool:
    try:
        loc = page.locator("input[id^='launch-code-'], #otp, input[name='otp'], input[autocomplete='one-time-code']")
        if loc.count() > 0 and loc.first.is_visible():
            return True
    except Exception:
        pass
    return "account_verifications" in (page.url or "")


def signup_github_session(
    row: dict,
    slot: StickySlot,
    mailbox_driver=None,
    headless: bool = False,
    otp_timeout_sec: int = 120,
) -> dict:
    """Execute end-to-end GitHub account registration, OTP verification, post-signup login, and session persistence."""
    import sys
    import time

    def _log(msg: str) -> None:
        sys.stderr.write(f"[signup] {msg}\n")
        sys.stderr.flush()

    base_username = row["username"]
    email_addr = row["email"]
    email_token = row.get("email_token") or ""
    password = row["password"]
    st_path = session_file_for(base_username)
    if st_path.is_file():
        st_path.unlink(missing_ok=True)
    used_codes: set[str] = set()
    if mailbox_driver is not None:
        for _ in range(10):
            old_c, _ = mailbox_driver.poll_otp(
                email_addr, email_token, timeout_sec=1, poll_sec=0.1, exclude_codes=used_codes
            )
            if not old_c:
                break
            used_codes.add(old_c)
        if used_codes:
            _log(f"excluded stale OTP codes: {sorted(used_codes)}")

    with launch_profile_session(slot, storage_state_path=st_path, headless=headless) as (ctx, page):
        _log(f"opening /login via :{slot.port} ({slot.country})")
        page.goto("https://github.com/login", wait_until="domcontentloaded", timeout=35000)
        page.wait_for_timeout(1500)
        signup_link = page.locator("a[href*='/signup']").first
        if signup_link.count() > 0:
            _log("clicking /signup link")
            try:
                signup_link.click(timeout=8000, no_wait_after=True)
            except Exception as exc:
                _log(f"signup_link click note: {exc}")
                page.evaluate("() => { const a = document.querySelector(\"a[href*='/signup']\"); if (a) a.click(); }")
        else:
            _log("navigating directly to /signup")
            page.goto("https://github.com/signup", wait_until="domcontentloaded", timeout=35000)

        for i in range(30):
            if page.locator("input#email").count() > 0 and page.locator("input#email").first.is_visible():
                _log(f"signup form visible after {i}s")
                break
            # If DataDome checkbox or challenge frame is present, click inside it
            for frame in page.frames:
                furl = frame.url or ""
                if "captcha-delivery" in furl:
                    try:
                        cb = frame.locator("#ddv1-test-tracking, input[type='checkbox'], [id*='checkbox'], body").first
                        if cb.count() > 0:
                            cb.click(timeout=2000, no_wait_after=True)
                            _log("poked captcha-delivery frame")
                    except Exception:
                        pass
            page.wait_for_timeout(1000)
        else:
            body_err = " ".join(page.locator("body").inner_text(timeout=2000).split())[:220]
            _log(f"form_load_timeout url={page.url} title={page.title()} body={body_err!r}")
            return {
                "ok": False,
                "stage": "form_load_timeout",
                "username": base_username,
                "email": email_addr,
                "url": page.url,
                "body": body_err,
            }

        page.wait_for_timeout(3500)
        _log(f"filling email={email_addr}")
        _sequential_fill(page, "input#email", email_addr)
        for _ in range(10):
            page.wait_for_timeout(500)
            if page.locator("input#email").first.get_attribute("aria-invalid") == "false":
                break

        _log("filling password")
        _sequential_fill(page, "input#password", password)
        for _ in range(10):
            page.wait_for_timeout(500)
            if page.locator("input#password").first.get_attribute("aria-invalid") == "false":
                break

        accepted_username = base_username
        for attempt in range(4):
            cand = base_username if attempt == 0 else f"{base_username}{attempt + 1}"
            _log(f"filling username={cand}")
            _sequential_fill(page, "input#login", cand)
            for _ in range(10):
                page.wait_for_timeout(500)
                if page.locator("input#login").first.get_attribute("aria-invalid") in ("false", "true"):
                    break
            err_txt = page.evaluate(
                """() => Array.from(document.querySelectorAll("auto-check [role='alert'], .error, [role='alert']"))
                    .map(e => (e.innerText || '').trim().toLowerCase()).join(' | ')"""
            )
            if "not available" in err_txt or "already taken" in err_txt:
                _log(f"username {cand} taken, retrying")
                continue
            accepted_username = cand
            break

        # Wait up to 12s for all 3 auto-check validations to complete (aria-invalid="false" and checkValidity()=true)
        pre_state: dict = {}
        for _ in range(15):
            pre_state = page.evaluate(
                """() => {
                    const tok = document.querySelector(".js-octocaptcha-token, input[name='octocaptcha-token']");
                    const loadBtn = document.querySelector(".js-octocaptcha-load-captcha");
                    const subBtn = document.querySelector(".js-octocaptcha-form-submit, form[action*='signup'] button[type='submit']");
                    const checks = Array.from(document.querySelectorAll("input#email, input#password, input#login")).map(el => ({
                        id: el.id,
                        valLen: (el.value || "").length,
                        ariaInvalid: el.getAttribute("aria-invalid"),
                        valid: el.checkValidity(),
                        msg: (el.validationMessage || "").slice(0, 60)
                    }));
                    return {
                        tokenVal: tok ? tok.value : null,
                        dynLoad: tok ? tok.getAttribute("data-dynamically-load-captcha") : null,
                        hasLoadBtn: Boolean(loadBtn && loadBtn.offsetParent !== null),
                        subBtnDisabled: subBtn ? subBtn.disabled : null,
                        allValid: checks.length === 3 && checks.every(c => c.valid && c.ariaInvalid === "false"),
                        checks
                    };
                }"""
            )
            if pre_state.get("allValid") and pre_state.get("tokenVal"):
                break
            page.wait_for_timeout(800)
        _log(f"pre-submit state: {pre_state}")

        load_btn = page.locator(".js-octocaptcha-load-captcha").first
        if load_btn.count() > 0 and load_btn.is_visible():
            _log("hovering and clicking .js-octocaptcha-load-captcha")
            load_btn.hover(timeout=5000)
            page.wait_for_timeout(500)
            load_btn.click(timeout=6000)
            # Wait up to 15s for octocaptcha-token to populate or auto-submit to fire
            for w in range(15):
                page.wait_for_timeout(1000)
                tok_val = page.locator("input[name='octocaptcha-token']").first.input_value() if page.locator("input[name='octocaptcha-token']").count() > 0 else ""
                if tok_val or _is_verify_screen(page) or "signup" not in (page.url or ""):
                    _log(f"after load-captcha {w}s: token={tok_val!r} url={page.url}")
                    break

        # If still on /signup and form wasn't auto-submitted yet, click the enabled submit button
        if "signup" in (page.url or "") and not _is_verify_screen(page):
            submit_btn = page.locator("form[action*='signup'] button[type='submit']").first
            for _ in range(20):
                try:
                    if submit_btn.count() > 0 and submit_btn.is_enabled():
                        break
                except Exception:
                    pass
                page.wait_for_timeout(800)

            _log("submitting signup form")
            clicked = False
            try:
                if submit_btn.count() > 0 and submit_btn.is_visible() and submit_btn.is_enabled():
                    submit_btn.click(timeout=8000)
                    clicked = True
            except Exception as exc:
                _log(f"native submit click exc: {exc}")

        # Wait up to 30s for transition off the signup form
        for i in range(15):
            page.wait_for_timeout(2000)
            body_snip = " ".join(page.locator("body").inner_text(timeout=2000).split())[:260]
            _log(f"post-submit wait {i}s url={page.url} text={body_snip!r}")
            if _is_verify_screen(page) or "signup" not in (page.url or ""):
                break
            err_after = page.evaluate(
                """() => Array.from(document.querySelectorAll(".js-signup-form-error, .flash-error, [role='alert']"))
                    .map(e => (e.innerText || '').trim()).filter(Boolean).join(' | ')"""
            )
            if err_after and "cannot be blank" not in err_after.lower() and "input is now valid" not in err_after.lower():
                _log(f"form error after submit: {err_after}")
                return {
                    "ok": False,
                    "stage": "signup_form_error",
                    "error": err_after[:300],
                    "username": accepted_username,
                    "email": email_addr,
                    "url": page.url,
                }

        if _is_verify_screen(page):
            if mailbox_driver is None:
                return {
                    "ok": False,
                    "stage": "otp_required_no_mailbox",
                    "username": accepted_username,
                    "email": email_addr,
                    "url": page.url,
                }
            code, _ = mailbox_driver.poll_otp(
                email_addr,
                email_token,
                timeout_sec=otp_timeout_sec,
                poll_sec=2.5,
                exclude_codes=used_codes,
            )
            if not code:
                return {
                    "ok": False,
                    "stage": "otp_poll_timeout",
                    "username": accepted_username,
                    "email": email_addr,
                    "url": page.url,
                }
            used_codes.add(code)
            _log(f"received OTP={code}, filling launch-code")
            _fill_launch_code(page, code, log_fn=_log)
            for w in range(15):
                page.wait_for_timeout(2000)
                body_after_otp = " ".join(page.locator("body").inner_text(timeout=2000).split())[:220]
                _log(f"post-OTP wait {w}s url={page.url} text={body_after_otp!r}")
                if not _is_verify_screen(page):
                    break

        # Check if already logged in after email verification before touching /login
        cookies = {c.get("name", ""): c.get("value", "") for c in ctx.cookies() if "github.com" in c.get("domain", "")}
        already_authed = cookies.get("logged_in") == "yes" or "user_session" in cookies

        # If GitHub redirected to /login after verification, sign in to capture logged_in=yes
        if not already_authed and page.locator("input#login_field").count() > 0 and page.locator("input#login_field").first.is_visible():
            _log("signing in at /login after email verification")
            _sequential_fill(page, "input#login_field", accepted_username)
            page.wait_for_timeout(400)
            _sequential_fill(page, "input#password", password)
            page.wait_for_timeout(600)
            sub_login = page.locator("input.js-sign-in-button, form[action*='session'] input[type='submit'], form[action*='session'] button[type='submit']").first
            try:
                if sub_login.count() > 0 and sub_login.is_visible():
                    sub_login.click(timeout=6000)
            except Exception as exc:
                _log(f"login click exc: {exc}")
            page.wait_for_timeout(5000)
            body_login = " ".join(page.locator("body").inner_text(timeout=2000).split())[:220]
            _log(f"after /login submit url={page.url} text={body_login!r}")
            if (_is_verify_screen(page) or "verified-device" in (page.url or "")) and mailbox_driver is not None:
                _log("device verification requested after login, polling second OTP")
                code2, _ = mailbox_driver.poll_otp(
                    email_addr,
                    email_token,
                    timeout_sec=otp_timeout_sec,
                    poll_sec=2.5,
                    exclude_codes=used_codes,
                )
                if code2:
                    used_codes.add(code2)
                    _log(f"received second OTP={code2}, filling")
                    _fill_launch_code(page, code2, log_fn=_log)
                    page.wait_for_timeout(5000)

        cookies = {c.get("name", ""): c.get("value", "") for c in ctx.cookies() if "github.com" in c.get("domain", "")}
        is_suspended = "/suspended" in (page.url or "")
        logged_in = (cookies.get("logged_in") == "yes" or "user_session" in cookies) and not is_suspended
        stage = "suspended" if is_suspended else ("verified" if logged_in else "post_submit")
        _log(f"done: stage={stage} logged_in={logged_in} cookies={sorted(cookies.keys())}")
        if st_path and logged_in:
            Path(st_path).parent.mkdir(parents=True, exist_ok=True)
            ctx.storage_state(path=str(st_path))
        return {
            "ok": logged_in,
            "stage": stage,
            "username": accepted_username,
            "email": email_addr,
            "url": page.url,
            "otp_used": sorted(used_codes),
            "storage_state": str(st_path) if logged_in else "",
            "cookie_names": sorted(cookies.keys()),
        }


def install_bandwidth_saver(page) -> None:
    """Drop heavy decorative media and telemetry while keeping all functional scripts/styles intact."""

    def _route_handler(route):
        url = route.request.url.lower()
        if any(p in url for p in BLOCKED_IMAGE_PATTERNS):
            return route.abort()
        if url.endswith(BLOCKED_MEDIA_EXTENSIONS) and "captcha" not in url:
            return route.abort()
        return route.continue_()

    page.route("**/*", _route_handler)


@contextmanager
def launch_profile_session(
    slot: StickySlot,
    storage_state_path: str | Path | None = None,
    headless: bool = False,
    save_bandwidth: bool = False,
):
    configure_runtime_env()
    from camoufox.sync_api import Camoufox

    os_name = (os.environ.get("BROWSER_OS") or "macos").lower()
    cfg = build_camoufox_config(slot, target_os=os_name)
    with Camoufox(
        headless=headless,
        proxy=slot.playwright_proxy(),
        os=os_name,
        humanize=True,
        i_know_what_im_doing=True,
        config=cfg,
        firefox_user_prefs={
            "security.sandbox.content.level": 0,
            "media.peerconnection.enabled": False,
        },
        addons=[],
    ) as browser:
        import json
        from typing import Any

        b_any: Any = browser
        if hasattr(b_any, "cookies"):
            context = b_any
        else:
            context = b_any.contexts[0] if getattr(b_any, "contexts", None) else b_any.new_context()
        if storage_state_path and Path(storage_state_path).is_file():
            try:
                raw_state = json.loads(Path(storage_state_path).read_text(encoding="utf-8"))
                clean_cookies = []
                for c in raw_state.get("cookies", []):
                    cc = {
                        k: c.get(k)
                        for k in ("name", "value", "domain", "path", "expires", "httpOnly", "secure", "sameSite")
                        if c.get(k) is not None
                    }
                    if cc.get("name") and cc.get("value"):
                        cc.setdefault("domain", ".github.com")
                        cc.setdefault("path", "/")
                        clean_cookies.append(cc)
                if clean_cookies:
                    context.add_cookies(clean_cookies)
            except Exception:
                pass
        page = context.pages[0] if getattr(context, "pages", None) else context.new_page()
        if save_bandwidth:
            install_bandwidth_saver(page)
        try:
            yield context, page
        finally:
            if storage_state_path:
                Path(storage_state_path).parent.mkdir(parents=True, exist_ok=True)
                try:
                    context.storage_state(path=str(storage_state_path))
                except Exception:
                    pass
            try:
                page.goto("about:blank", timeout=3000)
                page.close()
            except Exception:
                pass
