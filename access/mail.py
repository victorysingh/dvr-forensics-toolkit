"""Email notices for the access gate: optional, best-effort, informative only.

Two notices, and nothing else:

* **account created** - to the new user, at the address they signed up with.
* **access requested** - to every enabled administrator with an address on
  file. It carries what the admin panel's "Waiting for a decision" row shows
  (request, user, email, asked, from) and a link to /admin.

What a notice never carries: a password, a session token, or a link that
decides anything.  Approving still means signing in at /admin as an
administrator - an email can be forwarded, read over a shoulder or sit in a
compromised inbox, so it informs and nothing more.

Off unless configured (`serve --mail`): the air-gapped workstation has no
mail server.  A mail server that is slow or down must never hold up a sign-in,
so delivery runs on a background thread and only its outcome is recorded.

Standard library only: smtplib, over implicit TLS (port 465) or STARTTLS
(any other port).  Any SMTP service works - a Gmail account with an app
password, Amazon SES's SMTP interface, Brevo, and so on.
"""

from __future__ import annotations

import html
import os
import re
import smtplib
import ssl
import stat
import threading
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from typing import Callable, Optional

from access.policy import ACCESS_WINDOW_HOURS, REQUEST_TTL_MINUTES

PRODUCT = "AnokhiDrishti"
DEFAULT_ENV_FILE = os.path.join(os.path.expanduser("~"), ".config",
                                "anokhidrishti", "mail.env")
KEYS = ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "MAIL_FROM",
        "PUBLIC_URL")

#: Deliberately plain: one @, no spaces, no angle brackets or quotes (which
#: would let an address smuggle extra header text), a dotted domain.
EMAIL_RE = re.compile(r"^[^@\s<>\"',;]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$")


def valid_email(address: str) -> bool:
    return bool(address) and len(address) <= 254 and bool(EMAIL_RE.match(address))


# ---------------------------------------------------------------------------
class MailConfigError(Exception):
    pass


@dataclass(frozen=True)
class MailConfig:
    host: str
    port: int
    user: str
    password: str = field(repr=False)
    sender: str = ""
    public_url: str = ""            # where links point, e.g. https://example.org
    source: str = ""

    def __repr__(self) -> str:
        return (f"MailConfig(host={self.host!r}, port={self.port}, user={self.user!r}, "
                f"password=<hidden>, sender={self.sender!r}, source={self.source!r})")


def _read_env_file(path: str) -> dict:
    """KEY=VALUE lines from a file only its owner can read (it holds a password)."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        raise MailConfigError(
            f"no mail settings: set {', '.join(KEYS[:5])} in the environment, "
            f"or write them to {path}") from None
    except PermissionError:
        raise MailConfigError(f"{path} exists but this user cannot read it") from None
    if os.name == "posix" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise MailConfigError(
            f"{path} can be read by other users; it holds a password - "
            f"run: chmod 600 {path}")
    values: dict = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip().strip('"').strip("'")
    return values


def load_mail_config(env_file: str = "") -> MailConfig:
    """Settings from the environment first, then the file (default
    ~/.config/anokhidrishti/mail.env)."""
    values = {k: os.environ.get(k, "").strip() for k in KEYS}
    source = "environment"
    if not all(values[k] for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD")):
        path = env_file or DEFAULT_ENV_FILE
        from_file = _read_env_file(path)
        values = {k: values[k] or from_file.get(k, "") for k in KEYS}
        source = path
    missing = [k for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD") if not values[k]]
    if missing:
        raise MailConfigError(f"{source}: missing {', '.join(missing)}")
    try:
        port = int(values["SMTP_PORT"] or 465)
    except ValueError:
        raise MailConfigError("SMTP_PORT must be a number (465 or 587)") from None
    password = values["SMTP_PASSWORD"]
    if values["SMTP_HOST"].lower().endswith("gmail.com"):
        # Google shows an app password in four groups; the spaces are not part of it.
        password = password.replace(" ", "")
    sender = values["MAIL_FROM"] or values["SMTP_USER"]
    if not valid_email(sender.split("<")[-1].rstrip(">").strip()):
        raise MailConfigError("MAIL_FROM is not an email address")
    public = values["PUBLIC_URL"].rstrip("/")
    if public and not public.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise MailConfigError("PUBLIC_URL must be an https:// address")
    return MailConfig(host=values["SMTP_HOST"], port=port, user=values["SMTP_USER"],
                      password=password, sender=sender,
                      public_url=public, source=source)


# ---------------------------------------------------------------------------
class Mailer:
    """Sends one message at a time over SMTP, off the request thread."""

    def __init__(self, config: MailConfig, background: bool = True, timeout: float = 20.0):
        self.config = config
        self.background = background
        self.timeout = timeout

    def _connect(self) -> smtplib.SMTP:
        ctx = ssl.create_default_context()
        if self.config.port == 465:
            return smtplib.SMTP_SSL(self.config.host, 465, timeout=self.timeout, context=ctx)
        smtp = smtplib.SMTP(self.config.host, self.config.port, timeout=self.timeout)
        smtp.starttls(context=ctx)          # never sends the password in clear
        return smtp

    def _deliver(self, msg: EmailMessage) -> None:
        with self._connect() as smtp:
            smtp.login(self.config.user, self.config.password)
            smtp.send_message(msg)

    def send(self, to: str, subject: str, text: str, html_body: str,
             on_done: Optional[Callable[[bool, str], None]] = None) -> None:
        msg = EmailMessage()
        msg["From"] = formataddr((PRODUCT, self.config.sender))
        msg["To"] = to
        msg["Subject"] = subject
        msg["Message-ID"] = make_msgid(domain=self.config.sender.split("@")[-1])
        msg.set_content(text)
        msg.add_alternative(html_body, subtype="html")

        def run() -> None:
            try:
                self._deliver(msg)
            except Exception as exc:                       # noqa: BLE001
                if on_done:
                    # The class and a short reason only: an SMTP error can
                    # quote the conversation, which is no place for a log.
                    on_done(False, f"{type(exc).__name__}: {str(exc)[:120]}")
                return
            if on_done:
                on_done(True, "")

        if self.background:
            threading.Thread(target=run, name="access-mail", daemon=True).start()
        else:
            run()


# ------------------------------------------------------------- the notices
def _utc(stamp: str) -> str:
    return (stamp or "").replace("T", " ").split(".")[0].rstrip("Z") + " UTC"


def _link(public_url: str, path: str) -> str:
    return (public_url + path) if public_url else path


def _html(title: str, intro: str, rows: list[tuple[str, str]], action: tuple[str, str],
          note: str) -> str:
    """A small, self-contained HTML body: inline styles only, no images, no
    tracking, nothing fetched - it reads the same in any mail client."""
    e = html.escape
    table = "".join(
        f"<tr><td style=\"padding:6px 14px 6px 0;color:#58676f;white-space:nowrap\">{e(k)}</td>"
        f"<td style=\"padding:6px 0;font-family:ui-monospace,Menlo,Consolas,monospace\">{e(v)}</td></tr>"
        for k, v in rows)
    label, href = action
    return f"""<!doctype html><html><body style="margin:0;background:#f3f5f2;padding:24px 12px;
font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f151a">
<div style="max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #c9d2c8">
<div style="height:4px;background:#4a760a"></div>
<div style="padding:22px 24px">
<div style="font-weight:600;font-size:15px">{e(PRODUCT)}
<span style="color:#58676f;font-weight:400;font-size:12px">&middot; DVR/NVR forensics</span></div>
<h1 style="font-size:19px;margin:16px 0 6px">{e(title)}</h1>
<p style="margin:0 0 14px;line-height:1.5">{e(intro)}</p>
<table style="border-collapse:collapse;font-size:14px;margin:0 0 18px">{table}</table>
<a href="{e(href)}" style="display:inline-block;background:#4a760a;color:#ffffff;
text-decoration:none;padding:10px 16px;font-weight:600">{e(label)}</a>
<p style="margin:18px 0 0;color:#58676f;font-size:12.5px;line-height:1.5">{e(note)}</p>
</div></div></body></html>"""


def _browser(agent: str) -> str:
    """A readable name for a User-Agent string: what an admin needs to recognise it."""
    a = agent or ""
    for name, mark in (("Edge", "Edg/"), ("Opera", "OPR/"), ("Chrome", "Chrome/"),
                       ("Firefox", "Firefox/"), ("Safari", "Safari/")):
        if mark in a:
            browser = name
            break
    else:
        return (a[:60] + "...") if len(a) > 60 else (a or "-")
    for system, mark in (("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"),
                         ("Windows", "Windows"), ("macOS", "Mac OS X"), ("Linux", "Linux")):
        if mark in a:
            return f"{browser} on {system}"
    return browser


def account_created(username: str, email: str, created_utc: str,
                    public_url: str) -> tuple[str, str, str]:
    """(subject, text, html) for the new user."""
    login = _link(public_url, "/access/login")
    subject = f"{PRODUCT}: your account {username} was created"
    intro = ("Your account was created. An account on its own opens nothing: each "
             "time you sign in, you get a 9-digit access request that an "
             f"administrator must approve, and access then lasts {ACCESS_WINDOW_HOURS} hours.")
    rows = [("Username", username), ("Email", email), ("Created", _utc(created_utc))]
    note = ("If you did not create this account, you can ignore this email - no "
            "one can use it without an administrator's approval. This message "
            "holds no password and no sign-in link that works on its own.")
    text = (f"{PRODUCT} - account created\n\n{intro}\n\n"
            + "\n".join(f"  {k:<10} {v}" for k, v in rows)
            + f"\n\nSign in: {login}\n\n{note}\n")
    return subject, text, _html("Account created", intro, rows, ("Sign in", login), note)


def account_locked(username: str, until_utc: str, remote_ip: str, after: int,
                   public_url: str) -> tuple[str, str, str]:
    """(subject, text, html) for an account's owner after a lockout."""
    login = _link(public_url, "/access/login")
    subject = f"{PRODUCT}: your account {username} was locked after {after} failed sign-ins"
    intro = (f"There were {after} sign-in attempts on your account with a wrong password, "
             "so it is locked for now. It unlocks by itself; nobody got in.")
    rows = [("Username", username), ("Locked until", _utc(until_utc)),
            ("Last attempt from", remote_ip or "-")]
    note = ("If this was not you, someone may be guessing your password: tell an "
            "administrator, and choose a longer password once you are back in. "
            "Even a correct password only ever opens an access request that an "
            "administrator has to approve.")
    text = (f"{PRODUCT} - account locked\n\n{intro}\n\n"
            + "\n".join(f"  {k:<18} {v}" for k, v in rows)
            + f"\n\nSign in: {login}\n\n{note}\n")
    return subject, text, _html("Account locked", intro, rows, ("Go to sign in", login), note)


def access_requested(request: dict, user: dict, public_url: str) -> tuple[str, str, str]:
    """(subject, text, html) for each administrator: the admin panel's row."""
    admin = _link(public_url, "/admin")
    pid, who = request.get("public_id", ""), user.get("username", "")
    subject = f"{PRODUCT}: access request {pid} from {who} is waiting for a decision"
    intro = (f"{who} has signed in and is asking for access to the case console. "
             "Nothing is shared until an administrator approves the request.")
    rows = [("Request", pid), ("User", who), ("Email", user.get("email") or "-"),
            ("Asked", _utc(request.get("created_utc", ""))),
            ("From", request.get("remote_ip") or "-"),
            ("Browser", _browser(request.get("user_agent", ""))),
            ("Expires", _utc(request.get("request_expires_utc", "")) + " if undecided")]
    note = (f"Approve or reject it on the admin page, signed in as an administrator. "
            f"An approval grants {ACCESS_WINDOW_HOURS} hours; an undecided request "
            f"expires after {REQUEST_TTL_MINUTES} minutes. This email cannot approve "
            "anything by itself.")
    text = (f"{PRODUCT} - access request waiting\n\n{intro}\n\n"
            + "\n".join(f"  {k:<8} {v}" for k, v in rows)
            + f"\n\nDecide at: {admin}\n\n{note}\n")
    return subject, text, _html("Access request waiting for you", intro, rows,
                                ("Open the admin page", admin), note)


def access_decided(request: dict, username: str, status: str, decided_by: str,
                   public_url: str) -> tuple[str, str, str]:
    """(subject, text, html) for the user, when their request is approved,
    rejected, or a live grant is revoked."""
    pid = request.get("public_id", "")
    if status == "approved":
        site = _link(public_url, "/")
        subject = f"{PRODUCT}: access approved - request {pid}"
        intro = (f"An administrator approved your access request. It is valid for "
                 f"{ACCESS_WINDOW_HOURS} hours from the approval. If the waiting page is "
                 "still open, it moves into the console by itself; otherwise sign in again.")
        rows = [("Request", pid), ("Account", username), ("Approved by", decided_by),
                ("Valid until", _utc(request.get("access_expires_utc", "")))]
        action = ("Open AnokhiDrishti", site)
        note = ("This email does not sign you in: open the site in the browser you asked "
                "from, or sign in with your own account. The access lapses on its own.")
        title = "Access approved"
    else:
        site = _link(public_url, "/access/login")
        subject = (f"{PRODUCT}: access request {pid} was not approved" if status == "rejected"
                   else f"{PRODUCT}: your access was withdrawn - request {pid}")
        intro = ("An administrator did not approve your access request." if status == "rejected"
                 else "An administrator ended your access before its time ran out.")
        rows = [("Request", pid), ("Account", username),
                ("Decided by", decided_by), ("Note", request.get("decision_note") or "-")]
        action = ("Go to sign in", site)
        note = "You can sign in again to ask for access, if you need it."
        title = "Access not approved" if status == "rejected" else "Access withdrawn"
    text = (f"{PRODUCT} - {title.lower()}\n\n{intro}\n\n"
            + "\n".join(f"  {k:<12} {v}" for k, v in rows)
            + f"\n\n{action[0]}: {action[1]}\n\n{note}\n")
    return subject, text, _html(title, intro, rows, action, note)


def approval_confirmed(request: dict, username: str, decided_by: str,
                       public_url: str) -> tuple[str, str, str]:
    """(subject, text, html) for every administrator after an approval."""
    admin = _link(public_url, "/admin")
    pid = request.get("public_id", "")
    subject = f"{PRODUCT}: {decided_by} approved request {pid} for {username}"
    intro = (f"{decided_by} approved {username}'s access request. The grant lasts "
             f"{ACCESS_WINDOW_HOURS} hours and can be revoked from the admin page at any time.")
    rows = [("Request", pid), ("User", username), ("Approved by", decided_by),
            ("Valid until", _utc(request.get("access_expires_utc", "")))]
    note = ("Revoking ends the user's session on their very next request. This email "
            "cannot revoke or approve anything by itself.")
    text = (f"{PRODUCT} - approval recorded\n\n{intro}\n\n"
            + "\n".join(f"  {k:<12} {v}" for k, v in rows)
            + f"\n\nAdmin page: {admin}\n\n{note}\n")
    return subject, text, _html("Approval recorded", intro, rows,
                                ("Open the admin page", admin), note)
