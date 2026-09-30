"""The HTML the gate serves: sign-in, the waiting room, and the admin panel.

Rendered in Python rather than added to the React console on purpose.  These
pages have to work *before* anyone is authorised, so they cannot live behind
the gate they are part of; and keeping them here means the whole feature is
standard-library Python and the committed build in viewer/static/ does not
have to be regenerated to change a word on the login form.

Everything is inline - no script file, no font, no stylesheet, no image from
anywhere.  The console already promises to work with the network off
(ui/vite.config.js), and a login page that reaches for a CDN would break that
promise at the one moment it matters.

The colours are the console's own tokens (ui/src/index.css) so the gate does
not look like a different product, and they flip with prefers-color-scheme
because the gate has nowhere to store a theme preference yet.
"""

from __future__ import annotations

import html
import json
from typing import Optional

from access.policy import (ACCESS_WINDOW_HOURS, ACTIVE, APPROVED, EXPIRED,
                           PENDING, REJECTED, REQUEST_TTL_MINUTES, REVOKED)

PRODUCT = "AnokhiDrishti"
TAGLINE = "DVR/NVR forensics"

CSS = """
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#0b0f14; --surface:#121821; --surface2:#172030; --line:#1f2a37;
  --ink:#e6edf3; --dim:#8b98a5; --accent:#2dd4bf; --ok:#22c55e;
  --warn:#f59e0b; --bad:#ef4444; --radius:10px;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
  --sans:"IBM Plex Sans",system-ui,-apple-system,Segoe UI,sans-serif;
}
@media (prefers-color-scheme:light){
  :root{
    --bg:#f6f8fa; --surface:#ffffff; --surface2:#f0f3f6; --line:#d8dee6;
    --ink:#11181f; --dim:#5b6873; --accent:#0d9488;
  }
}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);
  font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}
a{color:var(--accent)}
.wrap{max-width:460px;margin:0 auto;padding:44px 20px 60px}
.wrap.wide{max-width:1080px}
.brand{display:flex;align-items:center;gap:9px;font-weight:600;font-size:16px;
  margin-bottom:22px}
.brand .mark{color:var(--accent);font-size:19px;line-height:1}
.brand .sub{color:var(--dim);font-weight:400;font-size:11.5px}
.panel{background:var(--surface);border:1px solid var(--line);
  border-radius:var(--radius);padding:22px}
h1{font-size:19px;margin:0 0 4px}
h2{font-size:14.5px;margin:26px 0 9px}
p.lead{color:var(--dim);margin:0 0 18px;font-size:13px}
label{display:block;font-size:12px;color:var(--dim);margin:14px 0 5px;
  letter-spacing:.03em;text-transform:uppercase}
input[type=text],input[type=password]{width:100%;padding:9px 11px;
  background:var(--surface2);color:var(--ink);border:1px solid var(--line);
  border-radius:8px;font:inherit}
input:focus{outline:2px solid var(--accent);outline-offset:-1px}
button{font:inherit;cursor:pointer;border-radius:8px;padding:9px 15px;
  border:1px solid var(--line);background:var(--surface2);color:var(--ink)}
button.primary{background:var(--accent);border-color:var(--accent);color:#04211d;
  font-weight:600;width:100%;margin-top:20px;padding:10px}
button.primary:hover{filter:brightness(1.08)}
button.sm{padding:5px 11px;font-size:12.5px}
button.ok{border-color:color-mix(in srgb,var(--ok) 50%,transparent);color:var(--ok)}
button.bad{border-color:color-mix(in srgb,var(--bad) 50%,transparent);color:var(--bad)}
.err,.note{border-radius:8px;padding:9px 12px;font-size:13px;margin:0 0 4px}
.err{border:1px solid color-mix(in srgb,var(--bad) 45%,transparent);
  background:color-mix(in srgb,var(--bad) 12%,transparent);color:var(--bad)}
.note{border:1px solid color-mix(in srgb,var(--ok) 45%,transparent);
  background:color-mix(in srgb,var(--ok) 12%,transparent);color:var(--ok)}
.foot{color:var(--dim);font-size:12px;margin-top:18px;text-align:center}
.idbox{font-family:var(--mono);font-size:30px;letter-spacing:.14em;
  text-align:center;padding:16px 10px;background:var(--surface2);
  border:1px dashed var(--line);border-radius:var(--radius);margin:6px 0 18px}
.state{display:flex;align-items:center;gap:10px;font-size:14.5px;
  font-weight:600;margin-bottom:6px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--dim);flex:none}
.dot.pend{background:var(--warn);animation:pulse 1.4s ease-in-out infinite}
.dot.ok{background:var(--ok)} .dot.bad{background:var(--bad)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
.bar{height:5px;background:var(--surface2);border-radius:99px;overflow:hidden;
  margin:14px 0 4px}
.bar i{display:block;height:100%;background:var(--accent);border-radius:99px;
  transition:width .6s linear}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);
  vertical-align:middle}
th{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.04em;
  font-weight:600}
td.mono,.mono{font-family:var(--mono);font-size:12.5px}
.pill{display:inline-block;border:1px solid var(--line);border-radius:99px;
  padding:1px 9px;font-size:11px;color:var(--dim);white-space:nowrap}
.pill.pending{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 45%,transparent)}
.pill.approved,.pill.active{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 45%,transparent)}
.pill.rejected,.pill.revoked,.pill.expired{color:var(--bad);
  border-color:color-mix(in srgb,var(--bad) 45%,transparent)}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  margin-bottom:8px}
.stat{background:var(--surface2);border:1px solid var(--line);
  border-radius:var(--radius);padding:11px 13px}
.stat b{display:block;font-size:21px;font-weight:600}
.stat span{color:var(--dim);font-size:11.5px}
.row{display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.bar-top{display:flex;align-items:center;gap:12px;margin-bottom:20px}
.bar-top .sp{flex:1}
.empty{color:var(--dim);text-align:center;padding:22px;font-size:13px}
.tiny{color:var(--dim);font-size:11.5px}
"""


def _e(text) -> str:
    return html.escape(str(text if text is not None else ""), quote=True)


def _page(title: str, body: str, head: str = "", wide: bool = False,
          nonce: str = "") -> bytes:
    return (
        "<!doctype html><html lang=\"en\"><head>"
        "<meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta name=\"referrer\" content=\"no-referrer\">"
        "<meta name=\"robots\" content=\"noindex,nofollow\">"
        f"<title>{_e(title)} &middot; {PRODUCT}</title>"
        f"<style>{CSS}</style>{head}</head><body>"
        f"<div class=\"wrap{' wide' if wide else ''}\">"
        f"<div class=\"brand\"><span class=\"mark\">&#9703;</span>"
        f"<span>{PRODUCT}</span>"
        f"<span class=\"sub\">&middot; {TAGLINE}</span></div>"
        f"{body}</div></body></html>"
    ).encode("utf-8")


def _msg(error: str = "", note: str = "") -> str:
    out = ""
    if error:
        out += f"<p class=\"err\">{_e(error)}</p>"
    if note:
        out += f"<p class=\"note\">{_e(note)}</p>"
    return out


# ---------------------------------------------------------------- sign in
def login_page(error: str = "", note: str = "", username: str = "",
               allow_signup: bool = True, csrf: str = "") -> bytes:
    signup_link = ("<p class=\"foot\">No account? "
                   "<a href=\"/access/signup\">Create one</a></p>"
                   if allow_signup else "")
    body = f"""<div class="panel">
<h1>Sign in</h1>
<p class="lead">Signing in does not open the console. It places a request that
an administrator on this machine has to approve.</p>
{_msg(error, note)}
<form method="post" action="/access/login" autocomplete="off">
<input type="hidden" name="csrf" value="{_e(csrf)}">
<label for="u">Username</label>
<input id="u" name="username" type="text" value="{_e(username)}"
  autocapitalize="none" spellcheck="false" autofocus required>
<label for="p">Password</label>
<input id="p" name="password" type="password" required>
<button class="primary" type="submit">Request access</button>
</form></div>{signup_link}
<p class="foot tiny">Approved access lasts {ACCESS_WINDOW_HOURS} hours.</p>"""
    return _page("Sign in", body)


def signup_page(error: str = "", username: str = "", csrf: str = "",
                min_len: int = 10) -> bytes:
    body = f"""<div class="panel">
<h1>Create an account</h1>
<p class="lead">A new account is an ordinary user. It cannot approve anything,
including its own requests.</p>
{_msg(error)}
<form method="post" action="/access/signup" autocomplete="off">
<input type="hidden" name="csrf" value="{_e(csrf)}">
<label for="u">Username</label>
<input id="u" name="username" type="text" value="{_e(username)}"
  autocapitalize="none" spellcheck="false" autofocus required>
<label for="p">Password &mdash; at least {min_len} characters</label>
<input id="p" name="password" type="password" required>
<label for="p2">Repeat password</label>
<input id="p2" name="password2" type="password" required>
<button class="primary" type="submit">Create account</button>
</form></div>
<p class="foot"><a href="/access/login">Back to sign in</a></p>"""
    return _page("Create an account", body)


# ----------------------------------------------------------- waiting room
_DOT = {PENDING: "pend", APPROVED: "ok", ACTIVE: "ok",
        REJECTED: "bad", REVOKED: "bad", EXPIRED: "bad"}

# Polls its own status and nothing else.  On a grant it replaces the document
# rather than following a link, so the 9-digit URL is not left in history as
# the last thing the browser saw.
_WAIT_JS = """
<script nonce="%s">
(function(){
  var id=%s, poll=%d;
  var dot=document.getElementById('dot'), msg=document.getElementById('msg'),
      sub=document.getElementById('sub'), bar=document.getElementById('bar');
  function paint(s){
    if(!s) return;
    dot.className='dot '+(s.status==='pending'?'pend':(s.granted?'ok':'bad'));
    msg.textContent=s.message;
    if(s.granted){
      sub.textContent='Opening the console\\u2026';
      location.replace('/');
      return;
    }
    if(s.final){ sub.textContent='This request is closed. Sign in again to ask for a new one.';
      if(bar) bar.style.display='none';
      var f=document.getElementById('again'); if(f) f.style.display='block';
      return; }
    if(typeof s.expires_in_s==='number'){
      var m=Math.floor(s.expires_in_s/60), ss=s.expires_in_s%%60;
      sub.textContent='This request expires in '+m+'m '+(ss<10?'0':'')+ss+'s if nobody decides.';
      if(bar) bar.firstChild.style.width=Math.max(0,Math.min(100,s.expires_in_s/(%d*60)*100))+'%%';
    }
  }
  function tick(){
    fetch('/access/status/'+id,{cache:'no-store'})
      .then(function(r){return r.ok?r.json():null}).then(paint).catch(function(){});
  }
  tick(); setInterval(tick, poll);
})();
</script>
"""


def waiting_page(public_id: str, status: str, message: str,
                 expires_in_s: int = 0, username: str = "",
                 poll_ms: int = 3000, csrf: str = "", nonce: str = "") -> bytes:
    final = status in (REJECTED, REVOKED, EXPIRED)
    bar = ("" if final else
           "<div class=\"bar\" id=\"bar\"><i style=\"width:100%\"></i></div>")
    again = ("<form method=\"get\" action=\"/access/login\" id=\"again\""
             f"{'' if final else ' style=display:none'}>"
             "<button class=\"primary\" type=\"submit\">Sign in again</button>"
             "</form>")
    who = (f"<p class=\"tiny\">Signed in as <b>{_e(username)}</b>.</p>"
           if username else "")
    body = f"""<div class="panel">
<h1>Access request</h1>
<p class="lead">Your request has been submitted. This is its identifier.</p>
<div class="idbox">{_e(public_id)}</div>
<div class="state"><span class="dot {_DOT.get(status, '')}" id="dot"></span>
  <span id="msg">{_e(message)}</span></div>
<p class="lead tiny" id="sub">Checking&hellip;</p>
{bar}
{who}
{again}
</div>
<p class="foot tiny">This page refreshes itself. Approved access lasts
{ACCESS_WINDOW_HOURS} hours from the moment it is granted.</p>
<form method="post" action="/access/logout" class="foot">
<input type="hidden" name="csrf" value="{_e(csrf)}">
<button class="sm" type="submit">Sign out</button></form>"""
    # Signing out is a POST: a GET link would let any page on any origin end
    # the session with nothing more than an <img> tag.
    head = _WAIT_JS % (_e(nonce), json.dumps(str(public_id)), int(poll_ms),
                       int(REQUEST_TTL_MINUTES))
    return _page("Access request " + str(public_id), body, head=head,
                 nonce=nonce)


def denied_page(title: str, message: str, detail: str = "") -> bytes:
    body = f"""<div class="panel">
<h1>{_e(title)}</h1>
<div class="state"><span class="dot bad"></span><span>{_e(message)}</span></div>
{f'<p class="lead tiny">{_e(detail)}</p>' if detail else ''}
<form method="get" action="/access/login">
<button class="primary" type="submit">Sign in again</button></form>
</div>"""
    return _page(title, body)


# ------------------------------------------------------------ admin panel
def _pill(status: str) -> str:
    return f"<span class=\"pill {_e(status)}\">{_e(status)}</span>"


def _decide_form(public_id: str, action: str, label: str, cls: str,
                 csrf: str) -> str:
    return (f"<form method=\"post\" action=\"/admin/decide\" style=\"display:inline\">"
            f"<input type=\"hidden\" name=\"csrf\" value=\"{_e(csrf)}\">"
            f"<input type=\"hidden\" name=\"public_id\" value=\"{_e(public_id)}\">"
            f"<input type=\"hidden\" name=\"action\" value=\"{_e(action)}\">"
            f"<button class=\"sm {cls}\" type=\"submit\">{_e(label)}</button></form>")


def admin_page(admin: str, overview: dict, pending: list, recent: list,
               users: list, audit: list, csrf: str, error: str = "",
               note: str = "") -> bytes:
    chain = (overview.get("audit_chain") or {})
    chain_ok = bool(chain.get("valid"))
    stats = (
        f"<div class=\"grid\">"
        f"<div class=\"stat\"><b>{len(pending)}</b><span>awaiting decision</span></div>"
        f"<div class=\"stat\"><b>{_e(overview.get('live_sessions', 0))}</b>"
        f"<span>live sessions</span></div>"
        f"<div class=\"stat\"><b>{_e(overview.get('users', 0))}</b>"
        f"<span>accounts ({_e(overview.get('admins', 0))} admin)</span></div>"
        f"<div class=\"stat\"><b>{_e(overview.get('audit_entries', 0))}</b>"
        f"<span>audit entries &middot; "
        f"<span style=\"color:var(--{'ok' if chain_ok else 'bad'})\">"
        f"{'chain intact' if chain_ok else 'CHAIN BROKEN'}</span></span></div>"
        f"</div>")

    if pending:
        rows = "".join(
            f"<tr><td class=\"mono\">{_e(r['public_id'])}</td>"
            f"<td>{_e(r['username'])}</td>"
            f"<td class=\"mono tiny\">{_e(r['created_utc'])}</td>"
            f"<td class=\"mono tiny\">{_e(r.get('remote_ip') or '-')}</td>"
            f"<td class=\"row\">"
            f"{_decide_form(r['public_id'], 'approve', 'Approve', 'ok', csrf)}"
            f"{_decide_form(r['public_id'], 'reject', 'Reject', 'bad', csrf)}"
            f"</td></tr>" for r in pending)
        pending_tbl = (
            "<table><thead><tr><th>Request</th><th>User</th><th>Asked</th>"
            "<th>From</th><th>Decision</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>")
    else:
        pending_tbl = "<p class=\"empty\">Nothing is waiting for a decision.</p>"

    if recent:
        rrows = "".join(
            f"<tr><td class=\"mono\">{_e(r['public_id'])}</td>"
            f"<td>{_e(r['username'])}</td><td>{_pill(r['status'])}</td>"
            f"<td class=\"mono tiny\">{_e(r.get('decided_by') or '-')}</td>"
            f"<td class=\"mono tiny\">{_e(r.get('access_expires_utc') or '-')}</td>"
            f"<td>{_decide_form(r['public_id'], 'revoke', 'Revoke', 'bad', csrf) if r['status'] in (APPROVED, ACTIVE) else ''}</td>"
            f"</tr>" for r in recent)
        recent_tbl = ("<table><thead><tr><th>Request</th><th>User</th>"
                      "<th>State</th><th>Decided by</th><th>Access until</th>"
                      f"<th></th></tr></thead><tbody>{rrows}</tbody></table>")
    else:
        recent_tbl = "<p class=\"empty\">No requests yet.</p>"

    def _enabled(user: dict) -> str:
        # A helper rather than a conditional inside the f-string: escaped
        # quotes inside an f-string expression only parse on 3.12 and later.
        return _pill("rejected" if user["disabled"] else "approved").replace(
            ">rejected<", ">disabled<").replace(">approved<", ">enabled<")

    urows = "".join(
        f"<tr><td>{_e(u['username'])}</td><td>{_e(u['role'])}</td>"
        f"<td class=\"mono tiny\">{_e(u.get('last_login_utc') or 'never')}</td>"
        f"<td>{_enabled(u)}</td>"
        f"<td class=\"mono tiny\">{_e(u.get('locked_until_utc') or '-')}</td>"
        f"</tr>" for u in users)
    users_tbl = ("<table><thead><tr><th>User</th><th>Role</th><th>Last sign-in</th>"
                 f"<th>State</th><th>Locked until</th></tr></thead>"
                 f"<tbody>{urows}</tbody></table>")

    arows = "".join(
        f"<tr><td class=\"mono tiny\">{_e(e.get('ts_utc'))}</td>"
        f"<td class=\"mono tiny\">{_e(e.get('actor'))}</td>"
        f"<td class=\"mono tiny\">{_e(e.get('action'))}</td>"
        f"<td class=\"mono tiny\">{_e(json.dumps(e.get('detail') or {}, sort_keys=True))[:160]}</td>"
        f"<td class=\"mono tiny\">{_e(str(e.get('entry_hash'))[:12])}</td></tr>"
        for e in audit)
    audit_tbl = ("<table><thead><tr><th>UTC</th><th>Actor</th><th>Action</th>"
                 "<th>Detail</th><th>Hash</th></tr></thead>"
                 f"<tbody>{arows}</tbody></table>") if audit else \
                "<p class=\"empty\">No audit entries yet.</p>"

    body = f"""<div class="bar-top">
<h1 style="margin:0">Access administration</h1><span class="sp"></span>
<span class="pill">{_e(admin)} &middot; admin</span>
<form method="post" action="/access/logout" style="display:inline">
<input type="hidden" name="csrf" value="{_e(csrf)}">
<button class="sm" type="submit">Sign out</button></form>
</div>
{_msg(error, note)}
{stats}
<h2>Waiting for a decision</h2>
<div class="panel" style="padding:6px 10px">{pending_tbl}</div>
<h2>Recent requests</h2>
<div class="panel" style="padding:6px 10px">{recent_tbl}</div>
<h2>Accounts</h2>
<div class="panel" style="padding:6px 10px">{users_tbl}</div>
<h2>Audit log &mdash; newest first, hash-chained</h2>
<p class="tiny">{_e(chain.get('message', ''))}</p>
<div class="panel" style="padding:6px 10px">{audit_tbl}</div>
<p class="foot tiny">Approving grants {ACCESS_WINDOW_HOURS} hours from the
moment of approval. Revoking kills the session on the next request.</p>
<p class="foot"><a href="/">Open the console</a></p>"""
    return _page("Access administration", body, wide=True)
