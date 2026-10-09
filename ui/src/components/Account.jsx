// The account control in the top bar: a profile picture that opens a menu
// with the profile, the light/dark switch and sign-out.
//
// Who is signed in comes from the server (api.me), never from the page.
// Behind `serve --require-access` that is the account and its grant, and
// "Log out" posts to /access/logout, which ends the session and lands on the
// sign-in page. On an examiner's own workstation sign-in is off: the menu
// says so rather than inventing an account, and there is nothing to sign
// out of.
import { useState, useEffect, useRef, useCallback, useSyncExternalStore } from "react";
import { api } from "../lib/api.js";
import { isDemo } from "../lib/host.js";
import { utcTime, dur, camColor } from "../lib/format.js";
import { useTheme, flipTheme } from "../lib/theme.js";
import { toGuide } from "../lib/useHashRoute.js";

/* ------------------------------------------------------------- who */
function describe(acct) {
  const user = acct?.user;
  // The same words as the top bar's badge (App.jsx::TopBar), so the menu
  // and the bar never describe the console two ways.
  const gated = isDemo() ? "hosted · approved access" : "offline · read-only · approved access";
  if (user) {
    const admin = user.role === "admin";
    return { key: user.username, name: user.username, user, admin, gate: true,
             role: admin ? "Administrator" : "Approved reviewer", posture: gated };
  }
  if (acct?.gate) {
    return { key: "", name: "Signed out", role: "Your session has ended", gate: true,
             ended: true, posture: gated };
  }
  if (isDemo()) {
    return { key: "guest", name: "Guest", role: "Public demonstration",
             posture: "demo · synthetic data", why: "no account in the demonstration" };
  }
  return { key: "local", name: "Examiner", role: "This workstation",
           posture: "offline · read-only", why: "sign-in is off on this workstation" };
}

function initials(name) {
  const parts = String(name).split(/[\s._@-]+/).filter(Boolean);
  return (parts.length > 1 ? parts[0][0] + parts[1][0] : String(name).slice(0, 2))
    .toUpperCase();
}

// One colour per name, from the camera palette, so the same account always
// wears the same colour and it follows the theme.
function tint(name) {
  let h = 0;
  for (const ch of String(name)) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return camColor(h);
}

/* --------------------------------------------------------- picture */
// A chosen picture stays in this browser only (localStorage), scaled down to
// 128 px: nothing is uploaded, so the server never holds a face it was not
// asked to keep.
const PIC = (key) => `anokhidrishti-avatar:${key}`;
const PIC_EVENT = "anokhidrishti-avatar";

function readPic(key) {
  try { return (key && localStorage.getItem(PIC(key))) || ""; } catch { return ""; }
}

function onPicChange(cb) {
  window.addEventListener(PIC_EVENT, cb);
  return () => window.removeEventListener(PIC_EVENT, cb);
}

const usePicture = (key) => useSyncExternalStore(onPicChange, () => readPic(key));

function savePic(key, dataUrl) {
  try {
    if (dataUrl) localStorage.setItem(PIC(key), dataUrl);
    else localStorage.removeItem(PIC(key));
  } catch { return false; }
  window.dispatchEvent(new Event(PIC_EVENT));
  return true;
}

// Centre-crop to a square and scale to 128 px.
async function shrink(file) {
  const url = URL.createObjectURL(file);
  try {
    const img = await new Promise((ok, bad) => {
      const i = new Image();
      i.onload = () => ok(i);
      i.onerror = () => bad(new Error("not an image"));
      i.src = url;
    });
    const s = Math.min(img.naturalWidth, img.naturalHeight);
    const c = document.createElement("canvas");
    c.width = c.height = 128;
    c.getContext("2d").drawImage(img, (img.naturalWidth - s) / 2, (img.naturalHeight - s) / 2,
      s, s, 0, 0, 128, 128);
    return c.toDataURL("image/jpeg", 0.85);
  } finally {
    URL.revokeObjectURL(url);
  }
}

export function Avatar({ who, size = 32 }) {
  const pic = usePicture(who.key);
  const c = tint(who.name);
  const box = { width: size, height: size };
  if (pic) {
    return <img src={pic} alt="" style={box}
      className="rounded-full object-cover shrink-0 border hairline" />;
  }
  const anon = !who.user;
  return (
    <span aria-hidden="true" style={{
      ...box, fontSize: Math.round(size * 0.38), color: anon ? "var(--color-ink-dim)" : c,
      background: anon ? "var(--color-surface-2)"
        : `color-mix(in srgb, ${c} 18%, var(--color-surface-2))`,
      borderColor: anon ? "var(--color-line)" : `color-mix(in srgb, ${c} 55%, transparent)` }}
      className="rounded-full border grid place-items-center shrink-0 font-semibold
        select-none leading-none tracking-wide">
      {anon ? <PersonGlyph size={Math.round(size * 0.56)} /> : initials(who.name)}
    </span>
  );
}

const PersonGlyph = ({ size }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="1.8" strokeLinecap="round">
    <circle cx="12" cy="8.5" r="4" />
    <path d="M4.5 20.5c1.2-3.8 4.2-5.6 7.5-5.6s6.3 1.8 7.5 5.6" />
  </svg>
);

/* ------------------------------------------------------------ time */
function useNow(active, every = 30000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), every);
    return () => clearInterval(t);
  }, [active, every]);
  return now;
}

function timeLeft(expires, now) {
  const t = Date.parse(expires || "");
  if (!t) return "";
  const s = Math.round((t - now) / 1000);
  return s > 0 ? `${dur(s)} left` : "ended";
}

/* ---------------------------------------------------------- logout */
// A real form post, not a fetch: the server answers with a redirect to the
// sign-in page and clears the cookie on the same response, and the browser
// simply follows it.
function LogoutForm({ csrf, className, role }) {
  return (
    <form method="post" action="/access/logout" className="contents">
      <input type="hidden" name="csrf" value={csrf} />
      <button type="submit" role={role} className={className}>
        <span className="w-5 text-center shrink-0" aria-hidden="true">&#x23FB;</span>
        Log out
      </button>
    </form>
  );
}

/* ------------------------------------------------------------ menu */
const ITEM = `w-full flex items-center gap-3 px-4 py-3 sm:py-2.5 text-left text-[13.5px]
  cursor-pointer hover:bg-[color-mix(in_srgb,var(--color-ink)_7%,transparent)]
  focus-visible:outline-none focus-visible:bg-[color-mix(in_srgb,var(--color-accent)_14%,transparent)]`;

export function ProfileMenu({ guide }) {
  const [acct, setAcct] = useState(null);
  const [open, setOpen] = useState(false);
  const [profile, setProfile] = useState(false);
  const btn = useRef(null), menu = useRef(null);
  const theme = useTheme();
  const who = describe(acct);
  const now = useNow(open || profile);

  const refresh = useCallback(() => api.me().then(setAcct), []);
  useEffect(() => { refresh(); }, [refresh]);
  // Re-ask on every open: the grant's clock runs, and a session can end
  // while the page sits open.
  useEffect(() => { if (open || profile) refresh(); }, [open, profile, refresh]);
  // Moving to another screen (a shortcut, the back button) closes both.
  useEffect(() => {
    const away = () => { setOpen(false); setProfile(false); };
    window.addEventListener("hashchange", away);
    return () => window.removeEventListener("hashchange", away);
  }, []);

  const close = useCallback((focusButton = true) => {
    setOpen(false);
    if (focusButton) btn.current?.focus();
  }, []);

  useEffect(() => {
    if (!open) return;
    menu.current?.querySelector('[role="menuitem"]:not([aria-disabled="true"])')?.focus();
    const away = (e) => {
      if (!menu.current?.contains(e.target) && !btn.current?.contains(e.target)) close(false);
    };
    // Escape closes the menu and goes no further: the console's own Escape
    // shortcut leaves the case, which is not what closing a menu means.
    const esc = (e) => { if (e.key === "Escape") { e.stopPropagation(); close(); } };
    document.addEventListener("pointerdown", away);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("pointerdown", away);
      document.removeEventListener("keydown", esc);
    };
  }, [open, close]);

  const onMenuKey = (e) => {
    const items = [...menu.current.querySelectorAll('[role="menuitem"]:not([aria-disabled="true"])')];
    const i = items.indexOf(document.activeElement);
    const to = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: items.length - 1 }[e.key];
    if (to !== undefined) {
      e.preventDefault();
      items[(to + items.length) % items.length]?.focus();
    } else if (e.key === "Escape") {
      close();
    } else if (e.key === "Tab") {
      close(false);
    }
    if (e.key !== "Tab") e.stopPropagation();      // keep the console's shortcuts out
  };

  const left = timeLeft(who.user?.expires_utc, now);

  return (
    <div className="relative shrink-0">
      <button ref={btn} type="button" onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu" aria-expanded={open} aria-label={`Account: ${who.name}`}
        title={who.name}
        className="rounded-full cursor-pointer grid place-items-center w-9 h-9
          hover:ring-2 hover:ring-accent/40 aria-expanded:ring-2 aria-expanded:ring-accent/60">
        <Avatar who={who} size={32} />
      </button>

      {open && (
        <div ref={menu} role="menu" aria-label="Account" onKeyDown={onMenuKey}
          style={{ background: "var(--color-surface)" }}
          className="menu-pop absolute right-0 top-[calc(100%+8px)] z-40 w-[296px]
            max-w-[calc(100vw-16px)] border hairline rounded-[var(--radius-panel)]
            shadow-xl shadow-black/40 overflow-hidden">
          <div className="flex items-center gap-3 px-4 py-3.5 border-b hairline">
            <Avatar who={who} size={44} />
            <div className="min-w-0">
              <div className="font-semibold truncate text-[15px]">{who.name}</div>
              <div className="dim text-[12px] truncate">{who.role}</div>
              {who.user?.email && <div className="dim font-mono text-[11px] truncate"
                title={who.user.email}>{who.user.email}</div>}
            </div>
          </div>

          <div className="py-1">
            <button type="button" role="menuitem" className={ITEM}
              onClick={() => { setOpen(false); setProfile(true); }}>
              <span className="w-5 text-center shrink-0" aria-hidden="true">&#x25C9;</span>
              Profile
            </button>
            {/* The top bar's "Start here" link has no room on a phone; here
                it is one tap away on every size. */}
            <a href="#/start" role="menuitem" className={ITEM}
              aria-current={guide ? "page" : undefined}
              onClick={(e) => { toGuide(e); setTimeout(() => setOpen(false)); }}>
              <span className="w-5 text-center shrink-0" aria-hidden="true">&#x25B6;</span>
              Start here
              {guide && <span className="ml-auto dim text-[11px]">you are here</span>}
            </a>
            <button type="button" role="menuitem" className={ITEM}
              onClick={() => flipTheme()}>
              <span className="w-5 text-center shrink-0" aria-hidden="true">
                {theme === "light" ? "◑" : "◐"}</span>
              {theme === "light" ? "Dark mode" : "Light mode"}
              <kbd className="ml-auto dim font-mono text-[11px]">t</kbd>
            </button>
            {who.admin && (
              <a href="/admin" role="menuitem" className={ITEM}>
                <span className="w-5 text-center shrink-0" aria-hidden="true">&#x2691;</span>
                Admin panel
              </a>
            )}
          </div>

          <div className="py-1 border-t hairline">
            {who.user ? (
              <LogoutForm csrf={who.user.csrf} role="menuitem"
                className={`${ITEM} text-danger`} />
            ) : who.ended ? (
              <a href="/access/login" role="menuitem" className={`${ITEM} text-accent`}>
                <span className="w-5 text-center shrink-0" aria-hidden="true">&#x2192;</span>
                Sign in again
              </a>
            ) : (
              <div role="menuitem" aria-disabled="true" title={who.why}
                className={`${ITEM} cursor-default hover:bg-transparent dim`}>
                <span className="w-5 text-center shrink-0" aria-hidden="true">&#x23FB;</span>
                <span>Log out<span className="block text-[11px]">{who.why}</span></span>
              </div>
            )}
          </div>

          <div className="border-t hairline px-4 py-2 dim font-mono text-[10.5px] flex gap-2
            justify-between">
            <span>{who.posture}</span>
            {left && <span title={`Access ends ${utcTime(who.user.expires_utc)} UTC`}>{left}</span>}
          </div>
        </div>
      )}

      <ProfileDialog open={profile} onClose={() => { setProfile(false); btn.current?.focus(); }}
        who={who} now={now} />
    </div>
  );
}

/* ---------------------------------------------------------- profile */
function ProfileDialog({ open, onClose, who, now }) {
  const dlg = useRef(null), file = useRef(null);
  const pic = usePicture(who.key);
  const [err, setErr] = useState("");

  useEffect(() => {
    const d = dlg.current;
    if (!d) return;
    if (open && !d.open) { setErr(""); d.showModal(); }
    if (!open && d.open) d.close();
  }, [open]);

  const choose = async (e) => {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    try {
      if (!savePic(who.key, await shrink(f))) setErr("This browser would not store the picture.");
      else setErr("");
    } catch {
      setErr("That file could not be read as an image.");
    }
  };

  const u = who.user;
  const rows = u ? [
    ["Account", u.username],
    ["Role", who.role],
    ["Email", u.email || "—"],
    u.public_id && ["Access request", <span className="font-mono">{u.public_id}</span>],
    ["Signed in", `${utcTime(u.signed_in_utc)} UTC`],
    ["Access ends", <>{utcTime(u.expires_utc)} UTC
      <span className="dim"> &middot; {timeLeft(u.expires_utc, now)}</span></>],
    ["Console", who.posture],
  ] : [
    ["Account", who.ended ? "none — the session has ended" : "none"],
    ["Console", who.posture],
    ["Sign-in", who.ended ? "required" : "off"],
  ];

  return (
    // Keys typed in the dialog stay in it: the console's shortcuts (digits
    // switch screens, Escape leaves the case) must not act behind a modal.
    <dialog ref={dlg} onClose={onClose} onKeyDown={(e) => e.stopPropagation()}
      onClick={(e) => { if (e.target === dlg.current) dlg.current.close(); }}
      aria-labelledby="profile-title"
      style={{ background: "var(--color-surface)", color: "var(--color-ink)" }}
      className="m-auto p-0 border hairline rounded-[var(--radius-panel)]
        w-[min(460px,calc(100vw-24px))] max-h-[calc(100dvh-24px)]
        shadow-2xl shadow-black/50 backdrop:bg-black/55">
      <div className="p-5 sm:p-6">
        <div className="flex items-start gap-4">
          <Avatar who={who} size={72} />
          <div className="min-w-0 flex-1 pt-1">
            <div className="micro">Profile</div>
            <h2 id="profile-title" className="text-[19px] font-semibold break-all leading-snug">
              {who.name}</h2>
            <div className="dim text-[13px]">{who.role}</div>
          </div>
          <button type="button" onClick={() => dlg.current.close()} aria-label="Close"
            className="dim hover:text-accent cursor-pointer w-8 h-8 -mr-2 -mt-1 text-lg
              leading-none shrink-0">&times;</button>
        </div>

        {who.key && (
          <div className="flex flex-wrap items-center gap-2 mt-4">
            <button type="button" onClick={() => file.current.click()}
              className="hairline border rounded-[var(--radius-panel)] px-3 py-1.5 text-[12.5px]
                cursor-pointer hover:border-accent hover:text-accent">
              {pic ? "Change picture" : "Add a picture"}</button>
            {pic && (
              <button type="button" onClick={() => savePic(who.key, "")}
                className="dim px-2 py-1.5 text-[12.5px] cursor-pointer hover:text-danger">
                Remove</button>
            )}
            <span className="dim text-[11px] basis-full">Kept in this browser only; never
              uploaded.</span>
            <input ref={file} type="file" accept="image/*" hidden onChange={choose} />
            {err && <span className="text-danger text-[12px] basis-full">{err}</span>}
          </div>
        )}

        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-[13px] mt-5
          pt-4 border-t hairline">
          {rows.filter(Boolean).map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="dim whitespace-nowrap">{k}</dt>
              <dd className="m-0 break-words min-w-0">{v}</dd>
            </div>
          ))}
        </dl>

        <p className="dim text-[12px] mt-4 leading-relaxed">
          {u && !who.admin && <>Access lasts eight hours from an administrator's approval.
            When it ends, sign in again to place a new request.</>}
          {u && who.admin && <>An administrator's session lasts eight hours and needs no
            approval.</>}
          {who.ended && <>Sign in again to place a new access request.</>}
          {!who.gate && !isDemo() && <>This console was started without
            {" "}<code className="font-mono">--require-access</code>: it serves this machine
            only (127.0.0.1) and asks no one to sign in.</>}
          {!who.gate && isDemo() && <>A public demonstration of the interface, on
            synthetic cases. There is no account to sign in to.</>}
        </p>

        <div className="flex flex-wrap justify-end gap-2 mt-5">
          <button type="button" onClick={() => dlg.current.close()}
            className="hairline border rounded-[var(--radius-panel)] px-4 py-2 text-[13px]
              cursor-pointer hover:border-accent">Close</button>
          {u && <LogoutForm csrf={u.csrf}
            className="border border-danger/50 text-danger rounded-[var(--radius-panel)] px-4
              py-2 text-[13px] cursor-pointer hover:bg-danger/10 inline-flex items-center gap-1" />}
          {who.ended && <a href="/access/login" className="border border-accent/50 text-accent
            rounded-[var(--radius-panel)] px-4 py-2 text-[13px]">Sign in again</a>}
        </div>
      </div>
    </dialog>
  );
}
