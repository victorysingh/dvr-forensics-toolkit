// Start here (viewer/guide.py): pick the recorder's brand, see what the tool
// can honestly do for it, and the steps from a disk in hand to a case on this
// console.
//
// Not a case screen: it lives at #/start and #/start/<brand>, so a picked
// brand can be sent to a colleague as a link like any other screen.
import { useState } from "react";
import { Section, Card, DL, Pill, Empty } from "../components/index.jsx";
import { linkTo } from "../lib/useHashRoute.js";
import { isDemo } from "../lib/host.js";
import { bytes } from "../lib/format.js";

export const slug = (vendor) => vendor.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

// What a status means to someone who has never seen the word. The weakest
// evidence sets it (detect/engine.py), so it is the honest headline.
const MEANS = {
  validated: "Checked byte for byte against the recorder's own export.",
  spec_only: "Parser written and tested, but not yet byte-matched against this "
    + "brand's own export: treat what it reports as unconfirmed until the SOP's checks are done.",
  detected_not_parsed: "Recognised on the disk; no parser yet. The footage is still "
    + "recovered by carving.",
  synthetic_only: "Only ever tested on generated disks.",
};

// The same statuses in plain words, for the pill a newcomer reads. The raw
// word stays on the Vendors screen.
const PLAIN = {
  validated: "validated",
  spec_only: "not yet validated",
  detected_not_parsed: "detected, not parsed",
  synthetic_only: "generated disks only",
};

// Whether a real drive of this brand has been read comes from the vendor
// matrix (`media`), never from the guide's own words.
const realDisk = (b) => Boolean(b.status && b.media && b.media !== "none");

// The brands grouped by what is actually behind each one, so the first thing
// a newcomer sees is which brands have been read off a real drive.
const GROUPS = [
  { title: "Read from a real disk", mark: "\u25CF", tone: "text-accent",
    hint: "the parser has run on a real recorder's drive of this brand",
    has: realDisk },
  { title: "No real disk yet", mark: "\u25CB", tone: "dim",
    hint: "written from the brand's own software or documents; the footage is "
      + "recovered by carving either way",
    has: (b) => b.status && !realDisk(b) },
  { title: "Not sure, or another brand", mark: "?", tone: "dim", hint: "",
    has: (b) => !b.status },
];

// CP Plus boards are Dahua-built, so a CP Plus disk usually scores as Dahua:
// either case shows how that family's disks look here.
const FAMILY = { "CP Plus": ["CP Plus", "Dahua"], Dahua: ["Dahua", "CP Plus"] };

export default function StartHere({ guide, cases, brand }) {
  if (!guide || !(guide.brands || []).length) {
    return <Empty what="The brand guide did not load from the server."
      how="python cli.py serve --out out" />;
  }
  const picked = guide.brands.find((b) => slug(b.vendor) === brand) || null;
  return (
    <div className="max-w-[1100px] mx-auto">
      <h1 className="display text-[22px] font-semibold">Start here</h1>
      <p className="dim text-[13px] mt-0.5 max-w-[760px]">
        Pick the brand on the recorder's label. You do not have to be sure: the scan
        identifies the brand from the disk itself, so this only tells you what to
        expect and which options to add.</p>
      {isDemo() && (
        <p className="text-[12.5px] mt-3 rounded-lg border border-synthetic/45 bg-synthetic/10
          px-3 py-2 max-w-[760px]">
          This is a copy hosted for review. The steps run on your own forensic
          workstation, offline - a disk is never connected to a website.</p>
      )}

      {GROUPS.map((g) => {
        const list = guide.brands.filter(g.has);
        return list.length > 0 && (
          <section key={g.title} className="mt-5">
            <h2 className="text-[13.5px] font-semibold mb-2 flex flex-wrap items-baseline gap-x-2">
              <span className={g.tone} aria-hidden="true">{g.mark}</span>{g.title}
              {g.hint && <span className="dim text-[11.5px] font-normal">{g.hint}</span>}</h2>
            <div className="grid gap-2.5 grid-cols-[repeat(auto-fill,minmax(200px,1fr))]"
              role="list" aria-label={g.title}>
              {list.map((b) => <BrandCard key={b.vendor} b={b}
                on={!!picked && picked.vendor === b.vendor} />)}
            </div>
          </section>
        );
      })}
      <ValidatedNote brands={guide.brands} />

      {picked
        ? <BrandPlan b={picked} steps={guide.steps} cases={cases} />
        : <p className="dim text-[13px] mt-5">Choose a brand to see the steps for it.</p>}
    </div>
  );
}

function BrandCard({ b, on }) {
  return (
    <a role="listitem" href={`#/start/${slug(b.vendor)}`}
      aria-current={on ? "true" : undefined}
      className={`panel px-3.5 py-3 block hover:border-accent group
        ${on ? "border-accent ring-1 ring-accent/40" : ""}`}>
      <div className={`font-semibold text-[14.5px] ${on ? "text-accent" : "group-hover:text-accent"}`}>
        {b.vendor}</div>
      {b.source && <div className="dim text-[11.5px] mt-1 leading-snug">{b.source}</div>}
    </a>
  );
}

// "validated" said once, in words, instead of the same pill on every card.
function ValidatedNote({ brands }) {
  const done = brands.filter((b) => b.status === "validated").map((b) => b.vendor);
  return (
    <p className="dim text-[12px] mt-4 max-w-[820px] leading-relaxed">
      {done.length
        ? <>Validated, that is checked byte for byte against the recorder's own export:{" "}
            <b>{done.join(", ")}</b>. For the others, treat what a parser reports as
            unconfirmed until the SOP's checks are done.</>
        : <>No brand is <b>validated</b> yet, that is checked byte for byte against the
            recorder's own export. Until then, treat what a parser reports as
            unconfirmed and run the SOP's checks before relying on it.</>}</p>
  );
}

function BrandPlan({ b, steps, cases }) {
  const flags = b.flags ? ` ${b.flags}` : "";
  const family = FAMILY[b.vendor] || [b.vendor];
  const examples = (cases || []).filter((c) => c.complete && family.includes(c.vendor));
  return (
    <>
      <Section title={`What to expect for ${b.vendor}`}>
        <Card>
          <p className="text-[13px] leading-relaxed mb-3">{b.note}</p>
          <DL rows={[
            b.status && ["Status", <span key="s" className="inline-flex items-start gap-2 flex-wrap">
              <Pill status={b.status} label={PLAIN[b.status]} />
              <span className="dim text-[12px]">{MEANS[b.status] || ""}</span></span>],
            b.family && ["Parsed as", b.family],
            b.status && ["Real disk read", realDisk(b) ? b.media : "none yet"],
          ]} />
        </Card>
      </Section>

      <Section title="From disk to case" hint="four steps, the same for every brand">
        <ol className="grid gap-2.5">
          {steps.map((s, i) => (
            <li key={s.title} className="panel p-3.5 grid grid-cols-[28px_1fr] gap-x-3">
              <span className="w-7 h-7 rounded-full border border-accent/50 text-accent
                grid place-items-center text-[13px] font-semibold">{i + 1}</span>
              <div className="min-w-0">
                <div className="font-semibold text-[14px]">{s.title}</div>
                <p className="dim text-[12.5px] mt-0.5 leading-relaxed">{s.what}</p>
                {s.cmd && <Command text={s.cmd.replace("{flags}", flags)} />}
              </div>
            </li>
          ))}
        </ol>
      </Section>

      {(b.after || []).length > 0 && (
        <Section title={`Then, for ${b.vendor}`} hint="recordings, footage and logs, from the same disk">
          <Command text={b.after.join("\n")} />
        </Section>
      )}

      <Section title="See it on a case">
        {examples.length ? (
          <div className="grid gap-2 grid-cols-[repeat(auto-fill,minmax(260px,1fr))]">
            {examples.map((c) => (
              <a key={c.id} href={linkTo(c.id, "dashboard")}
                className="panel px-3.5 py-2.5 hover:border-accent group block">
                <div className="font-semibold text-[13.5px] break-all group-hover:text-accent">{c.id}</div>
                <div className="dim text-[11.5px] mt-0.5">
                  detected as {c.vendor} &middot; {bytes(c.size_bytes)}
                  {c.synthetic && <span className="text-synthetic"> &middot; generated disk</span>}</div>
              </a>
            ))}
          </div>
        ) : (
          <p className="dim text-[12.5px]">No case of this brand on this console yet.</p>
        )}
      </Section>

      <p className="dim text-[12px] mt-6 leading-relaxed max-w-[820px]">
        With the packaged <b>ps26150-dvr.exe</b>, type <code>ps26150-dvr</code> where these
        say <code>python cli.py</code>. On Windows the disk is <code>\\.\PhysicalDriveN</code>{" "}
        behind a hardware write blocker. The full procedure, with seizure notes and the
        checks before a result is relied on, is in <code>docs/USER_MANUAL.md</code> &sect;3
        and <code>docs/SOP_EXAMINATION.md</code>.</p>
    </>
  );
}

// A command block with one copy button. Copying is a convenience: a browser
// that refuses the clipboard just leaves the text to be selected by hand.
function Command({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    try {
      navigator.clipboard.writeText(text).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }, () => {});
    } catch { /* no clipboard here */ }
  };
  return (
    <div className="relative mt-2">
      <pre className="panel-2 hairline border rounded-lg px-3 py-2 pr-16 font-mono text-[12px]
        overflow-x-auto whitespace-pre">{text}</pre>
      <button type="button" onClick={copy}
        className="absolute top-1.5 right-1.5 hairline border rounded px-2 py-0.5 text-[11px]
          panel hover:border-accent">{copied ? "copied" : "copy"}</button>
    </div>
  );
}
