// Chain of custody (UI_PLAN 6.8): the ledger, drawn as the hash chain it is.
//
// The verdict at the top is not a stored field - report/case.py re-runs
// ledger.verify() on every load.  What this screen shows is therefore a
// check made just now, not a claim the file makes about itself.
import { Section, Card, DL, Empty, Hash } from "../components/index.jsx";
import { num, utcTime } from "../lib/format.js";

const isHash = (v) => typeof v === "string" && /^[0-9a-f]{64}$/i.test(v);

// A ledger detail is whatever the stage recorded: a scalar, a hash, or a
// nested object such as the carve label tally or the timeline's clock rule.
function DetailValue({ v }) {
  if (v === null || v === undefined || v === "") return <span className="dim">&mdash;</span>;
  if (isHash(v)) return <Hash value={v} len={8} />;
  if (typeof v !== "object") return <span className="font-mono">{String(v)}</span>;

  if (Array.isArray(v)) {
    if (!v.length) return <span className="dim">none</span>;
    return (
      <span className="flex flex-wrap gap-1">
        {v.map((x, i) => x && typeof x === "object"
          ? <span key={i} className="block w-full hairline border-l pl-2 my-0.5">
              <DetailValue v={x} /></span>
          : <span key={i} className="hairline border rounded-full px-2 py-px text-[10.5px] dim">
              {String(x)}</span>)}
      </span>
    );
  }
  return (
    <dl className="grid grid-cols-[minmax(110px,auto)_1fr] gap-x-3 gap-y-0.5 text-[11px] mt-0.5">
      {Object.entries(v).map(([k, val]) => (
        <div key={k} className="contents">
          <dt className="dim">{k.replace(/_/g, " ")}</dt>
          <dd className="m-0 break-words"><DetailValue v={val} /></dd>
        </div>
      ))}
    </dl>
  );
}

export default function Custody({ c, reload, toast }) {
  const cu = c.custody || {};
  const entries = cu.entries || [];
  if (!entries.length) {
    return <Empty what="This case has no custody ledger."
      how={`cli.py scan --device <dev> --out ${c.id}`} />;
  }
  const v = cu.verify || {};

  const reverify = async () => {
    await reload();
    toast("Custody chain re-verified");
  };

  return (
    <>
      <Section>
        <Card className={v.valid ? "border-validated/50" : "border-danger/50"}>
          <div className="flex items-center gap-3.5 flex-wrap">
            <div className={`text-[27px] ${v.valid ? "text-validated" : "text-danger"}`}>
              {v.valid ? "✓" : "✗"}
            </div>
            <div>
              <div className={`text-lg font-semibold ${
                v.valid ? "text-validated" : "text-danger"}`}>
                {v.valid ? "Chain intact" : "Chain BROKEN"}
              </div>
              <div className="dim text-[12.5px]">{v.message || ""}</div>
            </div>
            <button onClick={reverify} title="Re-fetch the case and re-run the check"
              className="ml-auto hairline border rounded-lg px-3 py-1.5 text-[12.5px] dim
                hover:text-accent hover:border-accent cursor-pointer">
              Re-verify
            </button>
          </div>
          <div className="mt-3">
            <DL rows={[
              ["Entries", num(entries.length)],
              ["Head", <Hash value={cu.head} len={12} />],
            ]} />
          </div>
          <p className="dim text-[12px] mt-3">
            Each entry hashes its own contents and its predecessor's hash. Changing any
            entry after the fact changes every hash after it, which is what makes this
            checkable rather than merely written down.
          </p>
        </Card>
      </Section>

      <Section title="Examiner signatures"
        hint="RSA-PSS over the device, the hashes, the ledger head and every output">
        <Signatures sg={c.signatures} />
      </Section>

      <Section title="Ledger" hint="oldest first · times are UTC, as recorded">
        <ol className="list-none m-0 pl-6 relative">
          {/* the spine of the chain */}
          <span className="absolute left-1.5 top-1.5 bottom-1.5 w-px hairline border-l" />
          {entries.map((e, i) => {
            const det = e.detail && typeof e.detail === "object" ? e.detail : null;
            return (
              <li key={e.entry_hash || i} className="relative pb-4">
                {/* sits above the spine, which runs behind it */}
                <span className={`absolute -left-[18px] top-1.5 w-2.5 h-2.5 rounded-full z-10
                  ${v.valid ? "bg-validated" : "bg-danger"}`} />
                <div className="font-semibold text-[13px]">
                  {e.seq != null && <span className="dim">{e.seq}. </span>}
                  {String(e.action || "").replace(/_/g, " ")}
                </div>
                <div className="dim font-mono text-[11.5px]">
                  {utcTime(e.ts_utc)} UTC &middot; {e.actor || ""}
                  {e.case_id && <> &middot; {e.case_id}</>}
                </div>
                {det ? (
                  <div className="mt-1">
                    <dl className="grid grid-cols-[minmax(120px,auto)_1fr] gap-x-3.5 gap-y-0.5
                      text-[11.5px]">
                      {Object.entries(det).map(([k, val]) => (
                        <div key={k} className="contents">
                          <dt className="dim">{k.replace(/_/g, " ")}</dt>
                          <dd className="m-0 break-words"><DetailValue v={val} /></dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                ) : e.detail ? <div className="text-[12px] mt-1">{String(e.detail)}</div> : null}
                <div className="dim font-mono text-[11.5px] mt-1.5 flex items-center gap-1.5
                  flex-wrap">
                  entry <Hash value={e.entry_hash} len={7} />
                  &larr; prev <Hash value={e.prev_hash} len={7} />
                  {e.data_hash && <>&middot; data <Hash value={e.data_hash} len={7} /></>}
                </div>
              </li>
            );
          })}
        </ol>
      </Section>
    </>
  );
}

// What `cli.py verify` says about the examiner signatures, as of this load.
// A signature is checked here against the key it carries: that proves the
// files are what was signed, and whose key it was only once the key is one
// the examiner published - so the fingerprint is shown in full on hover.
function Signatures({ sg }) {
  if (!sg || !sg.signed) {
    return (
      <Card>
        <p className="dim text-[12.5px] m-0">
          Not signed: no examiner key was used on this case. <span className="font-mono">
          cli.py keygen</span> then <span className="font-mono">cli.py sign</span> adds a check
          anyone can run with the examiner's public key, without trusting this machine.
        </p>
      </Card>
    );
  }
  return (
    <Card className={sg.valid ? "border-validated/50" : "border-danger/50"}>
      <div className={`font-semibold ${sg.valid ? "text-validated" : "text-danger"}`}>
        {sg.valid ? "✓ " : "✗ "}{sg.message}</div>
      <ul className="list-none m-0 mt-2.5 p-0 grid gap-1.5">
        {(sg.signatures || []).map((s) => (
          <li key={s.file} className="text-[12.5px] flex flex-wrap gap-x-3 gap-y-0.5">
            <span className={s.valid ? "text-validated" : "text-danger"}>
              {s.valid ? "valid" : "FAILED"}</span>
            <span className="font-mono dim">{s.file}</span>
            <span>{s.signer || "unnamed key"}</span>
            <span className="font-mono dim" title={s.fingerprint}>key {s.key_id}</span>
            <span className="dim">{utcTime(s.signed_utc)} UTC</span>
            {!s.valid && <span className="text-danger basis-full">
              {(s.problems || []).join("; ")}</span>}
            {s.unsigned_newer && s.unsigned_newer.length > 0 && (
              <span className="dim basis-full">newer, not yet signed: {s.unsigned_newer.join(", ")}</span>)}
          </li>
        ))}
      </ul>
    </Card>
  );
}
