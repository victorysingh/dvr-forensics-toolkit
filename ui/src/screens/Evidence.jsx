// Evidence and acquisition (UI_PLAN 6.2): how the image was taken, what it
// hashed to, and what the block map says about the platter.
//
// The painted disk map is P3, once /api/case/<id>/blockmap exists.  What is
// here now is the device record, the hashes with their scope, the scan
// statistics and the entropy-vs-video verdict.
import { Section, Card, DL, Hash, Empty, DataTable } from "../components/index.jsx";
import { bytes, num, pct, dur, hex } from "../lib/format.js";

export default function Evidence({ c }) {
  const s = c.scan;

  if (!s) {
    return c.in_progress ? (
      <Card>
        <h3 className="dim text-[13px] uppercase font-semibold mb-2.5">Acquisition in progress</h3>
        <div className="panel-2 h-1.5 rounded-full overflow-hidden">
          <i className="block h-full bg-accent rounded-full"
            style={{ width: pct(c.in_progress.fraction) }} />
        </div>
        <p className="dim text-[12.5px] mt-2">
          {bytes(c.in_progress.bytes_done)} of {bytes(c.in_progress.size_bytes)} read
          &mdash; updated {c.in_progress.updated_utc} UTC
        </p>
      </Card>
    ) : (
      <Empty what="No acquisition for this case."
        how={`cli.py scan --device <dev> --out ${c.id}`} />
    );
  }

  const d = s.device || {}, st = s.stats || {}, r = c.regions;

  return (
    <>
      <Section title="Device">
        <Card>
          <DL rows={[
            ["Path", <span className="font-mono break-all">{d.path}</span>],
            ["Model", d.model || "—"],
            ["Serial", d.serial || "—"],
            ["Size", <>{bytes(d.size_bytes)}{" "}
              <span className="dim">({num(d.size_bytes)} bytes)</span></>],
            ["Sector size", `${num(d.sector_size)} B`],
            ["Bus", d.bus_type || "—"],
            ["Write block", d.write_block_method || "—"],
          ]} />
        </Card>
      </Section>

      <Section title="Hashes"
        hint="scope is part of the claim — a triage hash covers only what was read">
        <Card>
          <DL rows={[
            ...(s.hashes || []).map((h) => [
              h.algorithm.toUpperCase(),
              <>
                <Hash value={h.value} len={12} />
                <div className="dim text-[11.5px]">
                  {h.scope} &middot; offset {num(h.offset)} &middot; {bytes(h.length)}
                  {h.computed_utc && <> &middot; {h.computed_utc}</>}
                </div>
              </>,
            ]),
            s.merkle_root && ["Merkle root",
              <>
                <Hash value={s.merkle_root} len={12} />
                <div className="dim text-[11.5px]">
                  root of the per-block hash tree in blockmap.jsonl</div>
              </>],
          ]} />
        </Card>
      </Section>

      <Section title="Scan">
        <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(200px,1fr))]">
          <Card>
            <div className="dim text-[11.5px] uppercase tracking-wide">Bytes read</div>
            <div className="text-[26px] font-semibold leading-tight">{bytes(st.bytes_read)}</div>
            <div className="dim text-[11.5px]">
              {num(st.blocks_hashed)} blocks of {bytes(st.block_size)}</div>
          </Card>
          <Card>
            <div className="dim text-[11.5px] uppercase tracking-wide">Throughput</div>
            <div className="text-[26px] font-semibold leading-tight">
              {Number(st.throughput_mbps || 0).toFixed(2)}</div>
            <div className="dim text-[11.5px]">MB/s over {dur(st.duration_s)}</div>
          </Card>
          <Card>
            <div className="dim text-[11.5px] uppercase tracking-wide">Bad sectors</div>
            <div className={`text-[26px] font-semibold leading-tight
              ${st.bad_sectors ? "text-danger" : ""}`}>{num(st.bad_sectors)}</div>
            <div className="dim text-[11.5px]">
              {st.bad_sectors ? "see bad regions below" : "none encountered"}</div>
          </Card>
          <Card>
            <div className="dim text-[11.5px] uppercase tracking-wide">Pass</div>
            <div className="text-[19px] font-semibold leading-tight mt-1">
              {st.complete_pass ? "complete" : "partial (triage)"}</div>
            <div className="dim text-[11.5px]">
              {st.complete_pass ? "every block of the device was read"
                                : "only the region above was read"}</div>
          </Card>
        </div>
      </Section>

      {r && (
        <Section title="Entropy vs video structure" hint={`from regions.json · rule ${r.rule}`}>
          <Card>
            <p className="font-semibold mb-2.5">{r.verdict}</p>
            <DL rows={[
              ...Object.entries(r.counts || {}).map(([k, v]) =>
                [k.replace(/_/g, " "), `${num(v)} block(s)`]),
              ["Written blocks", num(r.written_blocks)],
              ["Flagged", `${num(r.flagged_blocks)} (${pct(r.flagged_share)})`],
            ]} />
            <p className="dim text-[12px] mt-3">
              A block that is incompressible but carries no video structure is the
              signature an encrypted region would leave. Counting them is how this tool
              can say &ldquo;nothing here looks encrypted&rdquo; without guessing.
            </p>
          </Card>
        </Section>
      )}

      {c.preserved && (
        <Section title="Preserved metadata">
          <Card>
            <DL rows={[
              ["Blocks", `${num(c.preserved.blocks)} · ${bytes(c.preserved.bytes_saved)}`],
              ["All blocks match", c.preserved.all_blocks_match
                ? <span className="text-validated">yes</span>
                : <span className="text-danger">NO</span>],
              ["Merkle root", <Hash value={c.preserved.merkle_root} len={10} />],
              ["Manifest", <Hash value={c.preserved.manifest_sha256} len={10} />],
            ]} />
          </Card>
        </Section>
      )}

      {(s.bad_regions || []).length > 0 && (
        <Section title={<span className="text-danger">Bad regions</span>}>
          <DataTable search={false}
            rows={s.bad_regions.map((b, i) => ({ ...b, __k: i }))}
            cols={[
              { key: "offset", label: "Offset", cls: "text-right font-mono", sort: "num",
                render: (x) => hex(x.offset) },
              { key: "length", label: "Length", cls: "text-right font-mono", sort: "num",
                render: (x) => bytes(x.length) },
              { key: "error", label: "Error" },
            ]} />
        </Section>
      )}
    </>
  );
}
