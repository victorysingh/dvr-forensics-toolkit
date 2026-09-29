// The case as one argument, in order.
//
// The nine screens were named after the files the pipeline wrote, which is
// the pipeline's shape, not the examiner's. These sections are the claims the
// tool actually makes, strongest evidence first, each carrying how strongly
// it can be made - which FINAL_REPORT §1 names as the whole design rule:
// "claim only what has been demonstrated, and say how strongly."
//
// Two of them are the differentiators nothing else in the category has
// (FINAL_REPORT §8): footage recovered from under another vendor's reformat,
// and a clock the tool refuses to convert without stated inputs. They are
// written to be read, not skimmed.
import { bytes, num, pct, pct0, dur, hex, clockTime, firstLocal } from "../lib/format.js";

/* Each section:
     id        anchor, and the rail's label
     rail      short name for the section rail
     title     the claim, as a sentence
     lead      one paragraph; the argument, not a caption
     figures   [{ value, label, tone? }]
     strength  { status, note }   how strongly this can be claimed
     cites     [{ file, hash }]
     marks     which platter mark kinds this section lights up
     detail    the existing screen component, as "show the evidence"
     absent    when the stage has not run: one honest line instead
*/

export function buildSections(c) {
  const s = c.scan;
  const det = s?.detections?.[0];
  const carve = c.carve;
  const labels = carve?.labels || {};
  const outside = labels.outside_index;
  const tl = c.timeline;
  const an = c.analytics;
  const cu = c.custody;
  const parse = c.parse;

  const S = [];

  /* ── 1. the drive ───────────────────────────────────────────────────── */
  S.push({
    id: "drive",
    rail: "The drive",
    title: s
      ? (s.stats?.complete_pass
          ? "Every block of this drive was read once, and hashed."
          : "The first region of this drive was read once, and hashed.")
      : "This drive has not been acquired.",
    lead: s
      ? `The drive was opened read-only and read in a single pass — no write path
         exists in the acquisition code. Each block carries its own SHA-256 and
         the blocks roll up into a Merkle root, so an interruption can be
         resumed and a later change can be named to the block rather than
         merely detected somewhere on the platter.`
      : null,
    figures: s ? [
      { value: bytes(s.device?.size_bytes), label: "drive" },
      { value: num(s.stats?.blocks_hashed), label: "blocks hashed" },
      { value: s.stats?.bad_sectors ? num(s.stats.bad_sectors) : "none",
        label: "bad sectors", tone: s.stats?.bad_sectors ? "danger" : null },
      { value: `${Number(s.stats?.throughput_mbps || 0).toFixed(1)} MB/s`,
        label: `one pass, ${dur(s.stats?.duration_s)}` },
    ] : [],
    strength: s ? {
      status: s.stats?.complete_pass ? "validated" : "spec_only",
      note: s.stats?.complete_pass
        ? "Whole-device hashes. The scope of every hash is stated with it."
        : `A triage pass: the hashes below cover ${bytes(s.stats?.bytes_read)}, not the whole drive.`,
    } : null,
    cites: [
      { file: "scan_report.json", hash: c.files?.["scan_report.json"] },
      { file: "blockmap.jsonl", hash: c.files?.["blockmap.jsonl"] },
    ],
    marks: [],
    detail: "evidence",
    absent: s ? null : `Run cli.py scan --device <dev> --out ${c.id}`,
  });

  /* ── 2. what it is ──────────────────────────────────────────────────── */
  S.push({
    id: "identity",
    rail: "What it is",
    title: det
      ? `The platter carries ${det.vendor} structures.`
      : "No vendor signature matched this platter.",
    lead: det
      ? `Identification is scored, never asserted. ${num(det.hit_count)} signature
         hits were found and weighed; the figure below is the detector's own
         confidence, not a probability that the device is guilty of anything.
         CP Plus units are commonly Dahua-built, so the disk is allowed to say
         "Dahua-family" and let the seized unit's label settle the rest.`
      : `An unknown platter still gets entropy, codec and filesystem maps, and
         footage can still be carved from it without any parser at all.`,
    figures: det ? [
      { value: det.vendor, label: "vendor" },
      { value: pct(det.confidence), label: "confidence" },
      { value: num(det.hit_count), label: "signature hits" },
    ] : [],
    strength: det ? {
      status: det.validation_status,
      note: statusNote(det.validation_status),
    } : null,
    cites: [{ file: "scan_report.json", hash: c.files?.["scan_report.json"] }],
    marks: [],
    detail: "vendors",
    absent: null,
  });

  /* ── 3. what the recorder says it holds ─────────────────────────────── */
  const cams = parse ? Object.keys(parse.per_camera || {}).length : 0;
  S.push({
    id: "index",
    rail: "Its own index",
    title: parse
      ? `The recorder's own index lists ${num(parse.recordings_total)} recordings.`
      : "The recorder's index has not been parsed.",
    lead: parse
      ? `This is the device's own account of what it holds, read from documented
         offsets. Every field below can be traced to where it was read and to the
         source that documents it — the provenance table is part of the claim,
         not a footnote to it.`
      : null,
    figures: parse ? [
      { value: num(parse.recordings_total), label: "recordings" },
      { value: num(cams), label: cams === 1 ? "camera" : "cameras" },
      { value: num(parse.remnants_total), label: "index remnants" },
    ] : [],
    strength: parse ? {
      status: parse.validation_status,
      note: statusNote(parse.validation_status),
    } : null,
    cites: parse ? [{ file: parse.file, hash: parse.sha256 }] : [],
    marks: ["indexed"],
    detail: "recordings",
    absent: parse ? null
      : `No parser has run over this platter. Run cli.py parse --device <dev> --out ${c.id}`,
  });

  /* ── 4. what the recorder forgot ── the headline differentiator ─────── */
  S.push({
    id: "forgotten",
    rail: "What it forgot",
    emphasis: true,
    title: outside
      ? `${num(outside.streams)} stream${outside.streams === 1 ? "" : "s"} of footage survive that the index no longer lists.`
      : carve
        ? "Every recovered stream is accounted for by the index."
        : "No carving has run over this platter.",
    lead: outside
      ? `These frames are on the platter, but the recorder's own index does not
         mention them — footage deleted, rotated past, or left behind when the
         disk was reformatted. Recovering them needs no parser and no index,
         which is why it works on vendors this tool cannot yet parse, and why it
         survives a different manufacturer's recorder reformatting the drive.
         Where frames carry no camera number, streams are separated by
         continuity and are split rather than merged: a stream whose camera
         cannot be told apart is never silently joined to another. Run beside
         the newest open DHFS tool on a disk of known contents, both found the
         same frames and only this one separated the three cameras.`
      : carve
        ? `Everything carved matches an index record. That is the ordinary case,
           and it is worth stating plainly rather than leaving blank.`
        : null,
    figures: outside ? [
      { value: num(outside.streams), label: "streams outside the index", tone: "synthetic" },
      { value: num(outside.frames), label: "frames" },
      { value: bytes(outside.bytes), label: "recovered" },
    ] : carve ? [
      { value: num(carve.stats?.streams_kept), label: "streams carved" },
      { value: num(carve.stats?.frames), label: "frames" },
    ] : [],
    strength: carve ? {
      status: carve.validation_status,
      note: `Carved by frame structure, not by trusting any index. `
        + `${num(carve.stats?.joined_by_contiguity || 0)} frames joined by contiguity, `
        + `${num(carve.stats?.ambiguous_splits || 0)} ambiguous splits.`,
    } : null,
    cites: carve ? [{ file: "carve/carve_report.json", hash: carve.sha256 }] : [],
    marks: ["outside"],
    detail: "recovered",
    absent: carve ? null : `Run cli.py carve --device <dev> --out ${c.id}`,
  });

  /* ── 5. when ── the refusal, which is the point ─────────────────────── */
  const counts = tl?.counts || {};
  S.push({
    id: "when",
    rail: "When",
    emphasis: true,
    title: tl
      ? "These times are the recorder's own clock, and are not converted."
      : "No timeline has been built.",
    lead: tl
      ? `${sentence(tl.clock?.rule) || "The recorder's zone was not stated, so no UTC is asserted."}
         A recorder keeps local time on a clock nobody audits, and a tool that
         silently prints UTC is inventing the one fact a court is most likely to
         test. So the conversion is refused until the zone and the clock's error
         are known — from the unit itself, from its own system log, or from
         where the cameras' infrared switches put dusk and dawn.`
      : null,
    figures: tl ? [
      { value: num(counts.indexed || 0), label: "indexed" },
      { value: num(counts.unindexed || 0), label: "unindexed", tone: "synthetic" },
      { value: num((tl.gaps || []).length), label: "gaps",
        tone: (tl.gaps || []).length ? "danger" : null },
    ] : [],
    strength: tl ? {
      status: "spec_only",
      note: "A gap is an absence of footage, not proof of deletion. Stated as found.",
    } : null,
    cites: tl ? [{ file: "timeline.json", hash: tl.sha256 }] : [],
    marks: ["indexed", "outside"],
    detail: "timeline",
    refusal: tl ? "No UTC is asserted for this case." : null,
    absent: tl ? null : `Run cli.py timeline --out ${c.id}`,
  });

  /* ── 6. leads ───────────────────────────────────────────────────────── */
  S.push({
    id: "leads",
    rail: "Leads",
    title: an
      ? "A detector marked frames worth an examiner's eye."
      : "No detector has been run over this footage.",
    lead: `Anything a model produced is a lead, never evidence. This is
      detection, not recognition: nothing here identifies a person. A detector
      on this project once scored a steel pot as a face at 0.99, which is
      exactly why its output is labelled and scored rather than asserted.`,
    figures: an ? [
      ...Object.entries(an.totals || {}).slice(0, 2).map(([k, v]) => ({
        value: num(v), label: k.replace(/_/g, " "), tone: "lead",
      })),
      { value: num(an.frames_analysed), label: "frames analysed" },
    ] : [],
    strength: an ? { status: an.status, note: "Leads for an examiner to check by eye." } : null,
    cites: an ? [{ file: "analytics/analytics.json", hash: an.sha256 }] : [],
    marks: [],
    detail: "ai",
    absent: an ? null : `Run cli.py analyse-video --out ${c.id} --fps 1`,
  });

  /* ── 7. the chain ───────────────────────────────────────────────────── */
  const ver = cu?.verify;
  S.push({
    id: "chain",
    rail: "The chain",
    title: ver?.valid
      ? `Every action taken against this evidence is recorded, and the chain holds.`
      : `The custody chain does not verify.`,
    lead: `Each entry hashes its own contents together with the hash of the entry
      before it. Editing any past entry — a timestamp, an operator, a hash —
      breaks verification for every entry after it, and the tool names the exact
      sequence number where it breaks. The check below was run just now, on load,
      not read from a field in the file.`,
    figures: cu ? [
      { value: num((cu.entries || []).length), label: "recorded actions" },
      { value: ver?.valid ? "intact" : "BROKEN", label: "chain",
        tone: ver?.valid ? "validated" : "danger" },
    ] : [],
    strength: cu ? {
      status: ver?.valid ? "validated" : "detected_not_parsed",
      note: ver?.message || "",
    } : null,
    cites: [{ file: "custody_ledger.jsonl", hash: c.files?.["custody_ledger.jsonl"] }],
    marks: [],
    detail: "custody",
    absent: null,
  });

  /* ── 8. what a court can use ────────────────────────────────────────── */
  S.push({
    id: "court",
    rail: "For a court",
    title: "A draft certificate, and the files behind every number above.",
    lead: `The tool fills the facts it recorded and leaves blank everything that
      belongs to a person — who owned or operated the device, that it was working
      properly, the declarant's name and signature. Those are not the tool's to
      state. The wording follows the BSA 2023 Schedule as published in the
      Gazette, checked word for word.`,
    figures: [],
    strength: { status: "spec_only", note: "A draft for the party and the expert to complete and sign." },
    cites: [],
    marks: [],
    detail: "exports",
    absent: null,
  });

  return S;
}

// The clock rule is written as a clause, not a sentence, and is quoted
// straight from timeline.json - so give it a full stop rather than editing
// the words the pipeline wrote.
function sentence(t) {
  if (!t) return "";
  const s = String(t).trim();
  return /[.!?]$/.test(s) ? s : s + ".";
}

function statusNote(status) {
  switch (status) {
    case "validated":
      return "Byte-matched against the recorder's own export.";
    case "spec_only":
      return "Read from documented structures and cross-checked, but not yet byte-matched "
           + "against an export from the recorder itself. Nothing is validated without that.";
    case "synthetic_only":
      return "Corroborated only by a generated fixture so far — no real media has confirmed it.";
    case "detected_not_parsed":
      return "The format was recognised on the platter, but its footage is not placed.";
    default:
      return "";
  }
}
