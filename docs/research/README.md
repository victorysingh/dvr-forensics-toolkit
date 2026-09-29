# Research notes (28-29 Sep 2026) - working notes, not yet reviewed

**Start with `SUMMARY.md`**: both hunts on one page, what the team has
already acted on, and what to do next.

The notes themselves are leads to check, not citations. Verify any claim
here before it goes into `RESEARCH_BASIS.md`, `OEM_COMPARISON.md` or the
final report.

Hunt 1 (28-29 Sep):

- `papers_usp.md`: papers, competitors (other SIH26150 teams, open-source and
  commercial tools) and the USP. Its SUMMARY gives:
  - 5 claims that hold up;
  - what is **not** unique (so it is not presented as a differentiator);
  - 3 gaps to close - an OSD cross-check, stale tails inside in-use blocks,
    and encryption labelling - all since acted on.
- `datasets.md`: public DVR/NVR data. It covers:
  - what is downloadable and verified (FFmpeg recorder samples, TP-Link VIGI
    and Uniview firmware);
  - what is mentioned but not public;
  - OEM and rebrand evidence for Godrej and Matrix;
  - what was searched and found nothing.

Hunt 2 (29 Sep, a deeper second pass on the same questions):

- `usp_papers_deep.md`: the USP stress-tested again; papers found by
  citation chaining; validation standards (SWGDE, UK FSR); Indian case law
  and government guidance; new rivals.
- `datasets_deep.md`: new data sources (a native Hikvision file, a second
  mirror of the NIST image with its licence and file listing) and firmware
  (TP-Link, Honeywell, Qualvision).
- `vendor_formats.md`: TP-Link, Uniview, Godrej/Qualvision, Matrix and
  Honeywell, from their firmware and official documents. The Uniview and
  TP-Link parts became the plugins in PR #43, whose `fwread/` folder holds
  the readers used, to re-derive them.

Both hunts were stopped early by the usage limit. The downloaded PDFs,
firmware and pages behind these notes (several hundred MB) are not in git;
they are on JP's machine under `C:\Users\JAIPREET SINGH\150\research\`
(hunt 2 in `hunt2\`).
