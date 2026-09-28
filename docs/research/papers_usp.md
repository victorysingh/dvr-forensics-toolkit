# PS26150 research hunt: papers, competitors, USP

Started: Mon Sep 28 17:21:06 IST 2026 (running log; sections filled as found)
Session 1: 17:21:06-17:39 IST 28 Sep (stopped by usage limit). Session 2: from 00:27:19 IST 29 Sep.

=====================================================================
# SUMMARY (read this first; detailed notes follow)
=====================================================================

## C. USP - 5 defensible claims (each: claim / evidence / what it beats / how to phrase it safely)

C1. Validated means "matches the recorder's own export, on real drives" - and every format shows which rung it has reached.
- Evidence: D1 status ladder (validated / spec_only / synthetic_only / detected_not_parsed, set by the weakest evidence); D2 two real 1 TB field drives with two acquisition bugs found and fixed on real hardware (the only team found reporting failures found ON real hardware); D12 own E01 reader reproduced FTK's hashes on the NIST CFReDS HeimVision image (note: rival "Trace" reproduced NIST's hashes too, via the Dissect library - so D12 supports C1 but is not unique on its own).
- Beats: of 30+ SIH26150 repos checked, none reports its own real field drives or a comparison with a recorder's native export; the only real media any rival shows is the public NIST HeimVision image (CCTVault, Trace) or one unnamed 28.65 GB image with no ground truth (Universa). The rest validate on synthetic or self-generated images - BhanuPrasad-2006 ("real recorder disks: not yet tested"), VigiTrace ("Nothing here has been validated against physical recorder hardware"), vidrensic ("does not prove universal real-recorder support"), TraceX (tests on images its own generator makes "authentic"), Pramaan/Trinetra (synthetic demos). Literature: Rzayeva 2025 scores "recovered videos / expected videos" on lab drives filming test charts, not byte comparison with exports; Yoon & Hwang 2026 and CARVE use before/after diffs of ONE lab NVR. Commercial tools (Witness, UFS Explorer, VIP) publish no per-format validation.
- Safe phrasing: "Graded labels are not new (vidrensic, BhanuPrasad, AmeyaMorgaonkar use them); ours are earned on real drives against native exports, which SWGDE 17-V-002 (2025) names as best evidence." State exactly which formats are 'validated' today; if none has reached byte-match yet, say "harness proven on real drives, N formats at spec_only".

C2. Recovery from a real drive that a DIFFERENT vendor's recorder had reformatted, with measured coverage.
- Evidence: D3 - about 6,300 h of Hikvision footage carved as MPEG-PS, dated from Hikvision "HK" descriptors, covering 99.6-99.7% of what the surviving HIKBTREE index says was recorded; Hikvision full-FS parser now reads the layout seen on the real drive.
- Beats: no paper tests a cross-vendor reformat (Han 2015 = Hikvision's own init; Ko & Lee 2020 = unallocated area inside HIKVISION FS; Yoon & Hwang = format on the same Honeywell NVR; Rzayeva = lab drives, 93.5% Hikvision videos recovered). A22Z4/hikvision-nvr-recovery recovers after a reset on a real disk but dates blocks by OCR and reports no coverage. SWGDE 17-V-002 names "the DVR might initiate a reformatting" as the risk of re-inserting a drive - this is that case, solved.
- Acknowledge: the per-frame Hikvision time format is documented (Magnet blog, Mar 2022: 5-byte "binary date time"; per-block Unix-epoch ranges), and fmpfeifer/hikextractor has run on real Hikvision drives (JFL DHD-2104N, DS-7208HQHI-SH/A with a failed RTC, "--physical-order") - but through the index, with no coverage figure. The novelty is the cross-vendor-reformat scenario at 6,300 h scale plus the measured coverage, not the timestamp decoding.
- Safe phrasing: do NOT say "beats 91.8%". Say "different, harder scenario; our coverage is measured against the drive's own surviving index, which is itself partial evidence".

C3. Times and events corroborated by independent sources on the same disk, not taken on trust.
- Evidence: D7 two independent routes to the recorder clock, no UTC without a stated zone; CP Plus drive 1: the recorder's own event log matched a 1-minute recorder-wide gap in the recorded video, to the minute; D12: HeimVision recorder's own log and index checked against the disk.
- Beats: Dragonas 2023/2024 (JFS) parse Hikvision/Dahua logs but do not cross-check them against gaps in the video; Magnet's Hikvision date/time note decodes formats with no zone or validation; Vanini et al. 2024 (DFRWS USA) define "time anchors" only for PC examples - the team applies them to DVRs; SWGDE assumes the clock offset must be measured live at the scene; rival Pramaan has Theil-Sen drift estimation on synthetic data only. No published DVR paper found that corroborates log events with recording gaps.
- Safe phrasing: "Corroborated to the minute on one real drive" - one case, not a rate.

C4. Brand is not format: vendor + model + unit identified from the platter and confirmed on the physical unit.
- Evidence: D8; drive 1 decoded to CP Plus CP-UNR-104F1, firmware V1.00.14.00.T, confirmed by the label and System Info photos; unit serial on the platter ties drive to unit.
- Why it matters: IPVM's public OEM directories: CP Plus (Orange Line) is a current Dahua OEM; Honeywell's Performance Series were relabelled Dahua until April 2022 (so an old "Honeywell" in India may need the Dahua parser, not the Yoon & Hwang Honeywell FS); rivals say Godrej = Xiongmai white-label. A tool keyed to brand strings (TraceX's invented "CPPLUS / Aditya Infotech" markers) picks the wrong parser.
- Beats: rivals detect by brand strings on synthetic images. Precedents to acknowledge: Yoon & Hwang (Honeywell sector 34 holds device ID + model), Rzayeva (reports list model/serial). Claim narrowly: "first on Indian-market CP Plus + Hikvision field drives, confirmed against the unit".

C5. Cameras separated on real NVR disks where the channel field says 0 for every frame - and the limits measured, not guessed.
- Evidence: D4 camera separation by stream continuity on Dahua/CP Plus disks where every frame says channel 0, split rather than guessed; D13 no-parser H.264/H.265 carver measured against ground truth: every slice accounted for, 0.07% false, and the "cannot separate identically configured cameras" limit stated.
- Beats: the 2026 DHAV paper the team already cites (Rzayeva, Shayakhmetov, Konakbayev et al., Information 17(5):493, Astana IT Univ. + TSARKA) demultiplexes ONLY by the DHAV channel byte (offset 6) and asserts that on IP NVRs streams "are stored in logically separated areas ... which can be easily extracted on a per-camera basis". The team's real CP Plus/Dahua NVR drives, where every frame says channel 0, contradict that assumption - a citable, field-evidence conflict. That paper's 97.5% "demultiplexing accuracy" is internal consistency only (channel byte uniformity, time monotonicity, SPS/PPS equality) - it says "ground-truth camera positions were not available"; the team's D13 is measured against ground truth. No rival repo reports a false-positive rate on real data; Rzayeva 2025 reports 2.4% false positives (different metric - quote side by side, don't rank).
- Tip: that paper's third invariant (SPS/PPS must stay identical within one camera's file) is a cheap extra splitter for D4 when cameras differ in resolution/profile - cite it.
- CAUTION: CARVE (DFRWS APAC 2026) claims to group fragments by camera using OCR of the on-screen camera label, or PRNU when there is no overlay, on a Honeywell testbed whose 8 cameras were configured identically (Yoon & Hwang setup). So "identical cameras cannot be separated" is a limit of THIS tool, not of the field. Say so and cite CARVE. (Compressed-domain alternative that suits a no-decoder carver: H4VDM, Xiang/Bestagini/Tubaro/Delp 2022, arXiv:2210.11549 - "same device?" from H.264 compression information on small fragments; tested on phones, not CCTV.)

## NOT unique - do not present these as differentiators
N1. Integrity and custody plumbing: MD5+SHA-256, Merkle trees, hash-chained ledger, BSA s.63 certificate drafts (D5, D6, D11). Trinetra-DFIR (block Merkle + hash-chained Merkle audit log + BSA s.63 Part A/B), Pramaan_ (RFC 6962 Merkle inclusion proofs, Ed25519 signing, BSA s.63(4), signed evidence bundle), Pheonix_37, Universa, Karthikraja2345 all have it; prior art Lone & Mir 2019, Schneier & Kelsey 1999. Call it table stakes; the only distinct detail is "in the same single read-only pass as detection and carving", which is engineering, not novelty.
N2. AI analytics as leads, not evidence (D9): Trinetra labels every AI output "investigative lead, not an identification"; Pramaan treats OSD OCR as "recorder-claimed". Common.
N3. Offline / air-gapped, and "tested on NIST CFReDS HeimVision" (D10, D12): many rivals claim offline. At least TWO rivals use the SAME CFReDS HeimVision E01: VinayBU14/CCTVault (via libewf) and Hardik-droid/sih_x "Trace" (via Dissect) - Trace even publishes NIST's full-logical MD5/SHA-1 reproduced, parses search.db (806 records) and decodes 12 HEVC excerpts from 3 files. What stays distinct in D12: your OWN E01 reader reproducing FTK's hashes (no libewf/Dissect), accounting for the whole image rather than a 3-file sample, and the recorder's own LOG checked against the disk. Present D12 as parity-plus, not as a headline. Kaitai .ksy specs for DVR formats: none found on public GitHub - minor but true.
N4. Graded status labels by themselves (see C1).

## Three gaps rivals/papers expose that the team can still close before the final
G1. Third, pixel-based route for time and camera: read the burned-in OSD timestamp and camera label as a CROSS-CHECK labelled "recorder-claimed" (Lehri & Roy 2022 IFIP tool - co-author Anyesh Roy appears to be a Delhi Police officer and the tool's SourceForge account is "lea-i4c", so likely Indian law-enforcement work, unconfirmed; A22Z4; CARVE; Pramaan). It gives a third time anchor for C3 and a documented route past the D13 identical-camera limit. Cheapest version without ML: template matching on the digit font, as Pramaan does; keep it optional so the stdlib-only core is untouched. (Also cheap: SPS/VPS parameter fingerprints to split cameras whose encoder settings differ - DFRWS APAC 2025 "Tracing Messenger Transmission Pathways of Videos Using SPS NALU".)
G2. Stale tails inside in-use blocks: Byun, Shim, Kim 2026 (JFS) found "video file slack" in pre-allocated recording files expands recoverable area by up to 966.7% on dashcams. Hikvision's pre-allocated 1 GB blocks and Dahua's fixed files have the same mechanism. Report older-cycle footage found past the live write pointer as a separate class, with its own status.
G3. Encryption: detect and label it (entropy + missing signatures -> detected_not_parsed: encrypted) instead of silently carving nothing. Rzayeva's only loss to commercial tools was encrypted disks (43% vs 78-82%); India's STQC regime (sale of non-certified CCTV barred from 1 Apr 2026) tests "storage and encryption of data", and CP Plus ships "STQC Phase-II" NVR firmware (Dec 2025). Check whether the CP-UNR-104F1's firmware offers HDD/stream encryption and say what the tool does with it.
(Optional G6: export recovered clips in the NIST CCTV Digital Video Export Profile - NISTIR 8161 Rev.1 (Apr 2019), "Level 0": MP4 + H.264 with MISB embedded time codes + an XMP / UUID "ClockOffset" box stating the DVR system-clock offset. It turns D7's "no UTC without a stated zone" into a standard, machine-readable field in every exported clip; developed with FBI input; no rival implements it (byteforce101 only mentions it in a doc). https://doi.org/10.6028/NIST.IR.8161r1)
(Optional G4: a scripted, reproducible scenario list on the CP Plus unit - record / delete / format / overwrite / clock change, native export after each step - modelled on Eichhorn, Gabel, Freiling DFRWS USA 2026 WiBtL; turns each status upgrade into something a judge can re-run. G5: run free rivals (DVRExtractor, hikextractor, ffmpeg dhav, dhfs_extractor) on the team's images and publish a difference table - a head-to-head like Rzayeva's without buying commercial licences.)

## B. Competitor table (brief; details and sources below)
| Tool | Vendors / formats claimed | Shown on real media? | Price / licence | Main gaps vs PS26150 |
|---|---|---|---|---|
| Magnet Witness (ex DVR Examiner, DME Forensics) | "over 50 native or proprietary DVR file formats" + cloud (Ring, Arlo); no public list | No vendor accuracy study; Rzayeva 2025 lab drives: 89.2% Hikvision, 84.8% Dahua videos recovered | Commercial, by quote | Closed; no per-format validation disclosed; no Indian-brand (CP Plus/Matrix/Godrej) claims |
| UFS Explorer Video Recovery (SysDev) | WFS, DHFS, HIK, Mirage, Pinetron, BKFL, dVfE, MDFS, Rsfs, SFMR, TPFS, UAVtech; ~130 stream formats; disk offset of every frame; Hik/Dahua event logs; RAID | Vendor claims only | EUR 8,000/yr commercial; gov ~EUR 3,584/yr (5-yr); Windows | No validation status; no custody ledger / BSA |
| SalvationDATA VIP 2.0 / 3.0 | "patented" auto FS identification; Honeywell, Dahua, Hikvision, Sony, Samsung, iCatch; disk + network | Rzayeva: 91.3% Hik, 87.2% Dahua (best commercial) | HW+SW, by quote | Closed; Chinese vendor (procurement sensitivity); no public validation |
| DiskInternals DVR Recovery | Hikvision DVR/NVR/NAS, Dahua DHFS (+iSCSI), RAID | Rzayeva: 84.7% Hik, 78.9% Dahua | from USD 199; trial preview only | Recovery tool, not forensic; "cannot recover overwritten" |
| 512 BYTE / Dolphin DVR | per-vendor modules (Uniview NVR, WFS, DHFS, iCatch, AVTECH, ZENO...); Dolphin: "Uniview 0x11 / 0x1C" | Vendor claims | ~EUR 119 per module / not listed | One vendor per product; no multi-vendor timeline |
| Amped DVRConv / Replay / FIVE | "hundreds" of proprietary EXPORT/player files | n/a (exports, not disks) | Commercial | No disk images, no deleted recovery |
| X-Ways + Wullen X-Tensions; TSK/Autopsy; ffmpeg | DHFS4.1 and HIK.2011.03.08 (X-Ways); TSK none (KU DFRC fork carpe-sleuthkit: HIKBTREE); ffmpeg DHAV container | Community | X-Ways licence; free | Two vendors / container only |
| Free OSS: DVRExtractor (Brazil), hikextractor, dhfs_extractor, A22Z4 | DHFS4.1, WFS0.X, HIKVISION, ZENO, RSFS, TVT, QFAT, IFS, JUAN (DVRExtractor); Hikvision/Dahua singles | A22Z4 shows a real Hikvision disk (OSD proof) | Free | No validation, no custody, no coverage metrics |
| Cellebrite, Belkasoft | No DVR proprietary-FS support found | - | - | - |
| SIH rival: byteforce101 TraceX | 11 parsers incl. Matrix, TP-Link VIGI, Godrej, Uniview, HeimVision | No: tested on images its own generator builds | OSS, 331 MB exe | Circular validation; Groq cloud LLM |
| SIH rival: BhanuPrasad-2006/sih-26150 | Dahua, Hikvision, Honeywell; CP Plus "by assumption"; others generic | Explicitly not yet | OSS, Windows installer, accounts | Honest, polished product; no real disk |
| SIH rival: Trinetra-DFIR / Pramaan_ / Pheonix_37 | Hikvision + Dahua (Pramaan: verified DHAV profile) | Synthetic | OSS | Strong custody/BSA/Merkle paperwork; no real media |
| SIH rival: VinayBU14/CCTVault | HeimVision (CFReDS), Dahua, Hikvision | Same public CFReDS HeimVision E01 (via libewf) | OSS | No log/index cross-check claimed |
| SIH rival: Hardik-droid/sih_x "Trace" | HeimVision + synthetic DVR-like index | CFReDS HeimVision: NIST MD5/SHA-1 reproduced (via Dissect), search.db 806 records, 12 HEVC excerpts from 3 files | OSS, Vercel web app | Samples 3 of 806 files; "model labels disagree, firmware unknown"; no log cross-check |
| SIH rival: quantum-quirk-forensic-tool | "All 8 vendors supported" | None; shows Rzayeva 2025's 91.8% / 96.7% / 2.4% as its own numbers | OSS (12 KB) | Borrowed metrics - an example of what judges will discount |
| SIH rival: Universa | DHAV, "ftypisom" as Hikvision, mock | 28.65 GB unnamed "raw CCTV disk image": 97 playable of 23,484 candidates | OSS (C++) | No ground truth, no recovery % |
| SIH rival: vidrensic / VigiTrace / sharath dvr-nvr | WFS + DHAV (vidrensic); network ISAPI/CGI/DVRIP (VigiTrace); 7 vendors claimed (dvr-nvr) | Synthetic / "nothing validated on physical hardware" | OSS | Capability-stage labels like D1, no real drives |

## Ten most important new papers (not in the team's list)
1. Giri, Yoon, Hwang - CARVE, DFRWS APAC 2026 (Honeywell; OCR/PRNU camera grouping; 99.89%). Changes D13's framing.
2. Eichhorn, Gabel, Freiling - "Every Frame You Take", DFRWS USA 2026 (reproducible camera test framework WiBtL; 9 cameras). Evaluation-method precedent.
3. SWGDE 17-V-002 v1.3 (2025) - DVR acquisition best practices (native export = best evidence; reformat-on-reinsertion risk; clock offset).
4. Byun, Shim, Kim 2026, JFS - video file slack in pre-allocated files (+966.7%).
5. Lehri & Roy 2022, IFIP AICT 653 - timestamps in carved DVR footage via OCR (likely Indian law-enforcement authorship; SourceForge "lea-i4c"; unconfirmed).
6. Vanini, Hargreaves, van Beek, Breitinger 2024, FSI:DI 49:301759 - time anchors / was the clock correct.
7. Ko & Lee 2020, J. Digital Forensics (Korea) 14(4) - efficient recovery from the unallocated area of HIKVISION FS.
8. Li & Zhang 2015, Forensic Science and Technology (China MPS) 40(6) - Dahua DHFS data recovery (channel + start time per block).
9. Molnar, Terpstra, Voitel 2025, SAE 2025-01-8690 - measured DVR/NVR timestamp accuracy (mean 2.99 ms, max 22 ms).
10. NISTIR 8161 Rev.1 (2019) - NIST/FBI CCTV Digital Video Export Profile Level 0 (MP4 + embedded time codes + ClockOffset metadata).
(Next tier: Mock & Brunty 2022 AAFS (Marshall Univ.; the DVR-dataset work behind the CFReDS HeimVision image); Xiang et al. 2022 H4VDM arXiv:2210.11549; Gomm, Brooks, Choo, Le-Khac, Hew 2020, Studies in Big Data 74 (multi-vendor CCTV workflow); Dreier et al. 2024 FSI:DI 49:301755 (implicit timing); Sandeepa 2018 IEEE IC4 (Hikvision, Indian authors); Yang 2015 SHS Web Conf (Dahua/Hikvision carving); Kim et al. 2023 IDIS G2FDb deletion behaviour; Altinisik & Sencar 2021 TIFS (H.264 parameter-set generation); Bruehs & Stout 2023 JFS (transcoding derivatives); Gloe et al. 2014 (video file format forensics); Sai Chung Law 2024 SPIE IWAIT; Krutov 2021 (Russia MoJ DVR examination); Silva 2018 (PCBox DVR FS, Argentina); Dragonas 2023 FSI:DI & IEEE CSR 2023 (Hikvision/Dahua mobile apps); block-based PRNU FSI:DI 2025.)

## Papers on Uniview / TP-Link / Matrix / Godrej
None found in EN/KR/CN/RU/PT/ES searches, arXiv, Crossref, OpenAlex, DFRWS 2023-2026 programs, or GitHub code search. Only commercial claims (512 BYTE, Dolphin for Uniview) and rival READMEs with unsourced markers. This is itself a point for the pitch: for these four brands, a tool that says "detected_not_parsed" honestly is ahead of the published state of the art.
=====================================================================

## A. Papers not in the team's list (running)

(format: citation | link | summary | dataset/public? | beats/conflicts?)

### A1. CARVE (DFRWS APAC 2026) - Giri, Yoon, Hwang (SKKU SoftSec)
- "CARVE: Recovering and Reconstructing Deleted H.264/H.265 Video from Honeywell Surveillance Systems", DFRWS APAC 2026 presentation. https://dfrws.org/presentation/carve-recovering-and-reconstructing-deleted-h-264-h-265-video-from-honeywell-surveillance-systems/
- Carves codec structures in the raw video region, separates deleted from live footage using embedded timestamps, groups fragments by source camera, rebuilds timelines. Two grouping routes: OCR of overlays (PaddleOCR-VL-1.5; +26% H.264 / +50% H.265 overlay detection with preprocessing) and, when no overlay, PRNU sensor-noise clustering. Claims 99.89% average recovery, 100% precision on internal gaps.
- CONFLICTS with D13 ("cannot separate identically configured cameras"): CARVE separates cameras by PRNU and by OCR of the on-screen camera label. Team's D4/D13 should cite this and either add an OCR/PRNU route or say why not (stdlib-only, compressed low-res footage).

### A2. Poole, Zhou, Abatis 2008 (pre-2010, foundational)
- "Analysis of CCTV digital video recorder hard disk storage system", Digital Investigation 5(1):85-92.

### A3. van Dongen 2008 (pre-2010)
- "Case study: Forensic analysis of a Samsung digital video recorder", Digital Investigation 5:19-28.

### A4. Yang et al. 2015 - SHS Web of Conferences
- "Basic principle and application of video recovery software for 'Dahua' and 'Hikvision' brand". https://www.researchgate.net/publication/272642140
- Vendor start/end keywords for H.264 segment carving (Dahua/Hikvision). Whole-disk scan; no FS model.

### A5. Sandeepa, Reyaz et al. 2018 - IEEE IC4
- "An Efficient Approach to Recover CCTV Video from Proprietary DVR File System", 2018 Int. CET Conf. on Control, Communication and Computing (IC4), pp. 250-254. https://ieeexplore.ieee.org/document/8531073/
- Hikvision; uses metadata regions; fails when metadata deleted/corrupted (per Yoon & Hwang). Indian (Kerala) authors.

### A6. Lee et al. 2023 - FSI:DI
- "Analysis of real-time operating systems' file systems: built-in cameras from vehicles". Chip-off; proprietary RTOS FS in car cameras.

### A7. Dragonas et al. 2023a - FSI:DI
- "IoT forensics: analysis of a Hikvision's mobile app" (Hik-Connect app artefacts).

(Competitor notes are further down under "B. Competitors - notes so far"; the USP is in the SUMMARY at the top.)

### A8. LI Zichuan, ZHANG Zuo 2015 - Forensic Science and Technology (刑事技术, China MPS)
- "Data Recovery from Dahua Embedded Video Surveillance System", Forensic Sci. & Tech. 40(6):445-449, DOI 10.16467/j.1008-3650.2015.06.004. http://www.xsjs-cifs.com/EN/abstract/abstract1011.shtml
- DHFS parameters that fix block size/arrangement; frame structure used to decide which channel a block belongs to and record start time. Cited by Dragonas 2024 as the DHFS reference.

### A9. Ko Eung-Gyu, Lee Sangjin 2020 - Journal of Digital Forensics (Korea) 14(4):337-349
- "A Study on Efficient Video Recovery Method in the Unallocated Area of HIKVISION Filesystem" (HIKVISION Filesystem 미할당 영역에서의 효율적인 동영상 복원 방법에 대한 연구). KCI ART002675183. Seoul Metropolitan Police + Korea Univ. Separates only the unallocated area of HIKVISION FS to speed recovery on multi-TB disks. Directly comparable to D3 (index-vs-unindexed split). Korean, no public dataset.

### A10. Kim Se-yeon et al. 2023 - Journal of Digital Forensics (Korea) 17(4):67-82
- "Analysis of IDIS G2FDb File System Deletion Behavior and Audio Data Identification" (IDIS G2FDb 파일시스템 삭제 행위 분석 및 음성 데이터 식별). https://www.dbpia.co.kr/journal/articleDetail?nodeId=NODE11663582
- Korean vendor IDIS; hex diffs per deletion type; determining intentional deletion; audio detection. Method (diff before/after deletion ops) = same as Yoon & Hwang. Not a PS26150 vendor but a model for "deletion-behaviour" evaluation.

### A11. Altinisik & Sencar 2021 - IEEE TIFS 16:4857-4868
- "Automatic Generation of H.264 Parameter Sets to Recover Video File Fragments". arXiv:2104.14522. Tool: https://github.com/FileScraper/tool
- Decodes headerless H.264 fragments by generating SPS/PPS from a dictionary of encoder settings learned from 55K+ videos; avg 11.3 decode trials. Relevant to D13 when a carved slice run has lost its SPS/PPS (DVR overwrite). Dataset: their corpus (partly public: VISION etc.).

### A12. Altinisik, Tasdemir, Sencar 2020 - IEEE TIFS
- "Mitigation of H.264 and H.265 Video Compression for Reliable PRNU Estimation". arXiv:1905.09611. Camera attribution from compressed video: relevant if the team wants a PRNU route to separate identical cameras (CARVE does).

### A13. Casey & Zoun 2014 - Digital Investigation 11 (DFRWS EU 2014)
- "Design tradeoffs for developing fragmented video carving tools". https://www.sciencedirect.com/science/article/pii/S174228761400053X (Defraser-style; evaluation of video carving methodology.)

### A14. Scalpel3 (arXiv:2608.20363, Aug 2026), Waguespack ... Golden G. Richard III (LSU)
- Massively-threaded fragmented carving framework; 80K-file mixed corpus; NOT video/CCTV. Only cite as general carving baseline.

## B. Competitors - notes so far

### SIH26150 GitHub teams (all created Aug-Sep 2026)
- byteforce101-ops/multi-vendor-dvr-forensics ("TraceX", 3 stars, 328 MB, v1.0.1 exe 331 MB): claims 11 parsers incl. Matrix SATATYA, TP-Link VIGI, Godrej SeeThru, Uniview UBS, Honeywell, HeimVision; BUT test data produced by its own `generate_all_vendor_samples.py` which "transcode[s] ... any standard video into authentic vendor filesystem disk images" => circular validation (parser tested on files built from the parser's own assumptions). Uses Groq LLaMA (cloud) for Q&A; ONNX detector; "ISO/IEC 27037-compliant dossier". No real-disk numbers.
- arnavps/Trinetra-DFIR: Hikvision (HIKFAT) + Dahua DHFS parsers, NAL carver + GOP reconstructor, Rust PyO3 block hashing + Merkle tree, hash-chained Merkle audit log (SQLite), BSA s.63 Part A/B drafts, offline ONNX (YOLOv8n, SCRFD, FastReID, ANPR, OpenCLIP, ESRGAN) labelled "investigative lead". Demo = synthetic Hikvision drive; 51 tests. => D5, D6, D9, D11 are NOT unique.
- BhanuPrasad-2006/sih-26150: the most honest rival. Badge "real recorder disks: not yet tested". Status table per OEM (Dahua/Hikvision from literature, Honeywell from Yoon&Hwang, CP Plus by assumption, TP-Link/Godrej/Uniview/Matrix no parser). Labels UNCERTAIN/PARTIAL/COMPLETE; "validation kit" ready for real disks + exported clip; ground-truth recall/precision/order and byte placement - on synthetic disks only. Cites "Wullen 2025 spec" (Dahua) and "Batista extractor" (gbatmobile/dhfs_extractor), and "a third party's published parse of a real 1 TB disk" for Hikvision. 367 tests. => D1 concept (status by weakest evidence, validation vs export) is shared in spirit; the team's edge is that theirs is exercised on REAL disks.
- phoenixspecss-mait/Universa (C++): claims "Proven Real-World Validation" on a 28.65 GB raw CCTV image: 23,484 candidate streams -> 97 playable clips; custody chain of 101 SHA-256 entries. Adapters: DHAV (Dahua/Godrej), `ftypisom` for Hikvision (!), `DVR-MOCK`. No ground truth, no recovery %.
- sharathbharadwajcp/dvr-nvr (Rust): claims Hikvision/Dahua/Uniview/Matrix/Godrej/TP-Link/Honeywell; "Tier 0/1/2" validation grammar (synthetic / literature / registry); 44 tests; BSA s.63.
- Karthikraja2345/DVR-Forensics: DHFS/Hikvision/Generic profiles, synthetic DHFS fixtures, hash-chained ledger, "Raw vs UTC offset vs drift" timestamp engine, evidence lineage DAG, VALIDATION_PLAN.md (ground truth planned).
- SuhasKanwar/VigiTrace (TypeScript): NETWORK acquisition (Hikvision ISAPI, Dahua CGI, CP Plus via Dahua adapter, Godrej via Xiongmai DVRIP port 34567) + Hikvision HIKBTREE on-disk; "Nothing here has been validated against physical recorder hardware". Good evidence: CP Plus SmartPlayer exports Dahua C++ symbols; Godrej = Xiongmai white label.
- anand-esc/Pheonix_37: Dahua "validated (prototype)" on synthetic+reference samples; Hikvision stub; signed hash-chained ledger ("not a blockchain"); BSA s.63.
- somesh-glitch: Dahua/Hikvision carving "currently simulated".
- Yuvaranjan-S/FORGE-VISION: web app, public datasets (UCF-Crime, VIRAT), "SIMULATED VENDOR DATA" labels, demo creds.
- Others (thin): Siddhant2037/TraceX, Selvashaju/SENTINEL-VF, Ajaydangi1509/vidforensi, aIxart-sjv/24fps, xarjunpatil, sangya03byte/ForenSight, devendrahundalekar, Jayakumar0912, Shravya03-11, bhatshreemata-arch/forensic-vision, ayushh1302, git-aditya3, Chhatrapatisupare/dvr-forensics (updated today).

### Non-SIH open source
- A22Z4/hikvision-nvr-recovery (Apr 2026): REAL-disk Hikvision recovery after reset: parse master sector + BTree, list unindexed blocks, OCR the OSD timestamp (tesseract) of one frame per block, concatenate blocks -> MP4. Rival route to D3 (dates by OCR, not HK descriptors; no coverage measure).
- gbatmobile/dhfs_extractor (Batista; 14 stars): DHFS4.1 videos, logs, slack.
- dw2102/X-Ways-DHFS4_1-X-Tension and X-Ways-HIKVISION-X-Tension (HIK.2011.03.08): X-Ways plug-ins.
- julienblitte/dhav_carving; Tedyst/HikLoad (network download via ISAPI).

### Commercial (so far)
- UFS Explorer Video Recovery (SysDev Labs): WFS, DHFS, HIK, Mirage, Pinetron, BKFL, dVfE, MDFS, Rsfs, SFMR, TPFS, UAVtech; ~130 stream formats; no transcoding; physical disk location of every recovered frame; event logs (Hikvision, Dahua); RAID; filter by camera/time. EUR 8,000/yr commercial; gov 5-yr ~EUR 3,584/yr. Windows only.
- 512 BYTE (Ukraine): per-vendor products ~EUR 119 each (Uniview NVR, HikV, DVR163, WFS, iCatch, HUAYI, AVTECH, ZENO, DHFS, Infinity). Claims date/time interval + channel per video.
- Magnet Witness (ex DVR Examiner, DME Forensics): "over 50 native or proprietary DVR file formats" + cloud (Ring, Arlo). Rzayeva 2025 compared DVR Examiner v7.1, DiskInternals DVR Recovery v5.8, SalvationDATA VIP 2.0 v3.2, Scalpel 2.0.

### Rzayeva 2025 (already cited) - facts pulled from the full PDF (important for USP)
- Authors: L. Rzayeva, M. Shayakhmetov, Y. Atanbayev, R. Budenov, H. Mutaher (Kazakhstan; two authors employed by TSARKA Group). Information 16(11):983, published 13 Nov 2025. PDF: https://mdpi-res.com/d_attachment/information/information-16-00983/article_deploy/information-16-00983.pdf
- Data: 27 drives = 15 Hikvision (HiWatch DS-N204P x4, DS-7608NI-K2 x5, DS-7604NI-K1 x3, DS-7616NI-K2 x3) + 12 Dahua (NVR5216-8P x4, NVR4104-P x3, NVR4108-8P x3, NVR4216-16P x2); ~2,400 h recorded over 6 months of STATIC LAB TARGETS (resolution charts); plus "artificially corrupted disk images". Data NOT public ("included in the article").
- Metric: Recovery rate = recovered videos / total expected videos; temporal accuracy = correctly sequenced frames / recovered frames. NO byte-level comparison with the recorder's own export (=> team's D1 is a stricter criterion).
- Commercial numbers they report (useful for the competitor table, single-source, lab data): Hikvision N=15 recovery/temporal: Magnet DVR Examiner v7.1 89.2/92.8, DiskInternals 84.7/90.1, VIP 2.0 91.3/94.2, Scalpel 68.9/74.8, proposed 93.5/97.3. Dahua N=12: Magnet 84.8/89.2, DiskInternals 78.9/86.8, VIP 2.0 87.2/92.3, Scalpel 74.6/78.2, proposed 89.6/95.9. Throughput: Magnet 3.8 GB/min, VIP 3.2, proposed 3.9 (~4.4 h per TB).
- Stated weaknesses (Table 6): encrypted disks 43% (Magnet 78%, VIP 82%); non-standard models 68%; severely damaged sectors 61%. Says modern enterprise/government deployments increasingly encrypt by default.
- Team comparison: D3 reports 99.6-99.7% of index-recorded content on a REAL field drive reformatted by another vendor - different metric (hours vs index, not videos vs lab ground truth), so present it as "different, stricter scenario", NOT as "beats 91.8%".

### A15. Vanini, Hargreaves, van Beek, Breitinger 2024 - FSI:DI 49:301759 (DFRWS USA 2024)
- "Was the clock correct? Exploring timestamp interpretation through time anchors for digital forensic event reconstruction". https://dfrws.org/wp-content/uploads/2024/07/Was-the-clock-correct-Exploring-timestamp-interp_2024_Forensic-Science-Inte.pdf
- Defines time anchors / anchoring events / time anomalies to decide whether system time was right and estimate skew. Not CCTV-specific. Gives the team the vocabulary for D7 (two independent routes to the recorder clock = two time anchors). Supports D7; no conflict.

### A16. Dragonas, Lambrinoudakis, Kotsis 2023 - FSI:DI 45 (DFRWS USA 2023) 
- "IoT forensics: Analysis of a HIKVISION's mobile app". https://dfrws.org/wp-content/uploads/2023/07/dragonas-hikvision.pdf ; artefacts merged into ALEAPP/iLEAPP. Companion-app evidence (who viewed/exported footage) - a source the team ignores.

### A17. PRNU / source-camera for video (camera attribution)
- "Compression effects and scene details on the source camera identification of digital videos" arXiv:2402.06669 (2024).
- "Source Camera Identification - Do we have a gold standard?" FSI:DI 2024, https://www.sciencedirect.com/science/article/pii/S2666281724001859
- Altinisik et al. "PRNU Estimation from Encoded Videos Using Block-Based Weighting" arXiv:2008.08138.
- Relevance: the only published route to separate identically configured cameras (the D13 limit). CARVE uses it on Honeywell.

### Other items noted
- Magnet blog "Analysis of Hikvision Date/Time" (1 Mar 2022): per-block index gives per-channel time range in Unix epoch; per-frame 5-byte "binary date time"; nothing on zone/DST. https://www.magnetforensics.com/blog/analysis-of-hikvision-date-time/
- Magnet blog: "Forensic Images for DVR Analysis (E01 or DD)". https://www.magnetforensics.com/blog/dvr-examiner-forensic-images-for-dvr-analysis-e01-or-dd/
- Patent KR101685043B1: method to check for/obtain past CCTV data in overwritten CCTV video (Korea).
- eSec Forte (Gurugram) resells DVR forensics products in India (partner logos only).

### A18. Eichhorn, Gabel, Freiling 2026 - DFRWS USA 2026 (FSI:DI), FAU Erlangen
- "Every Frame You Take: A Taxonomy and Reproducible Testing Framework for Digital Surveillance Cameras". Paper: https://dfrws.org/wp-content/uploads/2026/04/DFRWS_USA_2026_Camera_Ready_Paper_17.pdf ; code+artefacts: https://github.com/mxchhrn/wibtl
- Taxonomy of digital surveillance cameras + Python framework WiBtL that REPRODUCIBLY generates test data (controlled light, WILDTRACK clip on a display to trigger motion, scripted scenarios: firmware update, SD format, etc.). 9 consumer IP cameras (Nikkei, Woox, Littlelf, Arenti, Laxihub, Awow, Eufy, Reolink RLC-410-5MP, Vimtag) - microSD, companion apps, cloud; NOT DVR/NVR disks. Finding: limited generalisation across camera groups; device-specific analysis still needed.
- Relevance: EVALUATION METHODOLOGY. It is the closest published "reproducible ground-truth generation" method; the team's D1 (validate vs recorder's own export) is the DVR-disk analogue. Cite it; consider a scripted scenario list (record/delete/format/overwrite/clock change) modelled on theirs. Also cites Garfinkel, Nelson, Young 2012 "A general strategy for differential forensic analysis" (Digital Investigation 9) - the formal basis for before/after disk diffs.

### A19. CARVE full abstract (DFRWS APAC 2026) - adds: evaluated on ONE Honeywell NVR: baseline image + 3 deletion scenarios (data-expiration, overwrite, format); integrity + reproducibility tests (repeat runs identical, original preserved). Single device, lab data.

### A20. Other DFRWS 2025-2026 items found in programs
- "Video capturing device identification through block-based PRNU matching", FSI:DI 2025 (DFRWS EU 2025). https://www.sciencedirect.com/science/article/pii/S2666281725000125 (handles stabilisation misalignment; few frames).
- "Tracing Messenger Transmission Pathways of Videos Using SPS NALU" (DFRWS APAC 2025) - SPS fields as provenance fingerprint: the same idea could separate encoders/camera models in D4/D13 (SPS/VPS parameter differences between cameras).
- "Time-Anchor: Detecting System Clock Manipulation in Android" (DFRWS APAC 2026) - clock-manipulation detection; ties to D7.
- "Watching the Watchers: Forensic Analysis of Body-Worn Camera BLE Artifacts" (DFRWS USA 2026, presentation).
- "Seeing the Evidence: ... Ray-Ban Meta AI Smart Glasses" (DFRWS USA 2026) - not relevant.

### A21. Byun et al. 2026? - J. Forensic Sciences, DOI 10.1111/1556-4029.70412
- "Video data recovery from slack space of pre-allocated video files". Pre-allocated fixed-size recording files keep residue of older recordings in the unused tail. Directly relevant to Hikvision's pre-allocated 1 GB blocks and Dahua fixed-size files: after a partial overwrite the tail of a block can still hold older footage. Check whether D3/D13 look in the tails of in-use blocks.

### A22. Lee et al. 2023 FSI:DI - "Analysis of real-time operating systems' file systems: built-in cameras from vehicles" (chip-off; proprietary RTOS FS). And "Your car is recording: Metadata-driven dashcam analysis system", FSI:DI 2021, https://www.sciencedirect.com/science/article/pii/S2666281721000299.

### A23. Chain-of-custody prior art (so D6 is not claimed as novel)
- Lone & Mir 2019, "Forensic-chain: Blockchain based digital forensics chain of custody with PoC in Hyperledger Composer", Digital Investigation 28:44-55.
- Also "Blockchain-based chain of custody" ARES 2020 (ACM 10.1145/3407023.3409199).
- Oh et al. 2024, "Forensic Detection of Timestamp Manipulation for Digital Forensic Investigation", IEEE Access, DOI 10.1109/ACCESS.2024.3395644 (NTFS-journal cross-checks; >95%) - general, not CCTV.

### Commercial - more
- DiskInternals DVR Recovery: Hikvision (DVR/NVR/NAS), Dahua (DHFS, DHFS over iSCSI) + RAID; "Correction of Timestamps"; says overwritten data cannot be recovered; from USD 199; trial = preview only.
- Amped DVRConv / Replay / FIVE (Amped Engine): converts "hundreds" of proprietary EXPORTED/player files (not disk images); aims to keep original streams, separate cameras, read timestamps. Complements rather than competes on disk recovery.
- SalvationDATA VIP 2.0 / VIP 3.0: "patented" automatic proprietary FS identification; Honeywell, Dahua, Hikvision, Sony, Samsung, iCatch...; disk + network; claims recovery of lost/deleted/overwritten/fragmented metadata. Hardware+software bundle; price by quote.
- Magnet Witness (DVR Examiner successor): "over 50 native or proprietary DVR file formats"; deleted/partially overwritten; auditable reports; no public vendor list or accuracy study; licence by quote. Per Rzayeva 2025: 89.2% (Hik), 84.8% (Dahua) on their lab drives.
- Autopsy/TSK: no DVR FS module (forum requests for DHFS unanswered). X-Ways: community X-Tensions by Dane Wullen for DHFS4.1 and HIK.2011.03.08. Cellebrite/Belkasoft: no DVR proprietary-FS support found.
- ffmpeg: dhav demuxer since FFmpeg 4.2 (2019): channel, frame number, date/time per DHAV frame; container-level only (no DHFS).
- eSec Forte (Gurugram) resells DVR forensics tools to Indian agencies.

### A24. Lehri & Roy 2022 - IFIP Advances in Digital Forensics XVIII (IFIP AICT 653), ch. 8
- "Identifying Desired Timestamps in Carved Digital Video Recorder Footage". https://link.springer.com/chapter/10.1007/978-3-031-10078-9_8 ; tool: https://sourceforge.net/projects/carvedvrtimestamps/ (user "lea-i4c", Apache-2.0, 2022) - the SourceForge handle suggests India's I4C (Indian Cyber Crime Coordination Centre, MHA) law-enforcement origin (NOT confirmed).
- Carved, partly overwritten DVR footage has out-of-order frames; tool extracts frames, repairs/reconstructs, stitches, and OCRs the burned-in timestamp to find the frames of interest. Vendor-agnostic via OCR, no FS parsing.
- Relevance: an INDIAN, peer-reviewed precedent for OCR-based dating of carved DVR video. The team's D3/D7 date from on-disk descriptors (not pixels) - stronger, but judges may ask "why not OCR?". Answer: OCR is a third, independent route (overlay = what the recorder burned into pixels) that can cross-check D7's two routes. No conflict.

### A25. Molnar, Terpstra, Voitel 2025 - SAE Technical Paper 2025-01-8690 (WCX)
- "Accuracy of Timestamps in Digital and Network Video Recorders". https://trid.trb.org/View/2539628
- 4 recorders, 6 cameras, 30/15/4 fps, 54 videos vs an Axon VFR Lightboard reference: mean error 2.99 ms, max 22 ms; timestamp not always accurate second-to-second, but patterned. Relevance: frame-level timing accuracy of burned-in timestamps (sub-second), complementary to D7 (absolute clock offset). Useful citation for "what precision can we claim".

### A26. Gomm, Brooks, Choo, Le-Khac, Hew 2020 - in "Cyber and Digital Forensic Investigations", Studies in Big Data 74, Springer
- "CCTV Forensics in the Big Data Era: Challenges and Approaches". https://link.springer.com/chapter/10.1007/978-3-030-47131-6_6
- Workflow for acquiring/analysing many CCTV devices of different makes/formats; real case studies (UCD). Multi-vendor workflow precedent; no quantitative validation.

### A27. Dragonas, Lambrinoudakis, Kotsis 2023 - IEEE CSR 2023, pp. 452-457
- "IoT Forensics: Investigating the Mobile App of Dahua Technology". https://ieeexplore.ieee.org/document/10224982/ (Android+iOS DMSS app; FOSS parsers contributed).

### A28. Dashcam / vehicle DVR
- "Digital Forensic Analysis of Vehicular Video Sensors: Dashcams as a Case", Sensors 23(17):7548, 2023. https://doi.org/10.3390/s23177548
- "Evidence Collection from Car Black Boxes using Vehicular Digital Video Recorder System" (2016).

### A29. Pre-2010 foundations (for completeness)
- Poole, Zhou, Abatis 2008, Digital Investigation 5(1):85-92; van Dongen 2008, Digital Investigation 5:19-28 (Samsung DVR); Wang 2009 PhD thesis "Digital Video Forensics", Dartmouth.

---
## Session 2 (resumed Tue Sep 29 00:27:19 IST 2026)

### A30. Byun, Shim, Kim 2026 - J. Forensic Sciences (early view 16 Jul 2026), DOI 10.1111/1556-4029.70412 (confirmed via Crossref)
- "Video data recovery from slack space of pre-allocated video files". Defines "video file slack" in pre-allocated dashcam files (AVI/MP4/ASF); frame-based H.264 recovery from it; up to +966.7% recoverable area vs unallocated-only analysis; hit-and-run case: impact frames recovered only from slack. Dashcam data; not public.
- Relevance: same mechanism as DVR pre-allocated blocks (Hikvision 1 GB data blocks, Dahua fixed files). Ask: does D3/D13 carve the stale tail of IN-USE blocks, or only unindexed blocks? If not, this is a cheap addition with a citation.

### A31. Bruehs & Stout 2023 - J. Forensic Sciences 68:1036-1048, DOI 10.1111/1556-4029.15245 (FBI)
- "Evaluating digital video transcoding for forensic derivative results": practitioners' MP4 transcodes of the same files differed in quality depending on settings. Supports D1's rule (compare stream bytes to the recorder's own export; never validate via transcoded derivatives).

### A32. Sai Chung Law 2024 - Proc. SPIE 13164 (IWAIT 2024), DOI 10.1117/12.3018297
- "Video data recovery for a CCTV system by reverse engineering": reverse-engineered a commercial DVR FS without the hardware/software, recovered raw video from partly corrupted data; also RE by "eavesdropping on data structures of files while running the application software". Case-study; vendor unnamed in abstract; no public data.

### A33. Krutov 2021 - Theory and Practice of Forensic Science (Russia, MoJ RFCFS) 16(1):114-123, DOI 10.30764/1819-2785-2021-1-114-123
- "Video Recorder as an Object of Forensic Expert Analysis": examination sequence and expert questions for stationary DVRs; case study. Procedural precedent (what a court-appointed expert is asked).

### A34. Gloe, Fischer, Kirchner 2014 - Digital Investigation 11:S68-S76 (DFRWS EU 2014)
- "Forensic analysis of video file formats": container-structure fingerprints identify the recording device/software. Supports D8 (model identification from structure) as an established idea.

### A35. Other items (lower relevance)
- Iuliani, Sawyer, Fontani, Spreadborough, Jerian (Amped) 2025, arXiv:2512.19364 "ForeSpeed": PUBLIC dataset, 322 CCTV videos (3 digital + 3 analog cameras, known vehicle speeds, multiple export/compression settings). Useful public test set for D9 motion/speed leads.
- Lee, Eimon, Srinivasan, Kalva 2026, arXiv:2604.11010 "Byte-level generative predictions for forensics multimedia carving" (bGPT on BMP fragments) - not video; skip.
- "Digital forensic analysis for source video identification: A survey", FSI:DI 2022, DOI 10.1016/j.fsidi.2022.301390.
- "Digital Forensics: Acquisition and Analysis on CCTV Digital Evidence using Static Forensic Method based on ISO/IEC 27037" (2019, DOI 10.5220/0009120400850089) - Indonesian practitioner paper.
- CARVE full text: NOT public as of 29 Sep 2026 (DFRWS presentation page has abstract only; not on arXiv). So HOW PRNU/OCR separation was evaluated cannot be checked - only the abstract claims (OCR +26%/+50% overlay detection; PRNU clustering when no overlay; 99.89% avg recovery; 100% gap precision; one Honeywell NVR, 3 deletion scenarios). Treat its camera-separation accuracy as UNREPORTED in the abstract.

### OEM lineage (matters for D8 and for which parser a "brand" really needs)
- IPVM Dahua OEM directory (public report, https://ipvm.com/reports/dahua-oem): "CP Plus (Orange Line)" is a CURRENT Dahua OEM; "Honeywell previously relabeled Dahua models for their Performance Series, but said that they stopped purchasing these models in April 2022". => Older Honeywell Performance-series DVRs in Indian sites may carry DHFS/DHAV, not the Honeywell native FS in Yoon & Hwang. Brand != format; D8 (model + firmware) is what picks the parser.
- IPVM Hikvision OEM directory (https://ipvm.com/reports/hik-oems-dir): Honeywell = former Hikvision OEM too; "Matrix Security Solutions ... Terminated Hikvision OEM partnership" (may NOT be Matrix Comsec India - unverified).
- VigiTrace README (rival): Godrej = Xiongmai white-label (DVRIP port 34567) - "probable", from device fingerprints; CP Plus SmartPlayer exports Dahua C++ symbols.
- No public paper or format note found for Uniview, TP-Link VIGI, Matrix SATATYA or Godrej on-disk formats (searched EN/KR/CN, arXiv, Crossref, DFRWS 2023-2026 programs). Only commercial: 512 BYTE Uniview NVR (EUR 119), Dolphin DVR ("Uniview 0x11", "Uniview 0x1C" types), UFS Explorer "TPFS" (unclear if TP-Link).

### More rival / open-source repos found in session 2 (GitHub code search for HIKBTREE, HeimVision, CFReDS)
- VinayBU14/CCTVault (SIH-style, created 30 Aug, last push 10 Sep): IS TESTED ON THE SAME NIST CFReDS HeimVision K9604-W E01 the team used (README walks through "HeimVision K9604-W.E01"; repo has a "HeimVision K9604-W Image" folder + heimvision parser/detector). Parses the HeimVision "luo " container, Unix-epoch start/end, channels 1-4, gap detection, H.264 extraction, ffprobe validation, NAL carving. Uses libewf/ewf-tools (NOT its own E01 reader); no FTK-hash reproduction, no log-vs-disk cross-check claimed. => D12 "tested on CFReDS HeimVision" is NOT unique; what remains unique is (a) own E01 reader reproducing FTK's MD5/SHA-1 and (b) the recorder's own log + index checked against the disk.
- Aravind2674/Pramaan_ (1-2 Sep): RFC 6962 Merkle tree with inclusion proofs over artefact hashes, hash-chained audit ledger with tamper localisation, Ed25519 examiner signing, BSA s.63(4) Part A/B certificate ("No commercial or open-source DVR forensic tool surveyed ... generates either document"), Theil-Sen clock-drift estimate "robust to a single bad anchor", OSD OCR by template matching, "Surveillance Evidence Format" signed ZIP with JSON Schema, declarative YAML vendor profiles, verified Dahua DHAV profile + partial Hikvision master sector; 100% coverage claims; synthetic demo only. => strongest rival on D5/D6/D7/D11 paperwork; nothing on real media.
- imedkablavi/vidrensic ("0.6 alpha", created 20 Aug): Hikvision **WFS** reconstruction (global hypothesis solving), DHAV channel demux with physical order kept, Hikvision proprietary only at PROFILE stage (HIKBTREE not claimed), AES-CBC/CTR with KNOWN keys, ddrescue-style acquisition map receipts, "capability stages instead of one misleading supported flag", machine-readable validation corpus - intentionally synthetic ("does not prove universal real-recorder support"). => D1's graded-status idea is shared; real-media validation is not.
- fmpfeifer/hikextractor (22 stars, 2021-2026): parses HIKVISION DVR drives, exports footage (HIKBTREE-based). dw2102/HikVision-Data-Recovery (+ fork asternmadkatz/HikVision_Data_Recovery_Plus). vishwajitsarnobat/HIKVISION-DVR-Tool (2025). bkbilly/libHikvision. dfrc-korea/carpe-sleuthkit (Korea Univ. DFRC fork of TSK, 21 stars, mentions HIKBTREE). a1ive/FsRover (GRUB-based FS explorer; no DVR FS).
- BhanuPrasad-2006/sih-26150 re-checked 29 Sep 00:30: README unchanged ("real recorder disks: not yet tested"); recent work = Windows installer (PyInstaller+Inno Setup), first-run wizard, multi-examiner accounts, desktop window. Productisation is its edge; GitHub Pages site bhanuprasad-2006.github.io/sih-26150.

### A36. SWGDE 17-V-002 v1.3 (28 Feb 2025) "Best Practices for Data Acquisition from Digital Video Recorders" - the practice STANDARD
- PDF: https://www.swgde.org/wp-content/uploads/2025/03/2025-02-28-Best-Practices-for-Data-Acquisition-from-Digital-Video-Recorders-17-V-002-1.3.pdf
- Native/proprietary export = best evidence; record DVR clock vs atomic time and compute the offset; "Do not change the time and date on the DVR"; "The settings of the DVR are retained on the device, not the hard drive"; HDD removal risks: format not recognised, and "When the extracted hard drive(s) are returned to the DVR ... there is a risk that the DVR might initiate a reformatting procedure".
- Use: D1 (native export as ground truth) is SWGDE-consistent; D3 is recovery from exactly the reformat scenario SWGDE warns about; D7/D8 go beyond SWGDE's assumption that settings are only on the device (team recovers clock evidence and the unit's serial from the platter).

### A37. Latin-American practitioner papers (found via davisan/DVRExtractor references)
- Shimabuko, A. (2013) "Recuperação de vídeo em equipamento DVR", XXII Congresso Nacional de Criminalística (Brazil).
- Silva, Gaston A. (2018) "Ingeniería inversa del sistema de archivos de DVRs PCBox", XVIII Simposio Argentino de Informática y Derecho (SID), JAIIO 47. http://sedici.unlp.edu.ar/handle/10915/71847 - custom FS reconstruction for PCBox DVRs.
- hddmasters.by / disk-on.ru articles on WFS0.4 (Russian-language practitioner notes).
- davisan/DVRExtractor (free Windows tool, Brazil, 10 stars, 2021-2026): DHFS4.1, WFS0.X, HIKVISION, ZENO1.0, RSFS, TVT, QFAT, IFS, JUAN.
- theAtropos4n6/HikvisionLogAnalyzer (Dragonas' public Hikvision log parser).

### Yoon & Hwang 2026 (already cited) - details that matter for the USP (from arXiv HTML v1)
- Testbed: ONE Honeywell NVR HN35080200, EIGHT HN40E-2030I cameras "configured with identical settings for continuous recording starting simultaneously", Seagate 160 GB + 250 GB disks, FTK Imager; ground truth = differential images (0x00-filled baseline, then record / format / expire / overwrite) - i.e. Garfinkel-style before/after diffs, NOT comparison with the NVR's own export.
- "Sector 34 contains a Machine Data region that records device-specific information such as the Honeywell NVR device ID and model name ... identifies the device where the disk was installed" => precedent for D8 (drive-to-unit tie) on Honeywell. Rzayeva's reports also list "manufacturer, model, serial number, capacity, initialization date". So D8 must be claimed narrowly: on Dahua/CP Plus + Hikvision real drives, corroborated by the physical unit (label + System Info photos: CP Plus CP-UNR-104F1, fw V1.00.14.00.T).
- CARVE (same lab) therefore very likely evaluated camera grouping on 8 IDENTICALLY CONFIGURED cameras - exactly the case D13 says the team cannot split. CARVE full text not public, so its per-camera accuracy is unknown; but judges who know DFRWS may cite it.

### Dragonas 2023 (Hikvision logs) / 2024 (Dahua logs) - abstracts (Europe PMC)
- Logs record user actions such as formatting the HDD or disabling recording; "remain unexploited by major commercial forensic software"; tool: Hikvision Log Analyzer. Neither abstract claims cross-checking log events against gaps in the recorded video on the same disk. => the team's "recorder's own event log matched to a 1-minute recorder-wide gap on the drive, to the minute" (CP Plus drive 1) and D12's log+index-vs-disk check appear UNPRECEDENTED in the literature found.

### Session 2 - more rivals (00:38 IST 29 Sep)
- **Hardik-droid/sih_x ("Trace")** - pushed 28 Sep. docs/real-corpus-validation.md: on the NIST CFReDS HeimVision E01 (K9604-1/K9604-W) it reproduced NIST's published full-logical MD5 4895ea6d10b08c29fb1bb03591adc7b2 and SHA-1 06f48890961187979ed4142ceab8a7144bd4dfea (150,039,945,216 bytes, 24.7 min) - but through the Dissect library, not its own E01 reader; parsed the recorder's SQLite index search.db (96 SEARCH, 806 DETAIL records; 24.04 h, 2021-08-04 02:40:02 to 2021-08-05 02:43:01 UTC); decoded 12 four-camera HEVC excerpts (13,186 frames) from 3 of 806 .dat files; demuxed 8 kHz PCM audio; says "model labels disagree and firmware is unknown", parser "experimental". No log-vs-disk cross-check claimed. => D12 is now mostly PARITY with at least two rivals (CCTVault, Trace). What remains distinct: own E01 reader matching FTK; whole-image (not 3-file sample) accounting; the recorder's own LOG checked against the disk.
- **rameswarbehera00/quantum-quirk-forensic-tool** (12 KB repo): shows "Recovery Rate 91.8% / Temporal Accuracy 96.7% / False Positive 2.4%" - these are Rzayeva et al. 2025's numbers presented as its own, and marks all 8 vendors "Supported". Example of the overclaiming judges will have seen.
- **bethesky01/SIH26 ("Saboot Netra")**: Hikvision, Dahua, CP Plus, Honeywell, Matrix ("HIK-FS, DHFS, CPFS, Matrix"), claims drift normalisation to "+-0.25 s", "Immutable Blockchain Audit" (hash chain). No real media shown.
- **rajkiranmishra/SIH-2026- ("ForenX")**: Hikvision master sector + primary HIKBTREE "implemented; synthetic validation".
- **AmeyaMorgaonkar/multi-vendor-forensic-analysis-tool**: DB field validation_confidence in {'Validated: Real Device', 'Validated: Synthetic Reference Data', 'Stub: Awaiting Hardware'} - same idea as D1's ladder; README shows a "real-sample pull attempt", no real device result.
- Also: Ajaydangi1509/vidforensi (hash-chained ledger, BSA 63(4)), karthiksalupala-ds/deeptrace, Aayush-buri/Drishtik (claims CP Plus/Uniview/Godrej/Honeywell/Matrix adapters), SAurabh005coder/ForenSight (Hikvision+Dahua; synthetic "CONTROLLED DEMONSTRATION DATA"), Vortexx9/Chronexis.
- GitHub code search: no public .ksy (Kaitai) definitions for HIKBTREE/DHAV/DHFS anywhere => D10's Kaitai specs are unique on public GitHub (minor).

### More papers (session 2)
- Dreier, Vanini, Hargreaves, Breitinger, Freiling 2024, "Beyond timestamps: Integrating implicit timing information into digital forensic timelines", FSI:DI 49:301755 (DFRWS USA 2024), DOI 10.1016/j.fsidi.2024.301755 - implicit order (sequence numbers, allocation order) as timing evidence; supports using frame counters / block order in D7.
- Eichhorn, Gabel, Freiling 2026 = FSI:DI 57:302117, DOI 10.1016/j.fsidi.2026.302117.
- Li, Wang, Ma, Wang, Wu 2025, "Video capturing device identification through block-based PRNU matching", FSI:DI 52:301873, DOI 10.1016/j.fsidi.2025.301873.
- Lehri & Roy 2022: co-author Anyesh Roy appears to be a Delhi Police officer; SourceForge user "lea-i4c" - Indian law-enforcement origin likely but NOT confirmed (one search summary gave Lehri an AFIT affiliation - unverified).

### India regulatory note (forward risk)
- MeitY gazette 9 Apr 2024: STQC certification against Essential Requirements mandatory for CCTV; reported deadline: no sale of non-compliant CCTV from 1 Apr 2026. STQC "IoTSCS-P01 Procedure for CCTV Testing, Evaluation and Certification" (Issue 01, 21-05-2024, https://www.stqc.gov.in/sites/default/files/2024-05/IoTSCS-P01-Procedure-for-CCTV-Testing-Evaluation-and-Certification.pdf) lists "storage and encryption of data" among test areas and requires TLS for data in transit; I did NOT find an explicit "recorded video must be encrypted at rest" clause in P01 (blogs claim it - unverified). CP Plus distributes "STQC Phase-II" NVR firmware (Dec 2025) for CP-UNR-4K* and CP-UNR-108F1 (104F1 not listed on that page). Watch for at-rest encryption in post-2026 Indian recorders.

### Information 17(5):493 (2026) (already cited by the team) - facts from full PDF (important for D4)
- Authors: Leila Rzayeva, Madi Shayakhmetov, Olzhas Konakbayev, Gul G. Jussupova (Astana IT University "CyberTech"), Igor Seniushin, Anara Tasbolat (TSARKA Group). Published 17 May 2026. PDF: https://mdpi-res.com/d_attachment/information/information-17-00493/article_deploy/information-17-00493.pdf
- 14 ANALOG Dahua XVR drives from operational sites (DH-XVR1B04 ... DH-XVR7108HE-4KL-X; 500 GB-8 TB; 34.5 TB total; 11,812 expected files): 92.3% recovery, 91.3% temporal accuracy overall; 97.1% on healthy drives; channel demux "accuracy" 97.5%.
- Demux keyed on DHAV channel byte at offset 6 + frame-number continuity (+-3) + <=1 s time check. Verification = internal consistency only (channel-byte uniformity, timestamp monotonicity, SPS/PPS equality) - "ground-truth camera positions were not available for the majority of drives".
- States as background that on IP NVRs streams are "stored in logically separated areas or file formats ... easily extracted on a per-camera basis" and that Magnet/VIP/DiskInternals assume per-camera separation. The team's CP Plus/Dahua NVR drives (channel 0 on every frame) are counter-evidence => D4 is a genuine, citable gap in the published method.
- Table 6 feature matrix: Magnet, VIP 2.0, DiskInternals: no analog interleaved DVR support, "transparent algorithms: No".
- Data not public.
- fmpfeifer/hikextractor (README): written for a JFL DHD-2104N (strings HIKVISION, HIK.2011.03.08; layout differs from Han 2015 in details), also tested on a DS-7208HQHI-SH/A whose RTC failed ("--physical-order" option to export in on-disk order when timestamps are semi-random); FFmpeg MP4 mux; CLI+GUI. Real hardware, no metrics.
- vishwajitsarnobat/HIKVISION-DVR-Tool (2025): master sector + HIKBTREE + system logs -> web timeline, pyewf for E01.

### A38. NISTIR 8161 (Dec 2016; superseded by Rev.1, Apr 2019) - "Recommendation: Closed Circuit Television (CCTV) Digital Video Export Profile - Level 0"
- https://doi.org/10.6028/NIST.IR.8161 (Rev.1: https://doi.org/10.6028/NIST.IR.8161r1). MP4 container, one H.264 stream, MISB embedded time codes (SEI), XMP / UUID "ClockOffset" metadata for the DVR system clock offset; developed with FBI and CCTV-industry input; notes future work on signing/hashing. Directly relevant to D7 and to how recovered clips are exported. Not implemented by any rival found.

### Legal context note (India)
- Blogs report the Supreme Court upheld s.63(4) BSA on 22 May 2026 and stressed hash values in the certificate (NOT verified against the judgment text - check before quoting). Commentary: s.63 certificate needs both the person in charge of the device and an expert, with the hash of the original. D11 is table stakes (every serious rival drafts it).

### A39. Mock & Brunty 2022 - Proceedings of the American Academy of Forensic Sciences (AAFS), Seattle
- "Constructing Digital Video Recorder (DVR) Datasets for Multimedia Forensics Validation" (Marshall University; Rayna Mock may be a graduate student). This is the work behind the NIST CFReDS "HeimVision DVR E01 Forensic Image" (2021) the team used in D12. Abstract-level only (AAFS proceedings); dataset PUBLIC (CFReDS). Relevance: the only public, citable DVR validation dataset found; the team should cite it by this name when presenting D12.

### Commercial doc check (UFS Explorer Video Recovery manual)
- Presents recovered video in virtual folders "according to the camera, year, month and date"; the manual says nothing about time zones, clock offset, or unknown/ambiguous camera numbers. => supports C3/C5 "commercial docs are silent" (absence of documentation, not proof of absence of the feature).
- Magnet "Witness vs DVR Examiner" page: Witness = DVR Examiner + review/analysis; "password bypass", "collection of deleted or overwritten data"; detailed matrix only in a gated white paper.

### A40. Xiang, Bestagini, Tubaro, Delp 2022 - arXiv:2210.11549 "H4VDM: H.264 Video Device Matching" (Purdue VIPER + Politecnico di Milano)
- Open-set "same device?" decision from H.264 COMPRESSION information (not decoded pixels); robust where sensor fingerprints are disturbed; works on relatively small fragments of the H.264 sequence; trained/tested on a public 35-device video forensics dataset (phones/cameras, not CCTV).
- Relevance to D13 / C5: the closest published compressed-domain route to "which camera made this carved fragment" without decoding - a possible future answer to the identical-camera limit that fits a no-decoder carver better than PRNU. Unproven on CCTV encoders (which may be identical firmware/settings).
- Also: Altinisik, Tasdemir, Sencar 2020 (arXiv:2008.08138, IEEE TIFS) block-based weighting ~3x better PRNU matching at low-medium bitrates - the technique CARVE-style PRNU on CCTV would need.
