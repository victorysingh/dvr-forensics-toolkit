# What sets this tool apart, and the research it stands on

PS26150. For the pitch, the final project report and anyone who asks "how
is this different, and what is it based on?"

Written 28 Sep 2026. Every citation below was checked against the
publisher or an index on that date; the links are at the end. Where we could
not read a paper's full text, we say so and compare only what its abstract
states.

---

## 1. In one paragraph

Published DVR forensics is mostly one vendor per paper. It either reverse-engineers
one filesystem (Hikvision: Han, Jeong & Lee 2015; Dahua DHFS: Rzayeva et al.
2025; Honeywell: Yoon & Hwang 2026) or carves one container without the
filesystem (Ariffin, Slay & Choo 2013). This tool puts those ideas into
**one read-only pass** over a real drive and adds three things they do not
provide: **a per-block Merkle map and a hash-chained custody ledger**, so any
recovered clip can be proven to the acquisition later; **a status for every
vendor claim that only a byte-match against the recorder's own export can
raise to `validated`**; and **measurements on two real 1 TB drives**,
including the failures they exposed, **and on a public NIST image that
anyone can re-check** (D12).

---

## 2. What sets it apart

Each item has: what we do, the evidence, and the research or practice it
goes beyond.

### D1. Validation that cannot be claimed early

- **What.** Every vendor format carries a status: `validated`, `spec_only`,
  `synthetic_only` or `detected_not_parsed`. The **weakest** piece of
  evidence sets it, and that rule is enforced in code
  (`detect/engine.py::_weakest`). Only a byte-match of recovered footage
  against the recorder's own export can reach `validated`. `validate-export`
  (PR #9) does that match on the picture slices, in order.
- **Evidence.** Today nothing is `validated`, and the report says so. Dahua/CP
  Plus and the Hikvision container are `spec_only`, which means observed on
  real media but not yet byte-matched.
- **Beyond what.** The trap in this problem statement is claiming eight OEMs.
  One public repository for this same problem statement (Sep 2026) labels its
  Dahua parser `VALIDATED` and returns 100% confidence whenever the four bytes
  `DHFS` appear in the first 4 KiB, with an 8 MiB sample image as its test
  data. We report confidence as a score that saturates below 100%
  (`detect/engine.py`), and we treat `validated` as something only a
  recorder's own export can grant.

### D2. Measured on real drives, failures included

- **What.** Two real 1 TB surveillance drives, each acquired in a complete
  read-only pass. The failures they exposed are documented, not hidden
  (`VALIDATION_REPORT.md` §6).
- **Evidence.**
  - Drive 1 (CP Plus unit, Seagate ST1000VX013 `WWD4A3NX`) and drive 2
    (Hikvision footage, Seagate ST1000VX005 `Z9C2632A`).
  - Whole-drive MD5 and SHA-256, 0 unreadable sectors.
  - The USB bridge dropped out 5 times. The first two drops exposed the
    bugs below; the scan has since survived all 3 later drops by verified
    reconnect.
  - Five independent reads over three days agree bit for bit, apart from
    the two blocks that bug corrupted.
  - **Two bugs that could have put wrong data into the evidence hash**,
    found only on real hardware:
    - a lost device recorded as 180 GB of "bad sectors";
    - a short read zero-padded into the hash.

    Both are fixed, each with a regression test that fails on the old code.
- **Beyond what.** Published DVR papers report results, not the acquisition
  failures behind them. A defensible tool has to say what went wrong and how
  it was caught.

### D3. Footage recovered from a drive that was reformatted

- **What.** Drive 2's top layer is an empty Dahua-family DHFS format. Under it
  is a Hikvision recorder's footage, which the MPEG-PS carver recovers by
  structure alone and dates from Hikvision's `HK` stream-map descriptors.
- **Evidence.**
  - 2,516 streams, 923 GiB, about 6,300 hours, April 2021 to 30 Aug 2024.
  - Two copies of the Hikvision index survived near the end of the disk.
    Decoded, they give a ground truth *on the disk itself*: the carve recovered
    **99.6–99.7% of the hours the index says each of the 8 cameras recorded**.
  - Camera labels were checked against the picture: "Camera 01" and
    "Camera 03" burned in; clocks within 2 s.
- **Beyond what.** Han, Jeong & Lee (2015) describe the Hikvision filesystem
  as the recorder wrote it. Ariffin, Slay & Choo (2013) carve CCTV video with
  timestamps without the filesystem. We combine the two on a drive whose
  filesystem was destroyed by *another vendor's* format. We also use the
  surviving index both to name the camera and to *measure* the carve.

### D4. Separating cameras when the frames do not say which camera

- **What.** On our CP Plus unit (IP cameras), the DHAV channel byte is **0 for
  every camera**. Camera identity lives only in the DHFS index. The carver
  therefore separates streams by continuity (frame counter, millisecond
  clock, date). Where cameras cannot be told apart, it **splits rather than
  guesses**.
- **Evidence.** The full-drive carve found 349.5 M frames; 1,196 ambiguous
  boundaries were split, not guessed. On generated "twin" cameras with
  identical counters and clocks, no stream mixes sources.
- **Beyond what.** An Information (MDPI) paper from May 2026 demultiplexes
  interleaved DHAV streams from *analog* Dahua DVRs using the **channel
  identifiers embedded in the frames** plus temporal coherence. That works
  where the identifier is set. On the IP-camera unit we hold it is not, and
  continuity is what remains.

### D5. One pass, provable afterwards

- **What.** A single read-only traversal computes MD5 + SHA-256, a SHA-256
  per 8 MiB block with a **Merkle root** over them, vendor detection, both
  carvers and motion activity. Any byte range can later be proven to the root
  with a short inclusion path (`prove`), without re-reading the drive.
- **Evidence.** 11 h over USB 2.0 for 931.5 GiB, one pass. The run resumes
  across USB drops by re-verifying the last blocks before continuing. The
  preserved metadata (72 MB) is provable block by block.
- **Beyond what.** The Merkle tree is Merkle's (1987) construction, applied to
  a disk. It is how "Blockchain & Cybersecurity" is met without a
  blockchain: tamper-*localisation* (which block changed) rather than a bare
  "something changed".

### D6. A custody record that cannot be edited quietly

- **What.** Every action is appended to a hash-chained ledger with the hash of
  what it produced: scan, carve, extraction, timeline, analytics, OCR,
  validation, model. `verify` re-walks it.
- **Beyond what.** The hash-chained audit log follows Schneier & Kelsey
  (1999). What we add is scope: every derived artefact, not only access
  events, is bound into the chain.

### D7. Time handled the way a court would test it

- **What.**
  - Two independent routes to the recorder's clock: the date in the container
    (DHAV packed date, Hikvision `HK` descriptor) and the clock burned into
    the picture. They are cross-checked; three frames were checked by eye, all
    within 2 s. The OCR route, run on real frames for the first time (28 Sep),
    read 1 of 5 reference titles and no clock yet (`VALIDATION_REPORT.md`
    §8c), so the by-eye checks are the evidence today.
  - No UTC is asserted without a stated time zone and a measured clock error.
  - The combined view (PR #8) refuses to put two recorders on one axis unless
    both state a time zone.
- **Beyond what.** Boyd & Forster (2004) is the standard caution:
  investigators were wrongly accused of tampering because a defence expert
  misread timestamps, and their checklist asks to record the device clock
  against true time at seizure. Our SOP step 1.2 does exactly that, and the
  tool will not convert without it.

### D8. Vendor *and* model, with the disk's history as a finding

- **What.**
  - Vendor attribution is a confidence score, never a yes/no (CP Plus units
    are commonly Dahua-built).
  - The model is taken from two sources kept apart (PR #10): strings on the
    platter outside the video, and the examiner's reading of the unit with
    the photos hashed.
  - The two are cross-checked. A Hikvision unit whose disk carries Dahua
    structures is flagged as a disk another recorder formatted, which is drive
    2's actual history.
- **Evidence** (first real-media run, 28 Sep, PR #28). On drive 2,
  `identify-model` finds `DS-7B08HUHI-K1` 208 times on the platter. That
  agrees with the team's unit label. The unit's full device serial appears on
  the platter 202 times, so this unit wrote this drive.
- **Beyond what.** Rzayeva et al. (2025) list automatic manufacturer
  identification as one of their three innovations. We go on to check the
  manufacturer against the unit it was seized from, and we treat a mismatch
  as evidence.

### D9. AI that knows it is a lead

- **What.** Motion activity from compressed frame sizes, with no decoding.
  Faces and objects are an optional layer. Every output is labelled "lead,
  not evidence". Detections fixed in place through a clip (a steel pot
  scored as a face at 0.99) and face boxes spanning most of the frame are
  flagged and not counted.
- **Beyond what.** Compressed-domain motion detection is established. Poppe et
  al. (2009) detect moving objects in H.264 surveillance video from the size
  of the coded data rather than from motion vectors. We use the coarsest form of
  that idea (frame sizes per camera per minute) because it runs inside the
  acquisition pass with no decoder at all.

### D10. Air-gapped and auditable

- The forensic core (`core/`, `acquire/`, `detect/`, `parsers/`, `recover/`,
  and `validate/` from PR #9) is Python standard library only. It runs on a bare install
  with no network.
- The Dahua DHFS and Hikvision PS layouts are published as Kaitai Struct
  `.ksy` files, so others can check our reading of each format. Both are
  compiled with the official compiler and checked field by field against our
  own parsers (`validate/ksy_check.py`); the first check found, and we fixed,
  a Hikvision `.ksy` that compiled but could not read a stream. HeimVision's
  layout (D12) is documented in its plugin, not yet as a `.ksy`.
- Magnet Witness (formerly DVR Examiner, from DME Forensics), the leading
  commercial tool, is closed. We do not claim to match its vendor coverage.
  We claim a method that shows its evidence.

### D11. Built for Indian courts

- The Supreme Court held in *Arjun Panditrao Khotkar v. Kailash Kushanrao
  Gorantyal* (2020) that the Section 65B(4) certificate is mandatory for
  electronic records when the original is not produced.
- The Bharatiya Sakshya Adhiniyam, 2023 carries this forward in **Section
  63**. Its Schedule sets out the certificate in two parts: **Part A** by the
  party producing the record, and **Part B** by an expert. It asks for the
  record's **hash value and the algorithm** (SHA-1, SHA-256, MD5 or another
  accepted standard).
- The tool already produces exactly those values for every artefact, bound to
  the custody ledger, and drafts the certificate from the case
  (`cli.py certificate`, PR #14), recording the draft in the ledger. Its
  wording must be checked against the Schedule by Hriday before use.

### D12. Tested on a public image that anyone can re-check

- **What.** Besides our own two drives, the tool was run on a **public,
  independently published** disk image: the NIST CFReDS *Heimvision DVR .E01
  Forensic Image* (Brunty & Mock, Marshall University, 2021), the 150 GB disk
  of a HeimVision K9604-W 4-channel DVR, imaged with FTK Imager. HeimVision is
  not one of the eight vendors in the problem statement, so this was the
  add-a-vendor route (detect, survey, plugin) tried on a recorder we had never
  seen. The problem statement also asks for "other commonly used platforms".
- **Evidence** (`VALIDATION_REPORT.md` §8e):
  - **The image checks our reader.** Our own E01 reader (`acquire/ewf.py`)
    read all 150,039,945,216 bytes and computed an MD5 and SHA-1 **equal to
    the ones FTK Imager stored in the image**.
  - **An unknown format decoded from the disk alone** (`plugins/heimvision.py`):
    - an ext3 system partition, and a FAT32 ring of 17,152 files of 8 MiB;
    - every frame names its camera and carries a microsecond time;
    - 806 files were written: 24 h continuous on 4 cameras. CH01 has
      1,296,146 frames against the 1,296,150 that 24 h at 15 fps predicts.
  - **The recorder's time zone measured two independent ways**, both UTC-8:
    - the FAT clock against the frame times, on all 806 files;
    - the Linux clock (ext3 file times) against the UTC times in the
      recorder's own log.
  - **The recorder's own records checked, not trusted:**
    - its event log: 194 entries with no gaps, so none were deleted;
    - its recording index: 806 of 806 files listed with exactly the times
      their own headers give;
    - `index.bin`: marks every written file complete except the last one,
      still open when recording stopped.
  - Pinned by 3 real-image tests that run when the image is present.
  - Status stays `spec_only`: observed on real media, not byte-matched
    against a HeimVision export (D1).
- **Beyond what.** DVR studies typically test on drives the authors hold
  (Han, Jeong & Lee 2015; Rzayeva et al. 2025, 27 drives). A reader can
  follow the method but cannot re-run it on the same disk unless the images
  are published.
  Case-study reverse engineering (Tobin, Shosha & Gladyshev 2014; Gomm et al.
  2016) shows how a proprietary format was read. We add two things:
  - a result anyone can reproduce from a public image with a published hash;
  - the recorder's own log and index used to **check** the reading.

### D13. The fallback carver measured against ground truth, limits stated

- **What.** For a recorder with no parser, `carve-annexb` recovers raw
  H.264/H.265 by its parameter sets alone. On the HeimVision image the plugin
  knows every frame, so the carver's output could be scored start code by
  start code against a real recorder's own layout
  (`python -m validate.heimvision_carve <E01>`).
- **Evidence** (`VALIDATION_REPORT.md` §8e):
  - It ran over every part of the image that holds data: 178 regions,
    6.47 GiB.
  - It found **5,187,890 slices**. That is exactly the slice-shaped start codes
    in the 806 written files, less one per stream (a carved stream leaves out
    its last unit, whose end is unknown).
  - 3,826 of them (**0.07%**) are chance start codes in the recorder's own
    container bytes, not video. 884 of those look like keyframes: 2.5% of the
    keyframe count.
  - **The limit, stated:** the four cameras share one set of encoder settings,
    so every carved stream mixes all four. Only the container separates the
    cameras and gives the time. The carver therefore stays `synthetic_only`:
    it finds the video, but its streams here are not any one camera's footage.
  - **The same result on our own drive 1** (first real-media run, 28 Sep,
    PR #28). Over the first 8 GiB it covers 100% of the bytes the DHAV
    carver recovered, plus 48.7 MiB more, but as **one** stream: the three
    cameras share identical encoder settings.
- **Beyond what.** Garfinkel (2007) makes structural validation the test for
  accepting a carved candidate. We apply it, then **measure** the result
  against ground truth on real media and publish what the carver cannot do.
  Rzayeva et al. (2025) report 2.4% false positives on their own drives, but
  that is a different measure on different data, so the two numbers are not
  directly comparable.

---

## 3. Component by component: what it is built on

| Component | Built on | What we took | What we found or added on real media |
|---|---|---|---|
| Hikvision filesystem (`parsers/hikvision.py`, `hikbtree.py`) | Han, Jeong & Lee 2015 | `HIKVISION@HANGZHOU` master sector at 0x200; `HIKBTREE` index | 48-byte index records decoded from copies that survived a reformat; the 1 GiB data-block grid; channel per block; carved streams labelled from it |
| Hikvision video container (`recover/pscarve.py`, `formats/hikvision_ps.ksy`) | ISO/IEC 13818-1 (MPEG-2 Program Stream) | pack / PES / stream-map structure | `HK` descriptor 0x40 time decoded, checked against the burned-in clock to the second |
| Dahua DHAV frames (`parsers/dahua.py`) | ffmpeg `libavformat/dhav.c` | header layout, packed date, codec tags | header checksum = byte sum of 0x00–0x16 (ffmpeg ignores it); trailer repeats the length |
| Dahua DHFS 4.1 filesystem (`parsers/dahua.py`, `formats/dahua_dhfs41.ksy`) | Rzayeva et al. 2025 (header–footer validation of DHFS frames) | frame validation by header and trailer | partition table at 0x3C00 with backup; 32-byte cluster records; data-area base calibrated from frames; overflow into the *physically* next cluster; channel byte 0 on every camera |
| Camera separation (`recover/carver.py`) | Information 2026 (DHAV demultiplexing by channel identifier) | the problem statement: interleaved cameras | separation by stream continuity where the identifier is 0; split, never guess |
| Carving without a filesystem | Ariffin, Slay & Choo 2013; Tobin, Shosha & Gladyshev 2014; Gomm et al. 2016 | recover footage by structure, not by index | runs inside the acquisition pass; recovered the whole of a reformatted drive |
| Candidate validation in carving | Garfinkel 2007 (fast object validation) | accept a candidate only if its structure validates | a PS pack only if its packets end exactly at the next pack; a DHAV frame only if checksum and trailer hold |
| Corrupted / partial frames | Na et al. 2014 (frame-based recovery by codec specification) | — | the cause on drive 1 is measured: a reference frame missing from the disk (`VALIDATION_REPORT.md` §7). Decoding what such a frame still holds would serve a marked viewing copy, never the evidence |
| Integrity | Merkle 1987 | hash tree, inclusion proofs | per-8 MiB-block leaves; proofs per clip and per preserved structure |
| Custody | Schneier & Kelsey 1999 | hash-chained log | every derived artefact in the chain |
| Time | Boyd & Forster 2004 | record the device clock against true time | two clocks per stream cross-checked; no UTC without stated inputs |
| Motion | Poppe et al. 2009 | motion from compressed-domain sizes | frame sizes per camera per minute, inside the pass |
| OSD titles and clock | Tesseract (Smith 2007) | OCR engine | a label only when frames agree; ambiguous dates left ambiguous |
| Faces and objects | SSD (Liu et al. 2016), MobileNet (Howard et al. 2017), Ultra-Light face detector | detectors | static and implausible-box rules; "lead, not evidence" |
| Procedure | SWGDE *Best Practices for Data Acquisition from DVRs*; ISO/IEC 27037:2012; NIST SP 800-86 | seizure and acquisition practice | `SOP_EXAMINATION.md`, `LINUX_ACQUISITION.md` |
| Hikvision system log (`parsers/hiklog.py`) | Dragonas et al. 2023 (Hikvision log records); Hikvision's published SDK codes | where the log lives and how records are typed | 43,108 records from drive 2, read from the surviving master-sector copy with six cross-checks; power cuts and an admin session found; the log's clock checked against the footage |
| Honeywell (`plugins/honeywell.py`) | Yoon & Hwang 2026 (DFRWS USA) | the first published analysis of Honeywell's surveillance filesystem | a plugin at `spec_only` from their description; no real Honeywell disk yet |
| E01 images (`acquire/ewf.py`) | the libyal description of the Expert Witness (EWF) format | segments, section chain, chunk table, compressed and stored chunks | reproduces FTK Imager's stored MD5 and SHA-1 over a real 150 GB image (D12) |
| HeimVision K9604-W (`plugins/heimvision.py`, `parsers/ext3.py`) | NIST CFReDS public image (Brunty & Mock 2021); the ext2/ext3 on-disk layout | a public, published test image | the layout decoded from the disk; the zone measured two ways; the recorder's own log and index checked against the disk (D12) |
| Fallback carver scored (`validate/heimvision_carve.py`) | Garfinkel 2007 | structural validation of carved candidates | every carved slice accounted for against the recorder's own frames; 0.07% container bytes; cameras with identical settings not separable (D13) |

---

## 4. Next steps the research points to

1. **Date drive 2's reformat from its own logs.** Dragonas, Lambrinoudakis &
   Kotsis (2024) show that Dahua log records document user actions, including
   *formatting the hard drive*. If the log area of the Dahua-family format on
   drive 2 holds such a record, it dates the reformat and may name the
   recorder that did it.
2. ~~**Model and serial from Hikvision logs.**~~ **Done, 28 Sep (PRs #28,
   #29).** The model and the unit's serial were found on the platter outside
   the log (D8). The Hikvision system log itself is now read, following the
   record analysis of Dragonas et al. (2023) (`parsers/hiklog.py`, 43,108
   records). It shows 188 power cuts and one local admin session. It keeps
   the recorder's own clock, so it cannot give the time zone either.
3. **Honeywell on a real disk.** The plugin is built from Yoon & Hwang (2026)
   (PR #13) and is `spec_only`; any real Honeywell disk or image is what
   moves it on.
4. **Frames after a missing reference** on drive 1. The cause is measured
   (`VALIDATION_REPORT.md` §7) and confirmed frame by frame: `decode-check`
   explains 99.8% of the failures after a keyframe with a missing frame.
   Following Na et al. (2014), decode what each such frame still holds, for
   a viewing copy marked as such - never as intact evidence.

---

## 5. For the slides (five lines)

- Recovered **6,300 hours** of Hikvision footage from under **another vendor's
  format**: 99.6% of what the surviving index says was recorded.
- **One read** of a 1 TB drive: hashes, Merkle map, detection, both carvers;
  any clip provable later without re-reading.
- **Nothing is called `validated`** until it byte-matches the recorder's own
  export; the tool to do that is built.
- Cameras separated **even where the frames carry no camera number**; split,
  never guessed.
- **Two real drives, two real bugs** found and fixed, each with a regression
  test.

---

## References

1. J. Han, D. Jeong, S. Lee. *Analysis of the HIKVISION DVR File System.* ICDF2C 2015, LNICST 157, pp. 189–199. doi:10.1007/978-3-319-25512-5_13 — [Springer](https://link.springer.com/chapter/10.1007/978-3-319-25512-5_13)
2. Rzayeva et al. *Automated Forensic Recovery Methodology for Video Evidence from Hikvision and Dahua DVR/NVR Systems.* Information 16(11):983, 2025 — [MDPI](https://www.mdpi.com/2078-2489/16/11/983). Full text not accessible to us; compared on its abstract (27 drives; 91.8% recovery, 96.7% temporal accuracy, 2.4% false positives).
3. *Forensic Video Recovery from Multi-Channel Analog DVR Systems: Channel Demultiplexing and Temporal Reconstruction from Interleaved DHAV Streams.* Information 17(5):493, 2026. doi:10.3390/info17050493 — [doi](https://doi.org/10.3390/info17050493). Compared on its abstract.
4. J. Yoon, S. Hwang. *Forensic analysis of video data deletion and recovery in Honeywell surveillance file system.* DFRWS USA 2026 — [arXiv:2605.07430](https://arxiv.org/abs/2605.07430), [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S2666281726000739)
5. A. Ariffin, J. Slay, K.-K. R. Choo. *Data Recovery from Proprietary Formatted CCTV Hard Disks.* Advances in Digital Forensics IX (IFIP), 2013 — [Springer](https://link.springer.com/chapter/10.1007/978-3-642-41148-9_15)
6. L. Tobin, A. F. Shosha, P. Gladyshev. *Reverse engineering a CCTV system, a case study.* Digital Investigation 11(3):179–186, 2014. doi:10.1016/j.diin.2014.07.002 — [ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S1742287614000917)
7. R. Gomm, N.-A. Le-Khac, M. Scanlon, M-T. Kechadi. *An Analytical Approach to the Recovery of Data from 3rd Party Proprietary CCTV File Systems.* ECCWS 2016 — [PDF](https://markscanlon.co/papers/AnalyticalApproachToTheRecoveryOfDataFromCCTVFileSystems.pdf)
8. E. Dragonas, C. Lambrinoudakis, M. Kotsis. *IoT forensics: Exploiting log records from the DAHUA technology CCTV systems.* J. Forensic Sci. 69(1):117–130, 2024. doi:10.1111/1556-4029.15401 — [Wiley](https://onlinelibrary.wiley.com/doi/10.1111/1556-4029.15401)
9. E. Dragonas et al. *IoT forensics: Exploiting unexplored log records from the HIKVISION file system.* J. Forensic Sci., 2023. doi:10.1111/1556-4029.15349 — [Wiley](https://onlinelibrary.wiley.com/doi/10.1111/1556-4029.15349)
10. S. L. Garfinkel. *Carving contiguous and fragmented files with fast object validation.* Digital Investigation 4S:2–12, 2007. doi:10.1016/j.diin.2007.06.017 — [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S1742287607000369)
11. G.-H. Na, K.-S. Shim, K. W. Moon, S. G. Kong, E.-S. Kim, J. Lee. *Frame-Based Recovery of Corrupted Video Files Using Video Codec Specifications.* IEEE Trans. Image Processing 23:517–526, 2014. doi:10.1109/TIP.2013.2285625 — [doi](https://doi.org/10.1109/tip.2013.2285625)
12. B. Schneier, J. Kelsey. *Secure audit logs to support computer forensics.* ACM TISSEC 2(2):159–176, 1999. doi:10.1145/317087.317089 — [ACM](https://dl.acm.org/doi/10.1145/317087.317089)
13. C. Boyd, P. Forster. *Time and date issues in forensic computing — a case study.* Digital Investigation 1:18–23, 2004. doi:10.1016/j.diin.2004.01.002 — [ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S1742287604000076)
14. C. Poppe, S. De Bruyne, T. Paridaens, P. Lambert, R. Van de Walle. *Moving object detection in the H.264/AVC compressed domain for video surveillance applications.* J. Visual Communication and Image Representation 20(6):428–437, 2009 — [ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S1047320309000650)
15. R. C. Merkle. *A Digital Signature Based on a Conventional Encryption Function.* CRYPTO '87, LNCS 293, 1988.
16. R. Smith. *An Overview of the Tesseract OCR Engine.* ICDAR 2007.
17. W. Liu et al. *SSD: Single Shot MultiBox Detector.* ECCV 2016. A. G. Howard et al. *MobileNets.* arXiv:1704.04861, 2017.
18. SWGDE. *Best Practices for Data Acquisition from Digital Video Recorders* (17-V-002, v1.3, 2025) — [PDF](https://www.swgde.org/wp-content/uploads/2025/03/2025-02-28-Best-Practices-for-Data-Acquisition-from-Digital-Video-Recorders-17-V-002-1.3.pdf). ISO/IEC 27037:2012. NIST SP 800-86 (2006).
19. *Arjun Panditrao Khotkar v. Kailash Kushanrao Gorantyal*, Supreme Court of India, 14 Jul 2020 — [judgment (APHC copy)](https://aphc.gov.in/docs/imp_judgements/Arjun%20Panditrao%20Khotkar%20_%20Kailash%20Kushanrao%20Gorantyal%20And%20Ors._1701334263.pdf). Bharatiya Sakshya Adhiniyam, 2023, s.63 and the Schedule — [bare act, certificate](https://www.advocatekhoj.com/library/bareacts/bharatiyaaakshya2023/b.php)
20. FFmpeg, `libavformat/dhav.c` (DHAV demuxer). Kaitai Struct.
21. J. Brunty, R. Mock (Marshall University). *Heimvision DVR .E01 Forensic Image*, 2021. NIST Computer Forensic Reference Data Sets (CFReDS) — [cfreds.nist.gov](https://cfreds.nist.gov/). Media MD5 `4895ea6d10b08c29fb1bb03591adc7b2`.
22. J. Metz (libyal). *Expert Witness Compression Format (EWF)* — [libewf documentation](https://github.com/libyal/libewf/tree/main/documentation).

Items 15–17 and 20 are standard references not re-fetched on 28 Sep; the rest
were checked on that date.
