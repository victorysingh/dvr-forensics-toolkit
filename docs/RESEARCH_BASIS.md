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
- **Checked without an export.** Where no reference export exists, the
  testing standards accept a second method: comparison testing "may be the
  best available testing" (SWGDE 18-Q-001 v2.1, App. A); "Use of Second
  Method" (SWGDE 12-Q-001 §5.8); "uses of multiple tools" to mitigate
  uncertainty (UK FSR-G-218 §7.3.4); comparison with other validated methods
  (ISO/IEC 17025:2017 cl. 7.2.2.1). We apply them on vendor-made files from
  other recorders (`VALIDATION_REPORT.md` §8g): ffmpeg's `dhav` demuxer and
  ours agree frame for frame on two real Dahua recordings, and Hikvision's
  `HK` times agree with the painted clock or the recorder's own file name on
  three Hikvision-made files. None of this raises a status: it is shown next
  to it. Why it matters: in DFPulse 2024, 30% of practitioners (52% in the
  UK, where ISO 17025 applies) said missing validation stops them using
  open-source tools.

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
  continuity is what remains. Park & Lee (2014), the most-cited DVR fragment
  paper, reassemble DVR video fragments in unallocated space by continuity;
  the principle is theirs, and the measurement on real field drives, with a
  stated split-not-guess rule, is what we add.

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
    within 2 s. The OCR route, measured on six real recorders' files
    (29 Sep), read 5 of 36 painted clocks exactly and no title right
    (`VALIDATION_REPORT.md` §8c), so the by-eye checks are the evidence today.
  - No UTC is asserted without a stated time zone and a measured clock error.
  - The combined view (PR #8) refuses to put two recorders on one axis unless
    both state a time zone.
- **Beyond what.** Boyd & Forster (2004) is the standard caution:
  investigators were wrongly accused of tampering because a defence expert
  misread timestamps, and their checklist asks to record the device clock
  against true time at seizure. Our SOP step 1.2 does exactly that, and the
  tool will not convert without it.
- **Independent clocks, checked against each other** (`VALIDATION_REPORT.md`
  §8e, §8g). On NIST's HeimVision image the painted clock, the frame headers
  and the system clock are reconciled: the frame times *are* the painted
  clock, and the system clock runs 8 h behind (zone setting UTC+8). Another
  SIH team's published timeline for the same image disagrees with the
  painted clock by about 11 h 20 min; the cause is not established. On three
  Hikvision-made files the `HK` time equals the painted clock (0 s, 5/5),
  trails it by a constant 1 s (10/10), or equals the recorder's file-name
  start. Dstl (2022) puts it plainly: a hash shows a file was not altered,
  not that its clock was right - that is a question of authenticity.
- **"Working properly", from the device itself.** BSA s.63(2) asks whether
  the device was working properly during the period. The recorder's own
  log answers that from the device: drive 2's log records 188 power cuts,
  and the CP Plus unit's log (read on its screen) matched drive 1's
  recorder-wide gap at 18:59 to the minute (`VALIDATION_REPORT.md` §8).
- **UTC without the unit, from daylight** (`VALIDATION_REPORT.md` §8l). An
  outdoor camera's infrared switches happen at one sun elevation, so the
  recorder offset that puts every dusk and dawn switch at the same elevation
  is its zone plus its clock error. It is measured from the footage, needs
  no camera threshold, and is ruled against the 12-hour alias by the sun's
  direction. Estimating a clock from daylight is prior art (Sundial, EWSN
  2009); reading it from a DVR's infrared switches is the application here.

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

### D9. AI leads on recovered footage, with accuracy measured, not claimed

- **What.** The AI runs on footage the tool recovered from the disk itself,
  including footage the recorder's own index no longer lists. It needs no
  recorder and no vendor software, and runs offline.
  - Every model file is pinned by SHA-256 and recorded in the custody
    ledger.
  - Every output is labelled "lead, not evidence".
  - Nobody is identified. Detection says where a face is, not whose. Face
    search, run only when an examiner supplies a photo, ranks the faces by
    likeness and calls the closest *candidates*, never matches (§8n).
  - Motion activity comes from compressed frame sizes, with no decoding.
- **Measured, including what it gets wrong** (`VALIDATION_REPORT.md` §8a).
  - On 287 frames of real recorder footage labelled by eye, the first
    version found a person in 0 of 57 frames. The tool now finds 44 of 57,
    faces in 22 of 27 and moving vehicles in 7 of 12, and reports parked
    cars once per place (all 6 in a night car park, none false on CAVIAR).
  - Every false alarm is listed: six hands in the picture, and one head at
    a fisheye's edge.
  - It is checked on CAVIAR footage that played no part in any choice: 810
    of 1,089 labelled people (543 before the model change).
  - `validate/analytics_eval.py` and `validate/caviar_eval.py` let anyone
    re-measure it on their own footage.
- **Built for CCTV.**
  - Small, distant people: the frame is also searched in tiles.
  - Ceiling fisheye cameras: the frame is also turned round, because people
    seen from above lie at every angle.
  - A detection fixed in place through a clip is flagged and not counted
    (a steel pot scored as a face at 0.99), and so is a face box spanning
    most of the frame.
- **Face search is built for recorder-sized faces** (`VALIDATION_REPORT.md`
  §8n).
  - The numbers are OpenCV's own: our numpy code reproduces its
    `FaceRecognizerSF` to a cosine of 0.99999, with no OpenCV dependency.
  - It is measured where CCTV lives: LFW faces shrunk and H.264-encoded to
    recorder size, and strangers in real recorder footage. That sets the
    smallest face it will call a candidate.
- **What is not new, and is credited.** The models are public: YOLOX
  (Megvii), YuNet and SFace (OpenCV Zoo; SFace is Zhong et al. [34],
  measured on LFW [35]); faces are aligned to ArcFace's five-point template
  (insightface). Tiling is SAHI (Akyon et al., ICIP 2022),
  and rotation for overhead fisheye is RAPiD's idea (Duan et al., CVPR
  Workshops 2020). What is ours is putting them on footage recovered from a
  raw DVR disk, tied to the evidence chain, with the accuracy measured on
  held-out footage and published.
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
- Robust against damaged or tampered disks: 9,600 corrupted disks fed to
  all 8 vendor parsers found 144 crashes and a hang, now fixed. A parser can
  no longer end in a traceback. The three carvers and the E01 reader were
  fuzzed the same way (`VALIDATION_REPORT.md` §8o).
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
- *Pune Bar Association v. Union of India* (SC, 22 May 2026) upheld s.63(4)
  and its Schedule, called the hash value "an electronic fingerprint", and
  lets the Part B certificate come from a s.79A Examiner of Electronic
  Evidence or, "on the basis of unimpeachable material", from another
  skilled person. The tool is built to give that expert the material: the
  hash (Part A), a hash-chained record of every step, and a per-format
  status with its evidence. It is not admissible in itself; no tool is.
- *Randeep Singh @ Rana v. State of Haryana* (SC, 2024 INSC 887) held CCTV
  footage on a CD inadmissible. Nobody who copied it had seen it, nothing
  tied the CD to the recorder, it carried no hash or marking, and no
  certificate was produced. Each gap has an answer here: a hash per
  artefact bound to the drive's Merkle root; byte offsets and the recorder
  unit read off the platter; a ledger of who did what; and the recorder's
  own index and log checked against the recovered footage.
- Puducherry's G.O.Ms.No.27 (Home Dept, 6 May 2025) names the DVR/NVR itself
  as primary evidence and asks for the hash at seizure. Kerala Police's CCTV
  seizure SOP asks for make and model, a time check against a reference
  clock, and native export - the steps `record-device`, `identify-model`,
  SOP 1.2 and `validate-export` turn into recorded, hashed steps.
- MeitY's s.79A Examiner scheme (v2.0, Nov 2025) now lists "CCTV Forensics";
  labs must run ISO/IEC 17025 and list every tool, free or commercial, with
  its version - which is what the per-format status and validation records
  are for.

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
  - **The recorder's zone setting measured two independent ways**, both UTC+8:
    - its system clock (FAT times) against the frame times, on all 806 files;
    - its system clock (ext3 file times) against the times in its own log.
    - The frame and log times equal the clock painted on the picture, so
      they are local time, not UTC (corrected 29 Sep; first reported as
      UTC-8).
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
  - That limit is **this tool's**, not the field's: CARVE (Giri, Yoon &
    Hwang, DFRWS APAC 2026) separates identically configured Honeywell
    cameras by OCR of the painted camera label, or by PRNU sensor noise where
    there is none. Neither route is in our stdlib-only carver.
- **Beyond what.** Garfinkel (2007) makes structural validation the test for
  accepting a carved candidate. We apply it, then **measure** the result
  against ground truth on real media and publish what the carver cannot do.
  Rzayeva et al. (2025) report 2.4% false positives on their own drives, but
  that is a different measure on different data, so the two numbers are not
  directly comparable.

---

### D14. Two formats nobody has published, read from the vendors' own code

- **What.** Uniview and TP-Link have no published on-disk format (OEM_COMPARISON
  §5.1). Their public firmware was unpacked and the storage code read by
  static disassembly - nothing run - and each structure tied to the function
  that writes it. The result is two drop-in plugins: Uniview's block store
  (superblock, index, 256 MiB blocks, self-checking GOPs) and TP-Link's index
  (a SQLite database in TP's own header, which the firmware can AES-encrypt).
- **Evidence** (`VALIDATION_REPORT.md` §8f): 18 tests on disks built to the
  readings, including Uniview footage found with its index wiped, and an
  encrypted TP-Link index reported as encrypted rather than guessed at.
- **Beyond what.** No paper or rival found covers either format (hunt of 29
  Sep: `docs/research/`); commercial tools claim support without a layout.
  Stoykova et al. (2022, CLSR 46:105725) ask that a reverse-engineered format
  be documented and testable to be relied on; each field here cites its
  firmware function, and the status stays `spec_only` until a real disk
  checks it.
- **Then Godrej (29 Sep, `VALIDATION_REPORT.md` §8j).** Godrej's SeeThru
  recorders run Qualvision's software, so Qualvision's firmware was read the
  same way: the QVFS disk head, and a 20-byte frame head whose time the
  firmware's own debug print decodes with Dahua's packed-date shifts. A
  self-checking frame chain then finds and dates footage without the index.
  With Matrix from its own documents (§8h), all eight named OEMs now have a
  plugin, each with its source and what it does not know.

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

Stress-tested against the literature and 30+ rival repositories (29 Sep,
`docs/research/`):

- Recovered **6,300 hours** of Hikvision footage from under **another vendor's
  reformat**: 99.6% of what the drive's own surviving index says was
  recorded. No paper or rival tests a cross-vendor reformat.
- **Times checked, not trusted:** the recorder's log matched a video gap to
  the minute; on NIST's public image the painted, frame and system clocks are
  reconciled (zone setting UTC+8), where another team's timeline is ~11 h off
  the painted clock.
- **Nothing is called `validated`** until it byte-matches the recorder's own
  export; meanwhile every format shows the checks it passed - second
  implementation, vendor-made files - as SWGDE and ISO 17025 allow.
- **Real media from three recorder families** (Dahua/CP Plus, Hikvision,
  HeimVision), failures published. No paper or rival has more than two.
- Cameras separated **even where the frames carry no camera number**; split,
  never guessed.

Not unique, so not pitched as such: hashes, the Merkle map, the custody
ledger, the s.63 draft, "AI as a lead", offline use, testing on the NIST
image, and reading the model off the platter (Yoon & Hwang did it for
Honeywell). They are the engineering under the five lines above.

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

23. J. Park, S. Lee. *Data fragment forensics for embedded DVR systems.* Digital Investigation 11(3):187–200, 2014. doi:10.1016/j.diin.2014.06.001 — [doi](https://doi.org/10.1016/j.diin.2014.06.001). Abstract only.
24. S. Giri, J. Yoon, S. Hwang. *CARVE: Recovering and Reconstructing Deleted H.264/H.265 Video from Honeywell Surveillance Systems.* DFRWS APAC 2026 — [dfrws.org](https://dfrws.org/presentation/carve-recovering-and-reconstructing-deleted-h-264-h-265-video-from-honeywell-surveillance-systems/). Abstract.
25. *Pune Bar Association v. Union of India*, W.P.(C) No. 599 of 2026, Supreme Court of India, 22 May 2026, 2026 LiveLaw (SC) 551 — [judgment](https://www.livelaw.in/pdf_upload/2026/05/27/pune-bar-association-v-union-of-india-676590.pdf). Read in full.
26. *Randeep Singh @ Rana v. State of Haryana*, 2024 INSC 887, Supreme Court of India, 22 Nov 2024 — [judgment](https://api.sci.gov.in/supremecourt/2023/51279/51279_2023_5_1502_57415_Judgement_22-Nov-2024.pdf). CCTV passages read.
27. Government of Puducherry, Home Dept, G.O.Ms.No.27, 6 May 2025, *Comprehensive Guidelines for the admissibility of digital and electronic records under the BSA, 2023* — [PDF](https://police.py.gov.in/GO.Ms.No.27%20-%20Comprehensive%20Guidelines%20on%20Digital%20and%20electronic%20records%20-%20Home%20Order%20dst%2006.05.25.pdf). Read in full.
28. Kerala Police. *SOP: Digital Evidence Related to Crimes against Women and Children*, ch. 4 "Seizing CCTV" — [PDF](https://keralapolice.gov.in/storage/pages/custom/ckFiles/file/7GafuMCjLbFgjBNh8aXz8WhLv2Zqtfczvbi7Uv6m.pdf). Chapter read.
29. MeitY. *Scheme for Notifying Examiner of Electronic Evidence* (s.79A IT Act), v2.0, Nov 2025 — [PDF](https://www.meity.gov.in/static/uploads/2025/11/67f1ee29ffea0e76a3e5b5fee9883711.pdf). Read in full.
30. SWGDE 18-Q-001 v2.1 (2024), minimum requirements for tool testing, App. A; SWGDE 12-Q-001 v2.0 (2018), §5.8 "Use of Second Method" — [swgde.org](https://www.swgde.org/). Sections read.
31. UK Forensic Science Regulator. *FSR-G-218 Issue 2, Method Validation in Digital Forensics* (2024) — [PDF](https://assets.publishing.service.gov.uk/media/5f6ca608d3bf7f7231ac65e0/218_Method_Validation_in_Digital_Forensics_Issue_2_New_Base_Final.pdf). Sections read. ISO/IEC 17025:2017 cl. 7.2.2.1 (secondary summary; the standard is paywalled).
32. C. Hargreaves, F. Breitinger, L. Dowthwaite, H. Webb, M. Scanlon. *DFPulse: The 2024 digital forensic practitioner survey.* Forensic Science International: Digital Investigation 51:301844, 2024. doi:10.1016/j.fsidi.2024.301844. Read in full.
33. Dstl. *Recovery and Acquisition of Video Evidence*, v3.0, 28 Feb 2022 — [gov.uk](https://www.gov.uk/government/publications/recovery-and-acquisition-of-video-evidence). Relevant passages read.
34. Y. Zhong et al. *SFace: Sigmoid-Constrained Hypersphere Loss for Robust Face Recognition.* IEEE Transactions on Image Processing 30, 2021; arXiv:2205.12010. The model card (OpenCV Zoo, `face_recognition_sface`) read; the paper not read in full.
35. G. B. Huang, M. Ramesh, T. Berg, E. Learned-Miller. *Labeled Faces in the Wild: A Database for Studying Face Recognition in Unconstrained Environments.* UMass Amherst Technical Report 07-49, 2007. Used as data (§8n).

Items 15–17 and 20 are standard references not re-fetched on 28 Sep; items
1–14, 18–19 and 21–22 were checked on 28 Sep, and 23–33 on 29 Sep, as
marked. Full notes: `docs/research/`.
