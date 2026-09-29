# Research summary: both hunts (28-29 Sep 2026)

This page summarises four working notes in this folder: `papers_usp.md` and
`datasets.md` (hunt 1), and `usp_papers_deep.md`, `datasets_deep.md` and
`vendor_formats.md` (hunt 2). The notes are leads, not citations. Each claim
below names the note it comes from; check the source before it goes into
the final report. "Done" marks what the team has built since the hunts.

## 1. The bottom line

1. **No public DVR/NVR disk image exists for any of the eight vendors.**
   The only public DVR image is NIST's HeimVision E01, which we already use.
   Every rival without real media validates on data it generated itself.
2. **Five claims survive stress-testing** (§2):
   - recovery from under a different vendor's reformat;
   - times corroborated by the recorder's own log;
   - validation earned against known data;
   - real media from three recorder families;
   - cameras split, never guessed.

   Hunt 2 searched for each again and found none elsewhere.
3. **The legal case is now concrete** (§5):
   - the Supreme Court's 2026 ruling on BSA s.63 asks the Part B expert for
     "unimpeachable material";
   - a 2024 Supreme Court judgment lost CCTV evidence for want of exactly
     the links this tool records;
   - an Indian police SOP already asks for the steps the tool automates.
4. **Uniview and TP-Link formats were never published, but their firmware
   is public.** Reading it gave both plugins (PR #43). Godrej (a Qualvision
   OEM, format "QVFS") and Matrix (a normal file tree) look next-feasible
   by the same route (§7).
5. **Two papers must be cited before the final:**
   - Park & Lee 2014, the most-cited DVR fragment paper, is missing from our
     references;
   - CARVE (DFRWS APAC 2026) separates identically configured cameras by
     OCR and PRNU. So "identical cameras cannot be separated" is a limit of
     this tool, not of the field (§4).

## 2. What makes the tool different (claims that survive)

| # | Claim | Evidence | Say it like this |
|---|---|---|---|
| 1 | Footage recovered from under a **different vendor's reformat**, measured against the disk's own surviving index | drive 2: ~6,300 h of Hikvision footage under a Dahua-family format, 99.6-99.7% of what HIKBTREE says was recorded | "measured against the drive's own partial index" - never "beats 91.8%" (a different scenario from Rzayeva 2025) |
| 2 | **Times corroborated, not trusted** | drive 1: the recorder's event log matched a 1-minute gap in the video, to the minute; HeimVision: its own log and index checked against the disk; the HeimVision zone finding (#37) | "corroborated on one real drive" - one case, not a rate. On the NIST image, a rival (Trace) publishes the recorder's local display time as UTC (`usp_papers_deep.md` §4) |
| 3 | **Validation earned, per format, against known data** | status ladder set by the weakest evidence; nothing called `validated` before a byte-match with the recorder's export | frame it in SWGDE 18-Q-001 §5.3.2 and UK FSR-G-218 §7.4 terms (known datasets); DFPulse 2024: 30% of practitioners (52% in the UK) say lack of validation stops them using open-source tools |
| 4 | **Real media from three recorder families** (Dahua/CP Plus, Hikvision, HeimVision), failures published | no paper or rival shows more than two | two real bugs found on real hardware, each with a regression test |
| 5 | **Cameras split, never guessed**, where every frame says channel 0 | the real CP Plus drives contradict the 2026 DHAV paper's assumption that NVR channels are separable by the channel byte | cite Park & Lee 2014 and OpenDHFS for the principle; the field evidence is ours |

**Drop or narrow** (table stakes, or claimed by rivals too):
- Merkle maps, hash-chained ledgers and s.63 certificates: at least five
  rivals have them. Present them as "what a lab needs", not as novelty.
- "AI output is a lead, not evidence" and "works offline": common.
- "Tested on the NIST HeimVision image": two rivals use it too. Lead instead
  with our own E01 reader reproducing FTK's hashes, the whole image
  accounted for, and the zone finding.
- "Model identified from the platter": precedents exist (Yoon & Hwang;
  Gomm 2016, where a Ganz DVR turned out to be AvTech; Magnet Verify for
  files). Keep it as a supporting fact.
- Never "validated", "court-admissible", "certified" or "ISO-compliant". A
  tool is not certified; a lab is. Say "produces the records ISO/IEC 17025
  cl. 7.2.2 and 27041/27042 ask for".

## 3. The gaps the research named, and where they stand

| Gap | Status |
|---|---|
| G1: read the burned-in clock and camera name as a third, "recorder-claimed" time source | **Built** (OSD reader; weekday/AM-PM clocks in #34); accuracy on real frames still to be measured |
| G2: older footage left in in-use blocks ("stale tails"; Byun et al. 2026 measured +966% recoverable area on dashcams) | **Done** for Hikvision (#41) and Uniview (#43, `unv-stale-*`) |
| G3: encryption: detect and label it instead of carving nothing | **Done**: entropy labelling (#40); TP-Link's encrypted index reported as such (#43). No open tool or paper decrypts a DVR disk |
| G4: a scripted scenario list on the CP Plus unit (record, delete, format, overwrite, clock change, export after each) | open: needs the unit |
| G5: run the free rival tools on our images, publish the differences | open |
| G6: export in the NIST CCTV export profile (NISTIR 8161r1: MP4 + time codes + ClockOffset) | **Done** (`export-nist`); time stamps byte-identical to NIST's reference file (VALIDATION_REPORT §8i) |

## 4. Papers and standards to add to the references

**Must cite:**
- Park & Lee 2014, *Data fragment forensics for embedded DVR systems*,
  Digital Investigation 11(3):187-200 (18 citations; the most-cited DVR
  paper). Missing from ours; belongs under D4/D13.
- Giri, Yoon & Hwang, *CARVE*, DFRWS APAC 2026. Groups camera fragments by
  OCR and PRNU on a Honeywell testbed; qualifies D13's stated limit.
- SWGDE 17-V-002 v1.3 (2025): native export is the best evidence;
  re-inserting a drive can trigger a reformat (our drive 2 scenario).
- SWGDE 18-Q-001 v2.1 (2024): recovery tools must be tested on known
  datasets.

**Strong support:**
- UK FSR-G-218 Issue 2 (2024), method validation.
- Hargreaves et al. 2024, *DFPulse*, FSI:DI 51:301844 - the
  validation-barrier figures above.
- Stoykova et al. 2022, CLSR 46:105725 - reverse-engineered formats must be
  documented and testable; supports D14 (PR #43).
- Batista de Sousa & Brito 2022 - a Brazilian Federal Police author:
  commercial DVR tools "have errors in recovering videos" (WFS).
- Vanini et al. 2024 (time anchors); Byun et al. 2026 (file slack);
  Lehri & Roy 2022 (OCR timestamps); NISTIR 8161r1 (export profile).

The whole field is small: about 20 on-topic papers, 2008-2026
(`usp_papers_deep.md` §1). None covers Uniview, TP-Link, Godrej or Matrix.

## 5. Legal hooks (India)

| Source | What it gives the pitch | Checked |
|---|---|---|
| *Pune Bar Association v. Union of India*, SC, 22 May 2026, 2026 LiveLaw (SC) 551 | upholds BSA s.63(4); hash = "electronic fingerprint"; a Part B signer who is not a s.79A examiner needs "unimpeachable material" | full text read |
| *Randeep Singh @ Rana v. State of Haryana*, 2024 INSC 887 | bank CCTV on a CD held inadmissible: no hash, nothing tying it to the recorder, no certificate, nobody who had seen the footage. Each missing link is something the tool records | CCTV passages read |
| Puducherry G.O.Ms.No.27 (6 May 2025, under MHA S.O. 2506(E)) | the DVR/NVR itself is primary evidence; record the hash in the case diary; s.63(2) asks whether the device "was working properly" - the recorder's own log answers that | full text read |
| MeitY s.79A Examiner scheme v2.0 (Nov 2025) | "CCTV Forensics" is a notified scope; labs need ISO/IEC 17025 and must list every tool, "freeware or commercial" | full text read |
| Kerala Police SOP, ch. 4 (seizing CCTV) | make/model, clock check against a reference, native export as best evidence, seize the whole DVR - the steps `record-device`, the two-route clock and `validate-export` automate | chapter read |
| MHA O.M., April 2024 (CCTV procurement, STQC) | government sites move to STQC-tested, locally made recorders; formats and firmware will change and may encrypt, so honest detection and plugins matter | first pages read |

C-DAC's published forensic suite lists no DVR/NVR file-system tool
(checked 29 Sep).

## 6. Rivals

- **Other SIH26150 teams** (30+ repos checked): none holds real recorder
  data. Two use the same NIST HeimVision image (VinayBU14/CCTVault;
  Hardik-droid/sih_x "Trace"). Several claim eight vendors but validate on
  images their own generators build. Overclaims ("guaranteeing judicial
  admissibility", "ISO-compliant dossier") are easy for a judge to knock
  down.
- **Same philosophy, no real media:** OpenDHFS (Aug 2026) - "no evidence
  upgrading, no unsupported channel attribution".
- **Commercial:**
  - Magnet Witness: DVR Examiner is retiring at the end of 2026; "50+
    formats", no public per-format validation.
  - UFS Explorer Video Recovery: advertises decryption.
  - Also SalvationDATA VIP, DiskInternals, 512 BYTE / Dolphin.
  - Only Rzayeva 2025 measured any of them, on lab drives.
- **Free:** DVRExtractor, hikextractor, dhfs_extractor, A22Z4. No
  validation or coverage figures.

## 7. Data and firmware worth using

| Item | Use | Source note |
|---|---|---|
| VideoLAN `IMKH/00000001541000000.mp4` - a native Hikvision record file (5 MiB, IMKH + MPEG-PS, H.264) | a real vendor file to byte-check the Hikvision container parser against | `datasets_deep.md` |
| FFmpeg `camera-dvr/hikvision/` - Hikvision USB-backup exports | the same, for exports | `datasets.md` |
| archive.org mirror of the Marshall/NIST DVR E01 - licence **CC BY-ND 4.0**, and a **CSV file listing** in the zip | cite the licence; diff the HeimVision plugin's output against Marshall's own listing (2.95 GB download) | `datasets_deep.md` |
| ForeSpeed (Amped, arXiv:2512.19364): real exports from Lorex (Dahua-built), Swann, Anran DVRs | ask the authors for the link | `datasets_deep.md` |
| The Kazakh groups' real drive sets: 27 Hikvision/Dahua drives (*Information* 16(11):983, 2025) and 14 Dahua XVR drives (*Information* 17(5):493, 2026) | not public; the authors could be asked | `datasets.md` |
| CP Plus "STQC Phase-II" firmware (Dec 2025), incl. CP-UNR-108F1 - sibling of our unit | check with CP Plus whether STQC builds change the disk format or encrypt it (dealer links only - not downloaded) | `datasets_deep.md` |
| Uniview and TP-Link firmware | **used** for PR #43 | `vendor_formats.md` |
| Qualvision/Homaxi NVR firmware (Godrej's likely ODM) | QVFS: disk head magic "QVEX", frames `00 00 01 E0..EB` + length, times in Dahua's packed DHTIME | `vendor_formats.md` §3b |
| Matrix wiki how-tos | the SATATYA disk is a normal file tree: `Camera01/21_Apr_2018/14/14_47_19~14_59_59.stm1` + `.evnt` `.ifrm` `.tmid` | `vendor_formats.md` §4 |
| Honeywell legacy HRDP firmware (Wayback) | older Honeywell DVRs use "SSF", a Korean ODM's format - neither DHFS nor Yoon & Hwang's | `datasets_deep.md` |

Newer VIGI firmware (2025-26 builds) appears encrypted; the archive.org
builds used for #43 are not.

## 8. What to do next, in order

1. **Cite Park & Lee 2014 and CARVE** in RESEARCH_BASIS D4/D13. Reword D13's
   limit as this tool's, not the field's. (Small.)
2. **Put the legal hooks in FINAL_REPORT and the slides:** Randeep Singh,
   Pune Bar Association, Puducherry G.O. s.63(2), and the Kerala SOP.
   (Small.)
3. **Check the Hikvision container parser against the VideoLAN IMKH file**
   - a real vendor file, 5 MiB. (Small.)
4. **Godrej plugin from Qualvision firmware (QVFS), Matrix plugin from its
   file tree** - the #43 route. (Medium each.)
5. **Download the archive.org Marshall zip and diff its CSV listing against
   the HeimVision plugin.** (2.95 GB; JP's call.)
6. G5 (rival tools on our images). (Medium.) G6 is done.
