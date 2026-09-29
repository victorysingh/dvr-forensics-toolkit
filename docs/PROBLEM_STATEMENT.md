# Problem Statement 26150 (official portal text)

> This is the official text from the SIH portal. Earlier team planning used
> third-party PS listings; where anything contradicts this file, **this file
> wins**.

| Field | Value |
|---|---|
| Problem Statement ID | **26150** |
| Organization | National Technical Research Organisation (NTRO) |
| Department | National Technical Research Organisation (NTRO) |
| Category | Software |
| Theme | Blockchain & Cybersecurity |

**Title:** Development of a Multi-Vendor DVR/NVR Forensic Analysis Tool for
Standardized Acquisition, Recovery, and Analysis of Surveillance Evidence.

---

## Background

Digital/Network Video Recorders (DVR/NVRs) are widely used for surveillance in
government agencies, law enforcement, critical infrastructure, businesses, and
residential environments. Major DVR/NVR manufacturers such as Dahua Technology,
CP Plus, Honeywell Security, TP-Link, Godrej, Uniview, HIKVISON, and Matrix use
proprietary storage formats, file systems, metadata structures, and video
encoding mechanisms. During forensic investigations, surveillance footage
serves as crucial digital evidence; however, the lack of standardization across
DVR/NVR vendors makes acquisition, recovery, analysis, and validation
difficult. Investigators often rely on multiple vendor-specific tools,
resulting in increased investigation time, inconsistent results, timestamp
synchronization issues, challenges in deleted footage recovery, and
difficulties in maintaining evidence integrity. Therefore, a unified
vendor-agnostic DVR/NVR forensic analysis platform is required to provide
standardized workflows for evidence acquisition, recovery, analysis,
validation, and reporting.

## Description

The proposed solution aims to overcome challenges such as non-standard forensic
acquisition methods, proprietary file systems and video formats, difficulty in
recovering deleted or damaged recordings, inconsistent timestamps, limited
event correlation across cameras, challenges in maintaining chain of custody,
dependence on multiple tools, lack of standardized reporting, and limited use
of intelligent video analytics. The tool should support major DVR/NVR OEMs
including Dahua Technology, CP Plus, Honeywell Security, HIKVISON, TP-Link,
Godrej, Uniview, Matrix, and other commonly used platforms. It should
automatically identify DVR models, parse proprietary file systems, create
forensic images, extract videos and metadata, decode proprietary formats,
recover deleted footage, normalize timestamps, generate cryptographic hashes
(MD5 and SHA-256), correlate events across cameras, maintain chain-of-custody
records, generate reports, and perform AI-based analytics such as face, object,
and motion detection. Key modules include Device Identification, Acquisition,
File System & Format Parsing, Recovery, Timeline Analysis, Reporting, and
Machine Learning.

## Expected Solution

The expected outcome is a software-based forensic platform capable of
performing standardized acquisition, recovery, analysis, validation, and
reporting of surveillance evidence across multiple DVR/NVR vendors. The
solution should support at least five to six major DVR/NVR OEMs (Dahua
Technology, CP Plus, Honeywell Security, TP-Link, Godrej, Uniview, HIKVISON and
Matrix), provide a unified forensic workflow, reduce dependency on
vendor-specific tools, automate evidence acquisition and analysis, improve
deleted video recovery, ensure evidence integrity and admissibility, and
generate comprehensive forensic reports. Deliverables include a comparative
analysis of major DVR/NVR OEMs (Dahua Technology, CP Plus, Honeywell Security,
TP-Link, Godrej, Uniview, and Matrix), DVR/NVR forensic Image, system
architecture documentation, a functional prototype, Standard Operating
Procedures (SOPs), validation reports, user manuals, and a final project
report. The tool should successfully parse proprietary file systems, decode
video formats, recover deleted recordings, verify evidence integrity through
cryptographic hashing, generate standardized reports, reduce analysis time, and
produce reliable and legally defensible forensic results.

---

## Required modules, mapped to this repo

| PS module | Where it lives | State |
|---|---|---|
| Device Identification | `detect/signatures.py`, `detect/engine.py`, `detect/model.py` | working: vendor by confidence score; model from platter strings and the examiner's reading of the unit, cross-checked |
| Acquisition | `acquire/device.py`, `acquire/scanner.py` | working |
| File System & Format Parsing | `parsers/`, `plugins/` | all eight named OEMs have a plugin, each with its status: Dahua DHFS and CP Plus (the same format on our unit) and Hikvision (index records, MPEG-PS, full filesystem on the observed layout) read off our two real drives; HeimVision off a real NIST image; Honeywell from published research; Uniview, TP-Link's index and Godrej (Qualvision) from the vendors' own firmware; Matrix from its own documents. Only the first three are observed on real media; none is `validated` (that needs a byte-match with the recorder's own export) |
| Recovery | `parsers/dahua.py` remnants; `recover/carver.py`; `recover/pscarve.py`; `recover/annexb.py` (vendors with no parser) | Dahua remnants + indexless DHAV carver, and an MPEG-PS carver for Hikvision footage (recovered from under a reformatted drive, dated), both on real media (`spec_only`) and run inside the acquisition pass |
| Timeline Analysis | `analyse/timeline.py` | working: zone + measured clock error, gaps, cross-camera correlation |
| Reporting | `report/`, `viewer/` | working: HTML + JSON report, dependency-free viewer |
| Machine Learning | `analyse/activity.py` | motion activity from compressed frame sizes (lead, not evidence); face and object detection built as leads in the optional layer (ffmpeg + ONNX, `analytics/`), measured against 487 frames labelled by eye: the first version found a person in 0 of the 57 frames that had one; now (YOLOX-S + YuNet, fisheye pictures also turned round) 44 of 57, faces 22 of 27, moving vehicles 7 of 12 plus parked cars as their own lead, and 810 of 1,089 people on CAVIAR footage never used for choosing. **Face search** by a reference photo (SFace, 30 Sep): candidates for the examiner, never identifications; on LFW faces made recorder-sized the same person passes in 97.8% of pairs with eyes 12 px or more apart and no pair of different people passes; on strangers in 12 real surveillance clips, 1 false candidate, an upside-down head at a fisheye's edge (§8n) |

## Named deliverables

The PS asks for these explicitly. All exist now; `FINAL_REPORT.md` §12 maps
each to its file:

- comparative analysis of the major OEMs — `OEM_COMPARISON.md`
- a DVR/NVR forensic image — `FORENSIC_IMAGE.md`
- system architecture documentation — `ARCHITECTURE.md`
- Standard Operating Procedures — `SOP_EXAMINATION.md`, `LINUX_ACQUISITION.md`
- validation reports — `VALIDATION_REPORT.md`, `PERFORMANCE.md`
- user manuals — `USER_MANUAL.md`
- final project report — `FINAL_REPORT.md`

## Reading the PS honestly

The PS names eight OEMs and asks for "at least five to six". We hold media for
two recorders: a CP Plus unit's drive, which carries Dahua-family DHFS 4.1 (so
it covers the Dahua format, with CP Plus attribution resting on the unit's
label), and a Hikvision unit's drive, reformatted by a Dahua-family recorder,
from which ~6,300 hours of Hikvision footage were recovered. NIST's public
HeimVision image makes a third family. Every one of the eight has a plugin, and
each states how it was built and how strongly it is evidenced: three from real
drives, the rest from a paper, the vendors' own firmware or documents. That is
the defensible answer - not an implied claim of full support for formats we
could not test. See Rule 3 in `START_HERE.md`.

The PS also asks for AI analytics (face, object, motion). That is genuinely
requested, so it belongs in the architecture, but it is the last thing to
build and its output must be labelled **"lead, not evidence"** — a detection
that ranks footage for an investigator to review, never something presented as
a forensic conclusion.
