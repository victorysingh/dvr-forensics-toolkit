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
| File System & Format Parsing | `parsers/`, `plugins/` | HeimVision read off a real NIST image (`plugins/heimvision.py`, `spec_only`); Honeywell from published research (`plugins/honeywell.py`, `spec_only`); Dahua DHFS on real media (`spec_only`, two drives); Hikvision index records and MPEG-PS container on real media (`spec_only`), full-FS parser on the same observed layout (`spec_only`, not yet run on an intact Hikvision disk); drop-in plugins |
| Recovery | `parsers/dahua.py` remnants; `recover/carver.py`; `recover/pscarve.py`; `recover/annexb.py` (vendors with no parser) | Dahua remnants + indexless DHAV carver, and an MPEG-PS carver for Hikvision footage (recovered from under a reformatted drive, dated), both on real media (`spec_only`) and run inside the acquisition pass |
| Timeline Analysis | `analyse/timeline.py` | working: zone + measured clock error, gaps, cross-camera correlation |
| Reporting | `report/`, `viewer/` | working: HTML + JSON report, dependency-free viewer |
| Machine Learning | `analyse/activity.py` | motion activity from compressed frame sizes (lead, not evidence); face and object detection built as leads in the optional layer (ffmpeg + ONNX, `analytics/`), measured against 487 frames labelled by eye: the first version found a person in 0 of the 57 frames that had one; now (YOLOX-S + YuNet) 39 of 57, faces 12 of 27, vehicles 8 of 12, and 810 of 1,089 people on CAVIAR footage never used for choosing |

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
two: a CP Plus unit's drive, which carries Dahua-family DHFS 4.1 (so it covers
the Dahua format, with CP Plus attribution resting on the unit's label), and a
second drive believed to be Hikvision, not yet read. The defensible way to answer this is detection across
all eight plus a documented plugin SDK, with per-vendor status stated
explicitly — not an implied claim of full support for eight formats we cannot
test. See Rule 3 in `START_HERE.md`.

The PS also asks for AI analytics (face, object, motion). That is genuinely
requested, so it belongs in the architecture, but it is the last thing to
build and its output must be labelled **"lead, not evidence"** — a detection
that ranks footage for an investigator to review, never something presented as
a forensic conclusion.
