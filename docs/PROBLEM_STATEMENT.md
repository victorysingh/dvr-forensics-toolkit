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
| Device Identification | `detect/signatures.py`, `detect/engine.py` | working |
| Acquisition | `acquire/device.py`, `acquire/scanner.py` | working |
| File System & Format Parsing | `parsers/` | Dahua DHFS on real media (`spec_only`); Hikvision `synthetic_only` |
| Recovery | `parsers/dahua.py` remnants; `recover/` | Dahua remnants working; indexless carver not started |
| Timeline Analysis | — | not started |
| Reporting | — | not started |
| Machine Learning | — | not started (stretch) |

## Named deliverables not yet started

The PS asks for these explicitly, and they are marked work, not optional
polish:

- comparative analysis of the major OEMs
- a DVR/NVR forensic image
- system architecture documentation
- Standard Operating Procedures (`docs/LINUX_ACQUISITION.md` is the beginning
  of the acquisition SOP)
- validation reports
- user manuals
- final project report

## Reading the PS honestly

The PS names eight OEMs and asks for "at least five to six". We hold media for
exactly one (Hikvision). The defensible way to answer this is detection across
all eight plus a documented plugin SDK, with per-vendor status stated
explicitly — not an implied claim of full support for eight formats we cannot
test. See Rule 3 in `START_HERE.md`.

The PS also asks for AI analytics (face, object, motion). That is genuinely
requested, so it belongs in the architecture, but it is the last thing to
build and its output must be labelled **"lead, not evidence"** — a detection
that ranks footage for an investigator to review, never something presented as
a forensic conclusion.
