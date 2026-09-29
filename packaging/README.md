# Packaging: the tool as one executable

A forensic workstation is often offline and cannot `pip install` or even have
Python. `ps26150.spec` builds the whole tool into a single file,
`ps26150-dvr.exe` on Windows (a Linux binary when built on Linux). It contains:
- the stdlib core;
- every shipped plugin;
- the web viewer.

It runs with no Python on the machine.

## Build

```bash
python -m venv buildvenv
buildvenv/Scripts/python -m pip install pyinstaller          # Linux: buildvenv/bin/python
buildvenv/Scripts/python -m PyInstaller packaging/ps26150.spec --noconfirm
# -> dist/ps26150-dvr.exe   (about 11 MB)
```

Run the build from the repo root, on the platform you want to ship to:
PyInstaller does not cross-compile. The build uses no UPX packer, because
antivirus heuristics flag packed executables.

## Use

The executable takes the same commands as `python cli.py`:

```bash
ps26150-dvr.exe scan --device \\.\PhysicalDrive2 --out out\case1
ps26150-dvr.exe parse --device "HeimVision K9604-W.E01" --vendor HeimVision
ps26150-dvr.exe serve --out out            # viewer on http://127.0.0.1:8150
```

## Adding a vendor without a rebuild

Put a `plugins\` folder next to the executable and drop the plugin file in
(copy `plugins/_template.py`). The rules:
- It loads alongside the shipped plugins.
- Its signatures join detection.
- The viewer's "Drop-in folder" shows this folder.
- A dropped-in file with the same name as a shipped plugin is **not** loaded.
  It is listed under plugin errors, so evidence is never parsed by a file
  that silently replaced a shipped parser.

## What is left out

- **The analytics layer** (numpy, onnxruntime, the ONNX models) is hundreds of
  MB and optional. `analyse-video` says so and exits; the forensic core
  does not need it.
- `read-osd` and `decode-check` need Tesseract, ffmpeg or ffprobe on the PATH,
  as they do from source.
- The validation harnesses are not CLI commands: `validate.realmedia`,
  `validate.ksy_check`, `validate.heimvision_carve` and
  `validate.analytics_eval`. Run them from a source checkout with
  `python -m validate.<name>`.

## Checked on 29 Sep 2026 (Windows 11, PyInstaller 6.22.3, Python 3.13)

| Check | Result |
|---|---|
| `parse` on the NIST HeimVision E01 (139.74 GB) | same output as `python cli.py`, byte for byte; 9 s vs 8 s |
| `scan`, `report`, `verify`, `serve` on a synthetic image | work; `verify` gives a Merkle MATCH; the viewer serves `/` and `app.js` |
| A plugin dropped into `plugins\` next to the exe | loaded; its vendor is listed as a parser |
| A dropped-in `heimvision.py` (same name as a shipped plugin) | refused and reported; the shipped one is used |
| `analyse-video` with no analytics layer | clear message, no crash |

The same loader rules are covered by the test suite
(`tests/test_pipeline.py`, "drop-in plugins"), which runs from source.
