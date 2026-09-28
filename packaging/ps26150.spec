# PyInstaller spec: the forensic tool as one executable - the stdlib core,
# every shipped plugin and the web viewer.  Build and use: packaging/README.md.
#
#   pip install pyinstaller
#   pyinstaller packaging/ps26150.spec        # -> dist/ps26150-dvr(.exe)
#
# Built on Windows it makes a Windows .exe; on Linux, a Linux binary.  The
# optional analytics layer (numpy, onnxruntime, the ONNX models) is left out:
# it is hundreds of MB and the tool runs without it (analytics/README.md).
import os
import sys

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))  # noqa: F821 (set by PyInstaller)
sys.path.insert(0, ROOT)

# Every module of the tool: plugins are loaded from files at run time, so the
# modules they import (parsers.ext3, ...) are invisible to the import scan.
PACKAGES = ["core", "acquire", "detect", "parsers", "recover", "analyse", "report",
            "viewer", "validate"]
hidden = [m for p in PACKAGES for m in collect_submodules(p)]
# standard-library modules only a plugin imports
hidden += ["sqlite3", "statistics", "tempfile"]

datas = [(os.path.join(ROOT, "plugins", f), "plugins")
         for f in sorted(os.listdir(os.path.join(ROOT, "plugins")))
         if f.endswith(".py") and not f.startswith("_")]
datas += [(os.path.join(ROOT, "viewer", "static"), os.path.join("viewer", "static"))]

a = Analysis(  # noqa: F821
    [os.path.join(ROOT, "cli.py")],
    pathex=[ROOT],
    datas=datas,
    hiddenimports=hidden,
    excludes=["numpy", "onnxruntime", "kaitaistruct", "analytics.detect", "tkinter",
              "matplotlib", "PIL", "IPython"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz, a.scripts, a.binaries, a.datas, [],
    name="ps26150-dvr",
    console=True,
    upx=False,                 # no packer: antivirus heuristics dislike UPX
)
