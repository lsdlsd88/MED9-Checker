"""Build and check the Windows x64 one-file release."""

import importlib.util
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
SOURCES = (
    "med9_checker.py",
    "med9_flash.py",
    "med9_eeprom.py",
    "med9_hash_gen.py",
    "med9_native.c",
)


def find_vcvars():
    vswhere = (Path(os.environ["ProgramFiles(x86)"])
               / "Microsoft Visual Studio" / "Installer" / "vswhere.exe")
    if vswhere.is_file():
        installation = subprocess.check_output([
            str(vswhere), "-latest", "-products", "*", "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property", "installationPath",
        ], text=True).strip()
        if installation:
            vcvars = Path(installation) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
            if vcvars.is_file():
                return vcvars
    raise SystemExit("Install the MSVC x64 C++ build tools before building the release.")


def main():
    if sys.platform != "win32" or platform.machine().upper() not in {"AMD64", "X86_64"}:
        raise SystemExit("Run this builder with x64 Python on Windows.")
    if sys.maxsize <= 2**32:
        raise SystemExit("Run this builder with x64 Python.")
    if importlib.util.find_spec("PyInstaller") is None:
        raise SystemExit("Install PyInstaller in this Python environment first.")
    from PyInstaller.archive.readers import CArchiveReader

    vcvars = find_vcvars()
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="med9-build-", dir=dist) as temporary:
        stage = Path(temporary)
        for name in SOURCES:
            shutil.copyfile(ROOT / "scripts" / name, stage / name)

        (stage / "compile-native.cmd").write_text(
            '@echo off\n'
            'call "%MED9_RELEASE_VCVARS%" >nul\n'
            'if errorlevel 1 exit /b 1\n'
            'set "CL="\nset "_CL_="\nset "LINK="\nset "_LINK_="\n'
            'cl /nologo /O2 /LD /MT /W3 med9_native.c /Fe:med9_native.dll '
            '/link /INCREMENTAL:NO /DEBUG:NONE\n'
            'exit /b %errorlevel%\n', encoding="ascii",
        )
        env = dict(os.environ, MED9_RELEASE_VCVARS=str(vcvars))
        subprocess.run(["cmd.exe", "/d", "/c", "compile-native.cmd"],
                       cwd=stage, env=env, check=True)
        subprocess.run([sys.executable, "-c", (
            "import med9_hash_gen as engine\n"
            "from pathlib import Path\n"
            "dll = engine._load_dll()\n"
            "assert dll is not None and Path(dll._name).resolve() == Path('med9_native.dll').resolve()\n"
            "sample = bytes(range(256)) * 16\n"
            "assert engine._native_digest(sample) == engine._py_hash(sample)\n"
        )], cwd=stage, check=True)

        command = [
            sys.executable, "-m", "PyInstaller", "--onefile", "--noconsole",
            "--noupx", "--optimize", "2", "--log-level", "WARN",
            "--name", "MED9Checker", "--add-binary", "med9_native.dll:.",
        ]
        if importlib.util.find_spec("tkinterdnd2") is not None:
            command.extend(["--collect-all", "tkinterdnd2"])
        subprocess.run([*command, "med9_checker.py"], cwd=stage, check=True)

        executable = stage / "dist" / "MED9Checker.exe"
        archive = CArchiveReader(str(executable))
        if archive.extract("med9_native.dll") != (stage / "med9_native.dll").read_bytes():
            raise SystemExit("Bundled DLL differs from the checked native build.")
        smoke = stage / "smoke"
        smoke.mkdir()
        (smoke / "a.bin").write_bytes(b"MED9 build smoke test")
        shutil.copyfile(smoke / "a.bin", smoke / "b.bin")
        # A windowed Python process has no console stdout. Check its exit status.
        subprocess.run([str(executable), "--diff", "a.bin", "b.bin"],
                       cwd=smoke, check=True, timeout=60)

        executable.replace(dist / executable.name)
    print("Built dist/MED9Checker.exe with the verified x64 DLL.")


if __name__ == "__main__":
    main()
