"""Auto-provision ADB (Android Debug Bridge) and aapt2.

Downloads Android SDK platform-tools on first use so that end users
don't need to install anything manually.  The binaries are cached in
a local `.android-tools/` directory next to this script.
"""

import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

# Google's official standalone platform-tools downloads
_PLATFORM_TOOLS_URLS = {
    ("Linux", "x86_64"): "https://dl.google.com/android/repository/platform-tools-latest-linux.zip",
    ("Linux", "aarch64"): "https://dl.google.com/android/repository/platform-tools-latest-linux.zip",
    ("Darwin", "x86_64"): "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip",
    ("Darwin", "arm64"): "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip",
    ("Windows", "AMD64"): "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
}

_TOOLS_DIR = Path(__file__).resolve().parent / ".android-tools"
_PT_DIR = _TOOLS_DIR / "platform-tools"


def _detect_url():
    """Return the download URL for the current OS/arch."""
    system = platform.system()
    machine = platform.machine()
    key = (system, machine)
    url = _PLATFORM_TOOLS_URLS.get(key)
    if url is None:
        # Try loose match
        for (s, m), u in _PLATFORM_TOOLS_URLS.items():
            if s == system:
                return u
    return url


def _make_executable(path):
    """Ensure a file is executable (Unix)."""
    if platform.system() != "Windows":
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def get_adb_path():
    """Return the path to the ADB binary, downloading if necessary.

    Resolution order:
    1. ADB already on system PATH  ->  use it
    2. ADB in local .android-tools/  ->  use it
    3. Download platform-tools       ->  cache & use
    """
    # 1. System PATH
    system_adb = shutil.which("adb")
    if system_adb:
        return system_adb

    # 2. Local cache
    ext = ".exe" if platform.system() == "Windows" else ""
    local_adb = _PT_DIR / f"adb{ext}"
    if local_adb.exists():
        return str(local_adb)

    # 3. Download
    return _download_platform_tools()


def get_aapt2_path():
    """Return the path to aapt2, or None if not available.

    aapt2 ships with build-tools, not platform-tools, so we check PATH only.
    If not found we return None and the caller should degrade gracefully.
    """
    for tool in ["aapt2", "aapt"]:
        p = shutil.which(tool)
        if p:
            return p
    # Check if it's next to our local adb (some bundles include it)
    ext = ".exe" if platform.system() == "Windows" else ""
    for name in [f"aapt2{ext}", f"aapt{ext}"]:
        local = _PT_DIR / name
        if local.exists():
            return str(local)
    return None


def _download_platform_tools(progress_callback=None):
    """Download and extract platform-tools. Returns path to adb binary."""
    url = _detect_url()
    if url is None:
        raise RuntimeError(
            f"No platform-tools download available for {platform.system()} {platform.machine()}. "
            "Please install ADB manually."
        )

    _TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = _TOOLS_DIR / "platform-tools.zip"

    if progress_callback:
        progress_callback("Downloading Android platform-tools...")

    try:
        _download_with_progress(url, zip_path, progress_callback)
    except Exception as e:
        raise RuntimeError(f"Failed to download platform-tools: {e}") from e

    if progress_callback:
        progress_callback("Extracting platform-tools...")

    # Extract
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(_TOOLS_DIR)

    # Clean up zip
    zip_path.unlink(missing_ok=True)

    ext = ".exe" if platform.system() == "Windows" else ""
    adb_path = _PT_DIR / f"adb{ext}"

    if not adb_path.exists():
        raise RuntimeError("Downloaded platform-tools but adb binary not found inside.")

    _make_executable(str(adb_path))

    # Also make fastboot executable if present
    fastboot = _PT_DIR / f"fastboot{ext}"
    if fastboot.exists():
        _make_executable(str(fastboot))

    if progress_callback:
        progress_callback("ADB ready!")

    return str(adb_path)


def _download_with_progress(url, dest, progress_callback=None):
    """Download a file with optional progress reporting."""

    def _reporthook(block_num, block_size, total_size):
        if progress_callback and total_size > 0:
            downloaded = block_num * block_size
            pct = min(100, int(downloaded * 100 / total_size))
            progress_callback(f"Downloading... {pct}% ({downloaded // (1024*1024)}MB / {total_size // (1024*1024)}MB)")

    urllib.request.urlretrieve(url, str(dest), reporthook=_reporthook)


def ensure_adb(progress_callback=None):
    """Ensure ADB is available, downloading if needed. Returns adb path.

    Args:
        progress_callback: Optional callable(message: str) for status updates.
    """
    system_adb = shutil.which("adb")
    if system_adb:
        return system_adb

    ext = ".exe" if platform.system() == "Windows" else ""
    local_adb = _PT_DIR / f"adb{ext}"
    if local_adb.exists():
        return str(local_adb)

    return _download_platform_tools(progress_callback)


def run_adb(args, serial=None, timeout=30):
    """Run an ADB command using the provisioned adb binary.

    Returns (returncode, stdout, stderr).
    """
    adb_path = get_adb_path()
    cmd = [adb_path]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "ADB command timed out"
    except FileNotFoundError:
        return -1, "", f"ADB binary not found at {adb_path}"


def check_device(serial=None):
    """Verify a device is connected. Returns (device_line, serial) or raises."""
    rc, out, err = run_adb(["devices", "-l"])
    if rc != 0:
        raise RuntimeError(f"adb devices failed: {err}")
    lines = [l for l in out.strip().splitlines()[1:] if l.strip()]
    if not lines:
        raise RuntimeError("No Android device/emulator connected.")
    if serial:
        matching = [l for l in lines if l.startswith(serial)]
        if not matching:
            raise RuntimeError(f"Device '{serial}' not found. Available:\n" + "\n".join(lines))
        return matching[0], serial
    return lines[0], lines[0].split()[0]


def get_device_model(serial=None):
    """Get a human-readable device model string."""
    rc, out, _ = run_adb(["shell", "getprop", "ro.product.model"], serial=serial)
    model = out.strip() if rc == 0 else "Unknown"
    rc, out, _ = run_adb(["shell", "getprop", "ro.build.version.sdk"], serial=serial)
    sdk = out.strip() if rc == 0 else "?"
    return f"{model} (API {sdk})"
