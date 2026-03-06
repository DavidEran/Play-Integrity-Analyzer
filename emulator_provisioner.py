"""Auto-provision an Android emulator for sideload testing.

Downloads the Android SDK command-line tools, emulator, system image,
creates an AVD, and boots it headlessly — all automatically.  No manual
setup required.

The SDK is cached in `.android-sdk/` next to this script.
"""

import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_SDK_DIR = Path(__file__).resolve().parent / ".android-sdk"
_AVD_DIR = _SDK_DIR / "avd"
_AVD_NAME = "sideload_test_device"

# Android API level and system image to use
_API_LEVEL = "34"
_SYS_IMAGE_TAG = "google_apis"

# Detect host arch for the right system image ABI
_HOST_MACHINE = platform.machine().lower()
if _HOST_MACHINE in ("x86_64", "amd64"):
    _SYS_IMAGE_ABI = "x86_64"
elif _HOST_MACHINE in ("arm64", "aarch64"):
    _SYS_IMAGE_ABI = "arm64-v8a"
else:
    _SYS_IMAGE_ABI = "x86_64"

_SYS_IMAGE_PACKAGE = f"system-images;android-{_API_LEVEL};{_SYS_IMAGE_TAG};{_SYS_IMAGE_ABI}"

# SDK command-line tools download URLs
_HOST_OS = platform.system().lower()
if _HOST_OS == "darwin":
    _CMDLINE_TOOLS_OS = "mac"
elif _HOST_OS == "windows":
    _CMDLINE_TOOLS_OS = "win"
else:
    _CMDLINE_TOOLS_OS = "linux"

_CMDLINE_TOOLS_URL = (
    f"https://dl.google.com/android/repository/commandlinetools-{_CMDLINE_TOOLS_OS}-11076708_latest.zip"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_executable(path):
    """Make a file executable on Unix."""
    if platform.system() != "Windows":
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _find_binary(name):
    """Find a binary in the SDK directory tree."""
    ext = ".exe" if platform.system() == "Windows" else ""
    target = f"{name}{ext}"

    # Check common locations
    candidates = [
        _SDK_DIR / "cmdline-tools" / "latest" / "bin" / target,
        _SDK_DIR / "cmdline-tools" / "bin" / target,
        _SDK_DIR / "emulator" / target,
        _SDK_DIR / "platform-tools" / target,
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    # Recursive search as fallback
    for p in _SDK_DIR.rglob(target):
        if p.is_file():
            return str(p)
    return None


def _detect_proxy():
    """Detect proxy settings from environment (JAVA_TOOL_OPTIONS or env vars).

    Returns (proxy_type, host, port) or (None, None, None).
    """
    # Check JAVA_TOOL_OPTIONS first (set by many CI/container environments)
    java_opts = os.environ.get("JAVA_TOOL_OPTIONS", "")
    for prefix in ("-Dhttps.proxyHost=", "-Dhttp.proxyHost="):
        if prefix in java_opts:
            host = java_opts.split(prefix)[1].split(" ")[0].split("-D")[0].strip()
            port_prefix = prefix.replace("proxyHost", "proxyPort")
            port = "8080"
            if port_prefix in java_opts:
                port = java_opts.split(port_prefix)[1].split(" ")[0].split("-D")[0].strip()
            scheme = "https" if "https" in prefix else "http"
            return scheme, host, port
    # Check standard env vars
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        val = os.environ.get(var, "")
        if val:
            val = re.sub(r"^https?://", "", val)
            parts = val.split(":")
            host = parts[0]
            port = parts[1].rstrip("/") if len(parts) > 1 else "8080"
            scheme = "https" if "https" in var.lower() else "http"
            return scheme, host, port
    return None, None, None


def _sdkmanager_proxy_args():
    """Return sdkmanager CLI args for proxy, if a proxy is detected."""
    scheme, host, port = _detect_proxy()
    if host:
        return [f"--proxy={scheme}", f"--proxy_host={host}", f"--proxy_port={port}"]
    return []


def _run(cmd, env=None, timeout=600):
    """Run a command and return (returncode, stdout, stderr)."""
    merged_env = os.environ.copy()
    merged_env["ANDROID_SDK_ROOT"] = str(_SDK_DIR)
    merged_env["ANDROID_AVD_HOME"] = str(_AVD_DIR)
    # Suppress telemetry/analytics prompts
    merged_env["ANDROID_PREFS_ROOT"] = str(_SDK_DIR / ".android")
    if env:
        merged_env.update(env)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=merged_env
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Binary not found: {cmd[0]}"


def _download_file(url, dest, progress_callback=None):
    """Download a file with optional progress reporting. Respects proxy env vars."""
    # urllib automatically uses HTTP_PROXY / HTTPS_PROXY env vars via ProxyHandler
    def _hook(block_num, block_size, total_size):
        if progress_callback and total_size > 0:
            downloaded = block_num * block_size
            pct = min(100, int(downloaded * 100 / total_size))
            mb_down = downloaded // (1024 * 1024)
            mb_total = total_size // (1024 * 1024)
            progress_callback(f"Downloading... {pct}% ({mb_down}MB / {mb_total}MB)")

    try:
        urllib.request.urlretrieve(url, str(dest), reporthook=_hook)
    except Exception as e:
        raise RuntimeError(
            f"Failed to download {url}: {e}\n"
            f"Make sure dl.google.com is accessible from this server."
        ) from e


# ---------------------------------------------------------------------------
# SDK provisioning
# ---------------------------------------------------------------------------


def _install_cmdline_tools(progress_callback=None):
    """Download and install Android SDK command-line tools."""
    _SDK_DIR.mkdir(parents=True, exist_ok=True)

    zip_path = _SDK_DIR / "cmdline-tools.zip"
    if progress_callback:
        progress_callback("Downloading Android SDK command-line tools...")

    _download_file(_CMDLINE_TOOLS_URL, zip_path, progress_callback)

    if progress_callback:
        progress_callback("Extracting command-line tools...")

    # Extract to temp then move to correct layout
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(_SDK_DIR)

    # Google packages it as `cmdline-tools/` — we need `cmdline-tools/latest/`
    extracted = _SDK_DIR / "cmdline-tools"
    latest_dir = extracted / "latest"
    if not latest_dir.exists():
        # Move contents into a 'latest' subdirectory
        tmp_move = _SDK_DIR / "_cmdline_tmp"
        if tmp_move.exists():
            shutil.rmtree(tmp_move)
        extracted.rename(tmp_move)
        extracted.mkdir(parents=True)
        tmp_move.rename(latest_dir)

    zip_path.unlink(missing_ok=True)

    # Make binaries executable
    bin_dir = latest_dir / "bin"
    if bin_dir.exists():
        for f in bin_dir.iterdir():
            if f.is_file():
                _make_executable(str(f))


def _accept_licenses():
    """Accept all SDK licenses non-interactively."""
    sdkmanager = _find_binary("sdkmanager")
    if not sdkmanager:
        return
    # Pipe 'y' to accept all
    env = os.environ.copy()
    env["ANDROID_SDK_ROOT"] = str(_SDK_DIR)
    env["ANDROID_AVD_HOME"] = str(_AVD_DIR)
    env["ANDROID_PREFS_ROOT"] = str(_SDK_DIR / ".android")
    proxy_args = _sdkmanager_proxy_args()
    try:
        proc = subprocess.Popen(
            [sdkmanager, "--licenses", f"--sdk_root={_SDK_DIR}"] + proxy_args,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env,
        )
        # Send enough 'y' answers
        proc.communicate(input="y\n" * 20, timeout=120)
    except Exception:
        pass


def _check_connectivity(progress_callback=None):
    """Quick check that dl.google.com is reachable before attempting large downloads."""
    import urllib.error
    test_url = "https://dl.google.com/android/repository/repository2-3.xml"
    try:
        req = urllib.request.Request(test_url, method="HEAD")
        urllib.request.urlopen(req, timeout=15)
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(
            f"Cannot reach dl.google.com (Android SDK download server).\n"
            f"Error: {e}\n\n"
            f"This server's network must allow outbound HTTPS to dl.google.com.\n"
            f"If you're behind a corporate proxy or firewall, add dl.google.com to the allowlist."
        ) from e
    if progress_callback:
        progress_callback("Connectivity check passed (dl.google.com reachable)")


def _install_sdk_packages(progress_callback=None):
    """Install emulator, platform-tools, and system image via sdkmanager."""
    sdkmanager = _find_binary("sdkmanager")
    if not sdkmanager:
        raise RuntimeError("sdkmanager not found after installing command-line tools")

    _accept_licenses()

    packages = [
        "platform-tools",
        "emulator",
        f"platforms;android-{_API_LEVEL}",
        _SYS_IMAGE_PACKAGE,
    ]

    proxy_args = _sdkmanager_proxy_args()
    if proxy_args and progress_callback:
        progress_callback(f"Detected proxy: {proxy_args[1]}")

    for pkg in packages:
        if progress_callback:
            progress_callback(f"Installing {pkg}...")
        rc, out, err = _run(
            [sdkmanager, f"--sdk_root={_SDK_DIR}", "--install", pkg] + proxy_args,
            timeout=600,
        )
        if rc != 0:
            # Retry once with fresh license acceptance
            _accept_licenses()
            rc, out, err = _run(
                [sdkmanager, f"--sdk_root={_SDK_DIR}", "--install", pkg] + proxy_args,
                timeout=600,
            )
            if rc != 0:
                # sdkmanager often prints errors to stdout, not stderr
                output = (err.strip() or out.strip() or "(no output)")[:800]
                raise RuntimeError(
                    f"Failed to install {pkg}.\n\n"
                    f"sdkmanager output:\n{output}\n\n"
                    f"This usually means the network blocked the download. "
                    f"Make sure dl.google.com is accessible from this server."
                )


def _create_avd(progress_callback=None):
    """Create an AVD if it doesn't already exist."""
    _AVD_DIR.mkdir(parents=True, exist_ok=True)
    avdmanager = _find_binary("avdmanager")
    if not avdmanager:
        raise RuntimeError("avdmanager not found")

    # Check if AVD already exists
    rc, out, err = _run([avdmanager, "list", "avd"])
    if _AVD_NAME in out:
        if progress_callback:
            progress_callback(f"AVD '{_AVD_NAME}' already exists.")
        return

    if progress_callback:
        progress_callback(f"Creating virtual device '{_AVD_NAME}'...")

    env = os.environ.copy()
    env["ANDROID_SDK_ROOT"] = str(_SDK_DIR)
    env["ANDROID_AVD_HOME"] = str(_AVD_DIR)
    env["ANDROID_PREFS_ROOT"] = str(_SDK_DIR / ".android")
    try:
        proc = subprocess.Popen(
            [
                avdmanager, "create", "avd",
                "--name", _AVD_NAME,
                "--package", _SYS_IMAGE_PACKAGE,
                "--device", "pixel_6",
                "--force",
            ],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env,
        )
        # Answer 'no' to custom hardware profile
        proc.communicate(input="no\n", timeout=120)
    except Exception as e:
        raise RuntimeError(f"Failed to create AVD: {e}") from e


# ---------------------------------------------------------------------------
# Emulator lifecycle
# ---------------------------------------------------------------------------


def _get_adb_path():
    """Return path to ADB in the SDK."""
    # Check SDK first
    p = _find_binary("adb")
    if p:
        return p
    # Check system PATH
    sys_adb = shutil.which("adb")
    if sys_adb:
        return sys_adb
    return None


def _get_running_emulators():
    """Return list of running emulator serial numbers."""
    adb = _get_adb_path()
    if not adb:
        return []
    try:
        proc = subprocess.run(
            [adb, "devices"], capture_output=True, text=True, timeout=10
        )
        serials = []
        for line in proc.stdout.strip().splitlines()[1:]:
            if line.strip() and "emulator" in line.split()[0]:
                serials.append(line.split()[0])
        return serials
    except Exception:
        return []


def boot_emulator(progress_callback=None):
    """Boot the emulator headlessly. Returns the emulator serial (e.g. 'emulator-5554').

    If the emulator is already running, returns its serial immediately.
    """
    # Check if already running
    running = _get_running_emulators()
    if running:
        if progress_callback:
            progress_callback(f"Emulator already running: {running[0]}")
        return running[0]

    emulator_bin = _find_binary("emulator")
    if not emulator_bin:
        raise RuntimeError("Emulator binary not found. Run provision_emulator() first.")

    if progress_callback:
        progress_callback("Starting Android emulator (headless)...")

    env = os.environ.copy()
    env["ANDROID_SDK_ROOT"] = str(_SDK_DIR)
    env["ANDROID_AVD_HOME"] = str(_AVD_DIR)
    env["ANDROID_PREFS_ROOT"] = str(_SDK_DIR / ".android")

    # Start emulator as a background process
    proc = subprocess.Popen(
        [
            emulator_bin,
            "-avd", _AVD_NAME,
            "-no-window",
            "-no-audio",
            "-no-boot-anim",
            "-gpu", "swiftshader_indirect",
            "-no-snapshot-save",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )

    # Wait for the emulator to appear in adb devices
    adb = _get_adb_path()
    if not adb:
        raise RuntimeError("ADB not found")

    if progress_callback:
        progress_callback("Waiting for emulator to boot...")

    deadline = time.monotonic() + 180  # 3 minute timeout
    serial = None

    while time.monotonic() < deadline:
        time.sleep(3)
        running = _get_running_emulators()
        if running:
            serial = running[0]
            break

    if not serial:
        proc.kill()
        raise RuntimeError("Emulator failed to start within 3 minutes.")

    # Wait for boot to complete (sys.boot_completed = 1)
    if progress_callback:
        progress_callback("Emulator started, waiting for Android to finish booting...")

    boot_deadline = time.monotonic() + 180
    while time.monotonic() < boot_deadline:
        try:
            result = subprocess.run(
                [adb, "-s", serial, "shell", "getprop", "sys.boot_completed"],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip() == "1":
                break
        except Exception:
            pass
        time.sleep(3)
    else:
        if progress_callback:
            progress_callback("Warning: Boot completion check timed out, proceeding anyway...")

    if progress_callback:
        progress_callback(f"Emulator ready: {serial}")

    return serial


def shutdown_emulator(serial=None):
    """Shut down the emulator."""
    adb = _get_adb_path()
    if not adb:
        return
    if serial:
        subprocess.run(
            [adb, "-s", serial, "emu", "kill"],
            capture_output=True, timeout=30,
        )
    else:
        for s in _get_running_emulators():
            subprocess.run(
                [adb, "-s", s, "emu", "kill"],
                capture_output=True, timeout=30,
            )


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------


def is_provisioned():
    """Check if the SDK, emulator, and AVD are already set up."""
    return (
        _find_binary("sdkmanager") is not None
        and _find_binary("emulator") is not None
        and _find_binary("adb") is not None
        # Check AVD exists
        and (_AVD_DIR / f"{_AVD_NAME}.avd").exists()
    )


def provision_emulator(progress_callback=None):
    """Full provisioning: download SDK tools, install packages, create AVD.

    This is idempotent — skips steps that are already done.
    Takes ~2 GB of disk space on first run.

    Args:
        progress_callback: Optional callable(message: str) for status updates.
    """
    if is_provisioned():
        if progress_callback:
            progress_callback("Android SDK and emulator already provisioned.")
        return

    # Step 0: Verify network connectivity before downloading anything
    _check_connectivity(progress_callback)

    # Step 1: Command-line tools
    if not _find_binary("sdkmanager"):
        _install_cmdline_tools(progress_callback)

    # Step 2: SDK packages (emulator, platform-tools, system image)
    if not _find_binary("emulator"):
        _install_sdk_packages(progress_callback)

    # Step 3: AVD
    _create_avd(progress_callback)

    if progress_callback:
        progress_callback("Provisioning complete!")


def get_emulator_status():
    """Return a status dict about the current state.

    Returns:
        {
            "sdk_installed": bool,
            "emulator_installed": bool,
            "avd_exists": bool,
            "emulator_running": bool,
            "running_serial": str or None,
        }
    """
    running = _get_running_emulators()
    return {
        "sdk_installed": _find_binary("sdkmanager") is not None,
        "emulator_installed": _find_binary("emulator") is not None,
        "avd_exists": (_AVD_DIR / f"{_AVD_NAME}.avd").exists(),
        "emulator_running": len(running) > 0,
        "running_serial": running[0] if running else None,
    }
