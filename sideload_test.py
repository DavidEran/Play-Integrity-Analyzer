#!/usr/bin/env python3
"""APK Sideload QA Test Tool.

Automatically sideloads APKs onto a connected Android device (or emulator),
launches them, and detects whether any anti-sideload mechanism blocks or
degrades the user experience.

Usage:
    python sideload_test.py <apk_path_or_directory> [options]

Requirements:
    - Python 3.10+
    - ADB installed and on PATH
    - One Android device or emulator connected via ADB
    - (Optional) aapt2 or aapt on PATH for APK metadata extraction

Known Limitations:
    - Cannot detect server-side feature degradation requiring deep app usage
    - Cannot detect future Auto Protect applied at Play Store distribution time
    - Cannot detect intermittent or A/B tested blocking behavior
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from adb_provisioner import ensure_adb, get_aapt2_path

TOOL_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Keyword patterns for UI hierarchy analysis
# ---------------------------------------------------------------------------

TIER1_KEYWORDS = [
    # English
    "get this app from play",
    "get it on google play",
    "to continue using",
    "get app",
    "needs to be updated",
    "install from google play",
    "download from play store",
    "this app is not available",
    "app not installed correctly",
    "please update",
    "verify your purchase",
    "license check failed",
    "not licensed",
    "couldn't verify",
    # Portuguese
    "obtenha este app no play",
    "fazer login",
    "faça login e encontre",
    "obter app",
    "precisa ser atualizado",
    "instale pelo google play",
    "baixar da play store",
    "não licenciado",
    # Spanish
    "obtén esta app en play",
    "obtener app",
    "necesita actualizarse",
    "instalar desde google play",
    "descargar de play store",
    "sin licencia",
]

TIER2_KEYWORDS = [
    "update",
    "something went wrong",
    "connection error",
    "unavailable",
    "try again later",
    "session expired",
]

TIER2_PACKAGE_NAMES_IN_UI = [
    "com.android.vending",
    "com.google.android.play",
]

# Activities that indicate a redirect away from the app under test
PLAY_STORE_ACTIVITIES = {"com.android.vending"}
INSTALLER_ACTIVITIES = {"com.google.android.packageinstaller"}
KNOWN_LAUNCHERS = {
    "com.google.android.apps.nexuslauncher",
    "com.sec.android.app.launcher",
    "com.huawei.android.launcher",
    "com.miui.home",
    "com.oppo.launcher",
    "com.android.launcher3",
}

# ---------------------------------------------------------------------------
# ADB helpers
# ---------------------------------------------------------------------------


def _get_adb_path():
    """Get ADB binary path, auto-downloading if needed."""
    try:
        return ensure_adb(progress_callback=lambda msg: print(f"  {msg}"))
    except RuntimeError as e:
        print(f"ERROR: {e}")
        sys.exit(1)


# Module-level cached ADB path (resolved on first use)
_adb_path_cache = None


def _adb_cmd(args, serial=None, timeout=30):
    """Run an ADB command and return (returncode, stdout, stderr)."""
    global _adb_path_cache
    if _adb_path_cache is None:
        _adb_path_cache = _get_adb_path()

    cmd = [_adb_path_cache]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "ADB command timed out"
    except FileNotFoundError:
        print(f"ERROR: ADB binary not found at {_adb_path_cache}")
        sys.exit(1)


def _adb_shell(args, serial=None, timeout=30):
    """Shortcut for adb shell <args>."""
    return _adb_cmd(["shell"] + args, serial=serial, timeout=timeout)


def check_adb_device(serial=None):
    """Verify ADB is available and a device is connected. Returns device info string."""
    rc, out, err = _adb_cmd(["devices", "-l"])
    if rc != 0:
        print(f"ERROR: adb devices failed: {err}")
        sys.exit(1)
    lines = [l for l in out.strip().splitlines()[1:] if l.strip()]
    if not lines:
        print("ERROR: No Android device/emulator connected. Connect a device or start an emulator.")
        sys.exit(1)
    if serial:
        matching = [l for l in lines if l.startswith(serial)]
        if not matching:
            print(f"ERROR: Device '{serial}' not found. Available:\n" + "\n".join(lines))
            sys.exit(1)
        return matching[0], serial
    if len(lines) > 1 and not serial:
        print("WARNING: Multiple devices connected. Using first device. Use --device to specify.")
    first_line = lines[0]
    dev_serial = first_line.split()[0]
    return first_line, dev_serial


def get_device_model(serial=None):
    """Get a human-readable device model string."""
    rc, out, _ = _adb_shell(["getprop", "ro.product.model"], serial=serial)
    model = out.strip() if rc == 0 else "Unknown"
    rc, out, _ = _adb_shell(["getprop", "ro.build.version.sdk"], serial=serial)
    sdk = out.strip() if rc == 0 else "?"
    return f"{model} (API {sdk})"


# ---------------------------------------------------------------------------
# APK metadata extraction
# ---------------------------------------------------------------------------


def extract_apk_info(apk_path):
    """Extract package name, launchable activity, label, version from APK."""
    info = {
        "package_name": None,
        "launchable_activity": None,
        "app_label": None,
        "version_name": None,
        "version_code": None,
    }

    # Try provisioned aapt2/aapt first, then system PATH
    tools_to_try = []
    provisioned = get_aapt2_path()
    if provisioned:
        tools_to_try.append(provisioned)
    for t in ["aapt2", "aapt"]:
        p = shutil.which(t)
        if p and p not in tools_to_try:
            tools_to_try.append(p)

    for tool in tools_to_try:
        try:
            cmd = [tool, "dump", "badging", str(apk_path)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode != 0:
                continue
            output = proc.stdout
            # Package name
            m = re.search(r"package:\s+name='([^']+)'", output)
            if m:
                info["package_name"] = m.group(1)
            # Version
            m = re.search(r"versionCode='([^']+)'", output)
            if m:
                info["version_code"] = m.group(1)
            m = re.search(r"versionName='([^']+)'", output)
            if m:
                info["version_name"] = m.group(1)
            # App label
            m = re.search(r"application-label(?:-[^:]+)?:'([^']+)'", output)
            if m:
                info["app_label"] = m.group(1)
            # Launchable activity
            m = re.search(r"launchable-activity:\s+name='([^']+)'", output)
            if m:
                info["launchable_activity"] = m.group(1)
            if info["package_name"]:
                return info
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    # Fallback: try to get package name from aapt on the device via adb
    print("  WARNING: aapt2/aapt not found on PATH. APK metadata extraction limited.")
    return info


# ---------------------------------------------------------------------------
# Core test steps
# ---------------------------------------------------------------------------


def step_clean_slate(package_name, serial=None):
    """Uninstall previous version and clear Play Store state."""
    if package_name:
        _adb_cmd(["uninstall", package_name], serial=serial, timeout=15)
    _adb_shell(["am", "force-stop", "com.android.vending"], serial=serial)


def step_install(apk_path, serial=None):
    """Install APK via ADB sideload. Returns (success, message)."""
    rc, out, err = _adb_cmd(
        ["install", "-r", "-g", str(apk_path)], serial=serial, timeout=120
    )
    combined = out + err
    if rc == 0 and "Success" in combined:
        return True, "SUCCESS"
    # Parse failure reason
    m = re.search(r"(INSTALL_FAILED_\w+|INSTALL_PARSE_FAILED_\w+)", combined)
    reason = m.group(1) if m else combined.strip()[-200:]
    return False, reason


def step_launch(package_name, launchable_activity, serial=None):
    """Launch the app. Returns success boolean."""
    if launchable_activity:
        component = f"{package_name}/{launchable_activity}"
        rc, out, err = _adb_shell(
            ["am", "start", "-n", component], serial=serial
        )
        if rc == 0 and "Error" not in out:
            return True
    # Fallback: monkey launcher
    rc, out, err = _adb_shell(
        ["monkey", "-p", package_name, "-c",
         "android.intent.category.LAUNCHER", "1"],
        serial=serial,
    )
    return rc == 0


def get_foreground_activity(serial=None):
    """Get the current foreground activity component name."""
    rc, out, _ = _adb_shell(
        ["dumpsys", "activity", "activities"], serial=serial, timeout=10
    )
    if rc != 0:
        return None
    for line in out.splitlines():
        if "mResumedActivity" in line or "topResumedActivity" in line:
            # Parse: ActivityRecord{hash u0 com.pkg/.Activity t42}
            m = re.search(r"(\S+/\S+)\s+t\d+", line)
            if m:
                return m.group(1)
            # Alternative format
            m = re.search(r"u0\s+(\S+/\S+)", line)
            if m:
                return m.group(1)
    return None


def capture_ui_hierarchy(serial=None):
    """Dump UI hierarchy and return parsed XML or None."""
    _adb_shell(["rm", "-f", "/sdcard/ui_dump.xml"], serial=serial)
    rc, out, err = _adb_shell(
        ["uiautomator", "dump", "/sdcard/ui_dump.xml"], serial=serial, timeout=15
    )
    if rc != 0:
        # Retry once
        time.sleep(1)
        rc, out, err = _adb_shell(
            ["uiautomator", "dump", "/sdcard/ui_dump.xml"], serial=serial, timeout=15
        )
        if rc != 0:
            return None

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        rc2, _, _ = _adb_cmd(["pull", "/sdcard/ui_dump.xml", tmp_path], serial=serial)
        if rc2 != 0:
            return None
        tree = ET.parse(tmp_path)
        return tree
    except ET.ParseError:
        return None
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def search_ui_keywords(xml_tree):
    """Search UI hierarchy for tier 1 and tier 2 keyword matches.

    Returns (tier1_matches, tier2_matches, package_matches) where each match
    is a dict with 'text' and 'node_class'.
    """
    tier1_matches = []
    tier2_matches = []
    package_matches = []

    if xml_tree is None:
        return tier1_matches, tier2_matches, package_matches

    root = xml_tree.getroot()
    for node in root.iter():
        text = node.get("text", "")
        content_desc = node.get("content-desc", "")
        resource_id = node.get("resource-id", "")
        node_class = node.get("class", "")
        pkg = node.get("package", "")

        combined_text = f"{text} {content_desc}".lower()

        for kw in TIER1_KEYWORDS:
            if kw in combined_text:
                tier1_matches.append({
                    "text": text or content_desc,
                    "node_class": node_class,
                })
                break

        for kw in TIER2_KEYWORDS:
            if kw in combined_text:
                tier2_matches.append({
                    "text": text or content_desc,
                    "node_class": node_class,
                })
                break

        for pkg_name in TIER2_PACKAGE_NAMES_IN_UI:
            if pkg_name in pkg or pkg_name in resource_id:
                package_matches.append({
                    "text": f"Package {pkg_name} found in UI",
                    "node_class": node_class,
                })
                break

    return tier1_matches, tier2_matches, package_matches


def capture_screenshot(package_name, seconds, screenshots_dir, serial=None):
    """Capture a screenshot from device and save locally. Returns saved path or None."""
    screenshots_dir = Path(screenshots_dir)
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{package_name}_{seconds}s.png"
    local_path = screenshots_dir / filename

    _adb_shell(["screencap", "-p", "/sdcard/screenshot.png"], serial=serial, timeout=15)
    rc, _, _ = _adb_cmd(["pull", "/sdcard/screenshot.png", str(local_path)], serial=serial)
    if rc == 0 and local_path.exists():
        return str(local_path)
    return None


def get_app_pid(package_name, serial=None):
    """Get the PID of the running app."""
    rc, out, _ = _adb_shell(["pidof", package_name], serial=serial)
    if rc == 0 and out.strip():
        try:
            return int(out.strip().split()[0])
        except ValueError:
            pass
    return None


def capture_logcat_signals(package_name, serial=None):
    """Capture filtered logcat entries relevant to integrity/licensing."""
    signals = []
    pid = get_app_pid(package_name, serial=serial)

    # App-specific logcat
    if pid:
        rc, out, _ = _adb_shell(
            ["logcat", "-d", "-v", "time", "--pid", str(pid)],
            serial=serial, timeout=15,
        )
        if rc == 0:
            for line in out.splitlines():
                if re.search(
                    r"license|integrity|NOT_LICENSED|market://|play\.google\.com|attestation|appcheck|safetynet",
                    line, re.IGNORECASE,
                ):
                    signals.append(line.strip())

    # System-level integrity messages
    rc, out, _ = _adb_shell(
        ["logcat", "-d", "-v", "time"],
        serial=serial, timeout=15,
    )
    if rc == 0:
        for line in out.splitlines():
            if re.search(
                r"IntegrityService|LicenseCheck|PlayProtect|AutoProtect",
                line, re.IGNORECASE,
            ):
                if line.strip() not in signals:
                    signals.append(line.strip())

    return signals


def clear_logcat(serial=None):
    """Clear logcat buffer before launch."""
    _adb_shell(["logcat", "-c"], serial=serial)


# ---------------------------------------------------------------------------
# Monitoring loop
# ---------------------------------------------------------------------------


def _activity_package(activity_component):
    """Extract the package name from an activity component like 'com.pkg/.Activity'."""
    if activity_component and "/" in activity_component:
        return activity_component.split("/")[0]
    return activity_component


def monitor_app(package_name, timeout, screenshots_dir, serial=None):
    """Run the monitoring loop. Returns a signals dict."""
    foreground_changes = []
    keyword_matches = []
    screenshots = []
    logcat_signals = []

    t0 = time.monotonic()
    last_activity = None
    check_interval = 3
    # Ensure we capture at key times: 3, 10, 20, and final
    screenshot_times = set()
    mandatory_screenshots = {3, 10, 20, timeout}

    while True:
        elapsed = time.monotonic() - t0
        if elapsed > timeout:
            break

        seconds = int(elapsed)
        print(f"  \u23f3 Monitoring... {seconds}s", end="\r", flush=True)

        # Check A: Foreground activity
        current_activity = get_foreground_activity(serial=serial)
        if current_activity and current_activity != last_activity:
            foreground_changes.append({
                "time": round(elapsed, 1),
                "activity": current_activity,
            })
            current_pkg = _activity_package(current_activity)

            if current_pkg in PLAY_STORE_ACTIVITIES:
                print(f"\n  \u26a0 Foreground changed: {current_activity}")

            last_activity = current_activity

        # Check B: UI hierarchy keywords
        xml_tree = capture_ui_hierarchy(serial=serial)
        t1, t2, pkg_matches = search_ui_keywords(xml_tree)
        for match in t1:
            entry = {"time": seconds, "tier": 1, **match}
            if not any(
                m["text"] == entry["text"] and m["tier"] == 1
                for m in keyword_matches
            ):
                keyword_matches.append(entry)
        for match in t2:
            entry = {"time": seconds, "tier": 2, **match}
            if not any(
                m["text"] == entry["text"] and m["tier"] == 2
                for m in keyword_matches
            ):
                keyword_matches.append(entry)
        for match in pkg_matches:
            entry = {"time": seconds, "tier": 2, **match}
            if not any(
                m["text"] == entry["text"] and m["tier"] == 2
                for m in keyword_matches
            ):
                keyword_matches.append(entry)

        # Check C: Screenshot at key intervals
        closest_mandatory = min(mandatory_screenshots, key=lambda t: abs(t - seconds))
        if abs(closest_mandatory - seconds) <= 2 and closest_mandatory not in screenshot_times:
            path = capture_screenshot(package_name, seconds, screenshots_dir, serial=serial)
            if path:
                screenshots.append(path)
                screenshot_times.add(closest_mandatory)

        # Wait for next check interval
        next_check = t0 + (int(elapsed / check_interval) + 1) * check_interval
        sleep_time = next_check - time.monotonic()
        if sleep_time > 0 and time.monotonic() - t0 < timeout:
            time.sleep(min(sleep_time, timeout - (time.monotonic() - t0)))

    print()  # Clear the monitoring line

    # Final screenshot
    if timeout not in screenshot_times:
        path = capture_screenshot(package_name, timeout, screenshots_dir, serial=serial)
        if path:
            screenshots.append(path)

    # Check D: Logcat
    logcat_signals = capture_logcat_signals(package_name, serial=serial)

    return {
        "foreground_changes": foreground_changes,
        "keyword_matches": keyword_matches,
        "logcat_signals": logcat_signals,
        "screenshots": screenshots,
    }


# ---------------------------------------------------------------------------
# Verdict determination
# ---------------------------------------------------------------------------


def determine_verdict(signals, install_result, timeout):
    """Determine PASS/FAIL/REVIEW verdict and reason."""
    foreground_changes = signals["foreground_changes"]
    keyword_matches = signals["keyword_matches"]
    logcat_signals = signals["logcat_signals"]

    tier1 = [m for m in keyword_matches if m.get("tier") == 1]
    tier2 = [m for m in keyword_matches if m.get("tier") == 2]

    # FAIL: Install itself failed with verification error
    if install_result != "SUCCESS":
        if "VERIFICATION" in install_result:
            return "FAIL", f"Install failed: {install_result} (possible Play Protect block)"
        return "FAIL", f"Install failed: {install_result}"

    # FAIL: Foreground switched to Play Store
    for change in foreground_changes:
        pkg = _activity_package(change.get("activity", ""))
        if pkg in PLAY_STORE_ACTIVITIES:
            reason = "Play Auto Protect dialog detected — foreground switched to " + change["activity"]
            if tier1:
                reason += f" with '{tier1[0]['text']}' text"
            return "FAIL", reason

    # FAIL: Tier 1 keyword match
    if tier1:
        texts = ", ".join(f"'{m['text']}'" for m in tier1[:3])
        return "FAIL", f"Anti-sideload dialog detected — {texts}"

    # FAIL: App left foreground within 10s and launcher/play store is now showing
    if len(foreground_changes) >= 2:
        for change in foreground_changes[1:]:
            if change["time"] <= 10:
                pkg = _activity_package(change.get("activity", ""))
                if pkg in KNOWN_LAUNCHERS:
                    return "FAIL", f"App crashed or closed itself within {change['time']}s — device launcher is now foreground"

    # REVIEW: Tier 2 matches
    if tier2:
        texts = ", ".join(f"'{m['text']}'" for m in tier2[:3])
        return "REVIEW", f"Possible issues detected — {texts}"

    # REVIEW: Logcat integrity signals
    if logcat_signals:
        return "REVIEW", f"Integrity/license related logcat entries found ({len(logcat_signals)} entries)"

    # REVIEW: App left foreground for unknown activity
    if foreground_changes:
        last = foreground_changes[-1]
        last_pkg = _activity_package(last.get("activity", ""))
        # If the final foreground is not our app, that's suspicious
        pkg_from_changes = {_activity_package(c["activity"]) for c in foreground_changes}
        # Get the package from the first entry (should be our app)
        if len(foreground_changes) >= 1:
            first_pkg = _activity_package(foreground_changes[0].get("activity", ""))
            if last_pkg and last_pkg != first_pkg and last["time"] > 5:
                return "REVIEW", f"App lost foreground at {last['time']}s to {last['activity']}"

    # PASS
    return "PASS", "App remained in foreground for full monitoring duration, no blocking detected"


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


def step_cleanup(package_name, serial=None):
    """Force-stop and uninstall the app, clean temp files."""
    if package_name:
        _adb_shell(["am", "force-stop", package_name], serial=serial)
        _adb_cmd(["uninstall", package_name], serial=serial, timeout=15)
    _adb_shell(["rm", "-f", "/sdcard/ui_dump.xml"], serial=serial)
    _adb_shell(["rm", "-f", "/sdcard/screenshot.png"], serial=serial)


# ---------------------------------------------------------------------------
# Single APK test orchestrator
# ---------------------------------------------------------------------------


def test_single_apk(apk_path, timeout, screenshots_dir, serial=None):
    """Run the full test flow for one APK. Returns a result dict."""
    apk_path = Path(apk_path)
    result = {
        "apk_file": apk_path.name,
        "package_name": None,
        "app_name": None,
        "version": None,
        "verdict": None,
        "verdict_reason": None,
        "install_result": None,
        "signals": {},
        "duration_seconds": 0,
    }

    # Step 1: Extract app info
    info = extract_apk_info(apk_path)
    result["package_name"] = info["package_name"]
    result["app_name"] = info["app_label"]
    result["version"] = info["version_name"]
    display_name = info["app_label"] or info["package_name"] or apk_path.name

    if not info["package_name"]:
        print(f"  WARNING: Could not extract package name from {apk_path.name}")
        result["verdict"] = "FAIL"
        result["verdict_reason"] = "Could not extract package name from APK"
        return result

    # Step 2: Clean slate
    step_clean_slate(info["package_name"], serial=serial)

    # Step 3: Install
    success, install_msg = step_install(apk_path, serial=serial)
    result["install_result"] = install_msg

    if not success:
        print(f"  \u2717 Install failed: {install_msg}")
        result["verdict"] = "FAIL"
        result["verdict_reason"] = f"Install failed: {install_msg}"
        result["signals"] = {
            "foreground_changes": [],
            "keyword_matches": [],
            "logcat_signals": [],
            "screenshots": [],
        }
        step_cleanup(info["package_name"], serial=serial)
        return result

    print("  \u2713 Install successful")

    # Step 4: Launch
    clear_logcat(serial=serial)
    launched = step_launch(info["package_name"], info["launchable_activity"], serial=serial)
    if not launched:
        print("  \u2717 Failed to launch app")
        result["verdict"] = "FAIL"
        result["verdict_reason"] = "App failed to launch"
        result["signals"] = {
            "foreground_changes": [],
            "keyword_matches": [],
            "logcat_signals": [],
            "screenshots": [],
        }
        step_cleanup(info["package_name"], serial=serial)
        return result

    print("  \u2713 App launched")
    t_start = time.monotonic()

    # Step 5: Monitor
    signals = monitor_app(
        info["package_name"], timeout, screenshots_dir, serial=serial
    )
    result["signals"] = signals
    result["duration_seconds"] = round(time.monotonic() - t_start, 1)

    # Step 6: Determine verdict
    verdict, reason = determine_verdict(signals, install_msg, timeout)
    result["verdict"] = verdict
    result["verdict_reason"] = reason

    # Print verdict
    if verdict == "FAIL":
        print(f"  \u2717 FAIL: {reason}")
        for m in signals.get("keyword_matches", []):
            if m.get("tier") == 1:
                print(f"       \"{m['text']}\"")
    elif verdict == "REVIEW":
        print(f"  \u26a0 REVIEW: {reason}")
    else:
        print(f"  \u2713 PASS: {reason}")

    if signals.get("screenshots"):
        print(f"  \U0001f4f8 Evidence: {signals['screenshots'][-1]}")

    # Step 7: Cleanup
    step_cleanup(info["package_name"], serial=serial)
    print("  \U0001f9f9 Cleanup complete")

    return result


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def collect_apks(path):
    """Collect APK files from a file path or directory."""
    p = Path(path)
    if p.is_file() and p.suffix.lower() == ".apk":
        return [p]
    if p.is_dir():
        apks = sorted(p.glob("*.apk"))
        if not apks:
            print(f"ERROR: No APK files found in directory: {p}")
            sys.exit(1)
        return apks
    print(f"ERROR: Path is not a valid APK file or directory: {p}")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="APK Sideload QA Test Tool — detect anti-sideload mechanisms on Android devices",
    )
    parser.add_argument(
        "apk_path",
        help="Path to an APK file or directory containing APKs",
    )
    parser.add_argument(
        "--output",
        default="sideload_report.json",
        help="Path to JSON report file (default: sideload_report.json)",
    )
    parser.add_argument(
        "--screenshots-dir",
        default="./screenshots",
        help="Directory for evidence screenshots (default: ./screenshots)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Seconds to monitor after launch (default: 30)",
    )
    parser.add_argument(
        "--device",
        default=None,
        help="ADB device serial if multiple devices connected",
    )
    args = parser.parse_args()

    # Verify ADB and device
    device_info, serial = check_adb_device(args.device)
    device_model = get_device_model(serial)
    print(f"Device: {device_model} ({serial})")
    print()

    # Collect APKs
    apks = collect_apks(args.apk_path)
    total = len(apks)
    results = []
    verdicts = {"PASS": 0, "FAIL": 0, "REVIEW": 0}

    for i, apk in enumerate(apks, 1):
        if not apk.exists():
            print(f"[{i}/{total}] SKIPPED: {apk.name} (file not found)")
            continue

        info = extract_apk_info(apk)
        display = info["app_label"] or info["package_name"] or apk.name
        pkg_display = f" ({info['package_name']})" if info["package_name"] else ""
        print(f"[{i}/{total}] Testing: {display}{pkg_display}")

        result = test_single_apk(apk, args.timeout, args.screenshots_dir, serial=serial)
        results.append(result)

        v = result.get("verdict", "FAIL")
        if v in verdicts:
            verdicts[v] += 1
        else:
            verdicts["FAIL"] += 1

        print()

    # Build report
    report = {
        "test_run": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "device": device_model,
            "adb_serial": serial,
            "tool_version": TOOL_VERSION,
        },
        "results": results,
        "summary": {
            "total": total,
            "pass": verdicts["PASS"],
            "fail": verdicts["FAIL"],
            "review": verdicts["REVIEW"],
        },
        "known_limitations": [
            "Cannot detect server-side feature degradation requiring deep app usage (login, gameplay, etc.)",
            "Cannot detect future Auto Protect applied at Play Store distribution time",
            "Cannot detect intermittent or A/B tested blocking behavior",
        ],
    }

    # Write report
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    # Summary
    print("=" * 40)
    print("RESULTS SUMMARY")
    print("=" * 40)
    print(f"PASS:   {verdicts['PASS']} app(s)")
    print(f"FAIL:   {verdicts['FAIL']} app(s)")
    print(f"REVIEW: {verdicts['REVIEW']} app(s)")
    print("=" * 40)
    print(f"Full report: {output_path}")

    # Exit code: 1 if any failures
    sys.exit(1 if verdicts["FAIL"] > 0 else 0)


if __name__ == "__main__":
    main()
