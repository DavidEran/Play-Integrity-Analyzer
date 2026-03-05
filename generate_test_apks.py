#!/usr/bin/env python3
"""Generate 4 simple test game APKs for the Play Integrity Analyzer.

Creates synthetic APK files (ZIP archives) with embedded patterns that
the analyzer can detect. Each APK simulates a simple game with different
configurations:

1. game_integrity_on.apk  — Play Integrity API enabled (HIGH risk)
2. game_integrity_off.apk — Play Integrity API disabled (NONE risk)
3. game_wakelock_on.apk   — Wake Lock enabled (3-minute keep-alive)
4. game_wakelock_off.apk  — Wake Lock disabled
"""

import os
import struct
import zipfile

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_apks")


def _build_fake_manifest(package_name: str, permissions: list[str] | None = None) -> bytes:
    """Build a minimal AndroidManifest.xml with the package name embedded.

    The analyzer decodes the manifest as both latin-1 and utf-16-le and uses
    regex to find package names like com.example.foo. We embed the package
    name in plain UTF-16-LE so the analyzer picks it up.
    """
    permissions = permissions or []
    perm_block = "".join(
        f'    <uses-permission android:name="{p}" />\n' for p in permissions
    )
    manifest_text = (
        f'<?xml version="1.0" encoding="utf-8"?>\n'
        f'<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
        f'    package="{package_name}">\n'
        f'{perm_block}'
        f'    <application android:label="TestGame">\n'
        f'        <activity android:name=".MainActivity" />\n'
        f'    </application>\n'
        f'</manifest>\n'
    )
    # Store as UTF-16-LE so the analyzer's utf-16-le decode path finds the package
    return manifest_text.encode("utf-16-le")


def _build_fake_dex(strings: list[str]) -> bytes:
    """Build a fake classes.dex that contains the given strings.

    The analyzer reads .dex files, decodes as latin-1, and searches for
    substrings. We don't need a valid Dalvik Executable — just a file whose
    latin-1 representation contains the target strings.
    """
    # Start with the DEX magic header so it looks semi-legit
    header = b"dex\n035\x00"
    # Embed each string separated by null bytes
    body = b"\x00".join(s.encode("latin-1") for s in strings)
    return header + b"\x00" * 32 + body + b"\x00" * 16


def _build_fake_meta_inf(deps: list[str]) -> bytes:
    """Build a META-INF/dependencies file listing library references."""
    lines = [f"dependency={d}" for d in deps]
    return "\n".join(lines).encode("utf-8")


def _write_apk(path: str, manifest: bytes, dex: bytes,
               extra_files: dict[str, bytes] | None = None):
    """Package components into a ZIP file with .apk extension."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
        if extra_files:
            for name, data in extra_files.items():
                zf.writestr(name, data)


def generate_game_integrity_on():
    """Game APK with Play Integrity API ON — triggers HIGH risk."""
    package = "com.testgame.puzzleblast"

    manifest = _build_fake_manifest(package, permissions=[
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
    ])

    # Embed Play Integrity API class paths, token requests, and verdict strings
    dex_strings = [
        # Game activity code
        "com/testgame/puzzleblast/MainActivity",
        "com/testgame/puzzleblast/GameEngine",
        "android/app/Activity",
        # Play Integrity API classes (Layer 2)
        "com/google/android/play/core/integrity/IntegrityManager",
        "com/google/android/play/core/integrity/IntegrityManagerFactory",
        "com/google/android/play/core/integrity/IntegrityTokenRequest",
        "com/google/android/play/core/integrity/IntegrityTokenResponse",
        # Token request methods
        "requestIntegrityToken",
        "prepareIntegrityToken",
        # Verdict strings
        "appRecognitionVerdict",
        "deviceRecognitionVerdict",
        "appLicensingVerdict",
        "PLAY_RECOGNIZED",
        "UNRECOGNIZED_VERSION",
        "GET_LICENSED",
        "appAccessRiskVerdict",
    ]

    dex = _build_fake_dex(dex_strings)
    meta = _build_fake_meta_inf(["play-services-integrity"])

    path = os.path.join(OUTPUT_DIR, "game_integrity_on.apk")
    _write_apk(path, manifest, dex, {
        "META-INF/com.google.android.play.integrity.properties": meta,
    })
    print(f"  Created: {path}")
    return path


def generate_game_integrity_off():
    """Game APK with Play Integrity API OFF — triggers NONE risk."""
    package = "com.testgame.spacerush"

    manifest = _build_fake_manifest(package, permissions=[
        "android.permission.INTERNET",
    ])

    # Only generic game code — no integrity patterns
    dex_strings = [
        "com/testgame/spacerush/MainActivity",
        "com/testgame/spacerush/GameEngine",
        "com/testgame/spacerush/SpriteRenderer",
        "android/app/Activity",
        "android/graphics/Canvas",
        "android/view/SurfaceView",
        "android/media/SoundPool",
    ]

    dex = _build_fake_dex(dex_strings)

    path = os.path.join(OUTPUT_DIR, "game_integrity_off.apk")
    _write_apk(path, manifest, dex)
    print(f"  Created: {path}")
    return path


def generate_game_wakelock_on():
    """Game APK with Wake Lock ON (3-minute keep-alive)."""
    package = "com.testgame.dungeonrun"

    manifest = _build_fake_manifest(package, permissions=[
        "android.permission.INTERNET",
        "android.permission.WAKE_LOCK",
    ])

    # Wake lock usage in DEX — acquires a 3-minute partial wake lock
    dex_strings = [
        "com/testgame/dungeonrun/MainActivity",
        "com/testgame/dungeonrun/GameEngine",
        "com/testgame/dungeonrun/WakeLockManager",
        "android/app/Activity",
        "android/os/PowerManager",
        "android/os/PowerManager$WakeLock",
        "PARTIAL_WAKE_LOCK",
        "acquire",
        # 3-minute timeout = 180000ms
        "GameWakeLock",
        "PowerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, GameWakeLock)",
        "wakeLock.acquire(180000)",
        "android/graphics/Canvas",
        "android/view/SurfaceView",
    ]

    dex = _build_fake_dex(dex_strings)

    path = os.path.join(OUTPUT_DIR, "game_wakelock_on.apk")
    _write_apk(path, manifest, dex)
    print(f"  Created: {path}")
    return path


def generate_game_wakelock_off():
    """Game APK with Wake Lock OFF — no wake lock permission or usage."""
    package = "com.testgame.pixeljump"

    manifest = _build_fake_manifest(package, permissions=[
        "android.permission.INTERNET",
    ])

    # Standard game code, no wake lock references
    dex_strings = [
        "com/testgame/pixeljump/MainActivity",
        "com/testgame/pixeljump/GameEngine",
        "com/testgame/pixeljump/LevelManager",
        "android/app/Activity",
        "android/graphics/Canvas",
        "android/view/SurfaceView",
        "android/media/SoundPool",
    ]

    dex = _build_fake_dex(dex_strings)

    path = os.path.join(OUTPUT_DIR, "game_wakelock_off.apk")
    _write_apk(path, manifest, dex)
    print(f"  Created: {path}")
    return path


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("Generating test game APKs...")
    print()

    generate_game_integrity_on()
    generate_game_integrity_off()
    generate_game_wakelock_on()
    generate_game_wakelock_off()

    print()
    print(f"All 4 APKs written to: {OUTPUT_DIR}/")
    print()
    print("APK descriptions:")
    print("  1. game_integrity_on.apk  — Play Integrity ON  (expects HIGH risk)")
    print("  2. game_integrity_off.apk — Play Integrity OFF (expects NONE risk)")
    print("  3. game_wakelock_on.apk   — Wake Lock ON (3-min keep-alive)")
    print("  4. game_wakelock_off.apk  — Wake Lock OFF (no wake lock)")


if __name__ == "__main__":
    main()
