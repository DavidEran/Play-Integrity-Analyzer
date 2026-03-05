"""Core analysis engine for Play Integrity detection in APK files."""

import re
import zipfile
from io import BytesIO

from models import AnalysisResult, Finding, LayerResult, RiskLevel, RISK_DESCRIPTIONS
from detection_patterns import (
    PAIRIP_FILE_PATTERNS,
    PAIRIP_DEX_PATTERNS,
    INTEGRITY_API_CLASS_PATTERNS,
    INTEGRITY_TOKEN_REQUEST_PATTERNS,
    INTEGRITY_VERDICT_PATTERNS,
    INTEGRITY_APP_ACCESS_RISK_PATTERNS,
    SIDELOAD_BLOCK_VERDICTS,
    SAFETYNET_PATTERNS,
    FIREBASE_APPCHECK_PATTERNS,
    MANIFEST_PLAY_CORE_PATTERNS,
    PLAY_ASSET_DELIVERY_PATTERNS,
    META_INF_PATTERNS,
)


def _search_text(text: str, patterns: list[str], source: str, category: str) -> list[Finding]:
    """Search text for pattern matches and return findings."""
    findings = []
    for pattern in patterns:
        if pattern in text:
            findings.append(Finding(
                category=category,
                source_file=source,
                pattern_matched=pattern,
            ))
    return findings


def _extract_package_name(manifest_latin1: str, manifest_utf16: str) -> str:
    """Try to extract the package name from binary manifest data."""
    for text in (manifest_latin1, manifest_utf16):
        # Look for common Android package name patterns
        matches = re.findall(r'((?:com|org|net|io|app|me|dev)\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,6})', text)
        if matches:
            # Filter out known library packages and pick the most likely app package
            candidates = [
                m for m in matches
                if not m.startswith(("com.google.", "com.android.", "org.apache.",
                                     "com.squareup.", "com.facebook.", "org.jetbrains.",
                                     "io.reactivex.", "com.jakewharton."))
            ]
            if candidates:
                return candidates[0]
            return matches[0]
    return "Unknown"


def analyze_apk(file_data: bytes, file_name: str) -> AnalysisResult:
    """Analyze an APK file for Play Integrity and Auto Protection indicators.

    Args:
        file_data: Raw bytes of the APK file.
        file_name: Original filename for display.

    Returns:
        AnalysisResult with all findings and risk classification.
    """
    result = AnalysisResult(
        file_name=file_name,
        file_size_mb=round(len(file_data) / (1024 * 1024), 2),
    )

    try:
        apk_io = BytesIO(file_data)
        with zipfile.ZipFile(apk_io, 'r') as apk:
            all_files = apk.namelist()
            _scan_file_listing(all_files, result)
            _scan_dex_files(apk, all_files, result)
            _scan_manifest(apk, result)
            _scan_meta_inf(apk, all_files, result)
    except zipfile.BadZipFile:
        result.error = "Invalid APK file — not a valid ZIP archive."
        return result
    except Exception as e:
        result.error = f"Error analyzing APK: {e}"
        return result

    _classify_risk(result)
    return result


def _scan_file_listing(all_files: list[str], result: AnalysisResult):
    """Layer 1 (partial): Check file listing for pairip libraries."""
    for file_path in all_files:
        file_lower = file_path.lower()
        for pattern in PAIRIP_FILE_PATTERNS:
            if pattern.lower() in file_lower:
                finding = Finding(
                    category="Auto Protection (pairip)",
                    source_file=file_path,
                    pattern_matched=pattern,
                    detail=f"Found pairip library: {file_path}",
                )
                result.auto_protection.findings.append(finding)
                result.all_findings.append(finding)

        # Also catch any file path containing "pairip"
        if "pairip" in file_lower and not any(
            p.lower() in file_lower for p in PAIRIP_FILE_PATTERNS
        ):
            finding = Finding(
                category="Auto Protection (pairip)",
                source_file=file_path,
                pattern_matched="pairip (file path)",
                detail=f"File path contains pairip: {file_path}",
            )
            result.auto_protection.findings.append(finding)
            result.all_findings.append(finding)


def _scan_dex_files(apk: zipfile.ZipFile, all_files: list[str], result: AnalysisResult):
    """Scan all DEX files for patterns across all detection layers."""
    dex_files = sorted(f for f in all_files if f.endswith('.dex'))

    for dex_name in dex_files:
        dex_data = apk.read(dex_name)
        dex_text = dex_data.decode('latin-1')

        # Layer 1: pairip in DEX
        findings = _search_text(dex_text, PAIRIP_DEX_PATTERNS, dex_name, "Auto Protection (pairip)")
        result.auto_protection.findings.extend(findings)
        result.all_findings.extend(findings)

        # Layer 2: Play Integrity API classes
        findings = _search_text(dex_text, INTEGRITY_API_CLASS_PATTERNS, dex_name, "Play Integrity API")
        result.play_integrity.findings.extend(findings)
        result.all_findings.extend(findings)

        # Layer 2: Token request methods
        findings = _search_text(dex_text, INTEGRITY_TOKEN_REQUEST_PATTERNS, dex_name, "Play Integrity API")
        result.play_integrity.findings.extend(findings)
        result.all_findings.extend(findings)

        # Layer 2: Verdict strings
        findings = _search_text(dex_text, INTEGRITY_VERDICT_PATTERNS, dex_name, "Play Integrity API")
        result.play_integrity.findings.extend(findings)
        result.all_findings.extend(findings)

        # Layer 2: App Access Risk
        findings = _search_text(dex_text, INTEGRITY_APP_ACCESS_RISK_PATTERNS, dex_name, "Play Integrity API")
        result.play_integrity.findings.extend(findings)
        result.all_findings.extend(findings)

        # Layer 3: SafetyNet
        findings = _search_text(dex_text, SAFETYNET_PATTERNS, dex_name, "SafetyNet (Legacy)")
        result.safetynet.findings.extend(findings)
        result.all_findings.extend(findings)

        # Layer 4: Firebase App Check
        findings = _search_text(dex_text, FIREBASE_APPCHECK_PATTERNS, dex_name, "Firebase App Check")
        result.firebase_appcheck.findings.extend(findings)
        result.all_findings.extend(findings)

        # Layer 5: Play Asset Delivery
        findings = _search_text(dex_text, PLAY_ASSET_DELIVERY_PATTERNS, dex_name, "Play Asset Delivery")
        result.play_asset_delivery.findings.extend(findings)
        result.all_findings.extend(findings)


def _scan_manifest(apk: zipfile.ZipFile, result: AnalysisResult):
    """Scan AndroidManifest.xml (binary format) for patterns."""
    try:
        manifest_data = apk.read('AndroidManifest.xml')
    except KeyError:
        return

    manifest_latin1 = manifest_data.decode('latin-1')
    manifest_utf16 = manifest_data.decode('utf-16-le', errors='ignore')

    # Extract package name
    result.package_name = _extract_package_name(manifest_latin1, manifest_utf16)

    for text in (manifest_latin1, manifest_utf16):
        encoding = "latin-1" if text is manifest_latin1 else "utf-16-le"
        source = f"AndroidManifest.xml ({encoding})"

        # Play Core / manifest patterns (informational only)
        findings = _search_text(text, MANIFEST_PLAY_CORE_PATTERNS, source, "Manifest Analysis")
        result.manifest_analysis.findings.extend(findings)
        result.all_findings.extend(findings)


def _scan_meta_inf(apk: zipfile.ZipFile, all_files: list[str], result: AnalysisResult):
    """Scan META-INF and other metadata files for integrity-related dependencies."""
    meta_files = [f for f in all_files if f.startswith('META-INF/') or f.endswith('.properties')]
    asset_files = [f for f in all_files if f.startswith('assets/')]

    for file_path in meta_files + asset_files:
        try:
            data = apk.read(file_path)
            # Only scan text-like files up to 1MB
            if len(data) > 1_000_000:
                continue
            text = data.decode('latin-1')
        except Exception:
            continue

        for pattern in META_INF_PATTERNS:
            if pattern in text:
                finding = Finding(
                    category="Manifest Analysis",
                    source_file=file_path,
                    pattern_matched=pattern,
                    detail=f"Dependency reference found in {file_path}",
                )
                result.manifest_analysis.findings.append(finding)
                result.all_findings.append(finding)


def _classify_risk(result: AnalysisResult):
    """Apply risk classification logic based on all findings."""
    # Mark layers as detected
    result.auto_protection.detected = len(result.auto_protection.findings) > 0
    result.play_integrity.detected = len(result.play_integrity.findings) > 0
    result.firebase_appcheck.detected = len(result.firebase_appcheck.findings) > 0
    result.safetynet.detected = len(result.safetynet.findings) > 0
    result.play_asset_delivery.detected = len(result.play_asset_delivery.findings) > 0
    result.manifest_analysis.detected = len(result.manifest_analysis.findings) > 0

    # Build summaries
    if result.auto_protection.detected:
        archs = set()
        for f in result.auto_protection.findings:
            if "lib/" in f.source_file:
                parts = f.source_file.split("/")
                if len(parts) >= 2:
                    archs.add(parts[1])
        arch_str = ", ".join(sorted(archs)) if archs else "detected in DEX/manifest"
        result.auto_protection.summary = f"pairip found ({arch_str})"

    if result.play_integrity.detected:
        matched = {f.pattern_matched for f in result.play_integrity.findings}
        has_standard = any("Standard" in p for p in matched)
        api_type = "Standard API" if has_standard else "Classic API"
        has_tokens = any(p in matched for p in INTEGRITY_TOKEN_REQUEST_PATTERNS)
        has_verdicts = any(p in matched for p in INTEGRITY_VERDICT_PATTERNS + INTEGRITY_APP_ACCESS_RISK_PATTERNS)
        parts = [api_type]
        if has_tokens:
            parts.append("token requests")
        if has_verdicts:
            parts.append("verdict checks")
        result.play_integrity.summary = ", ".join(parts)

    if result.firebase_appcheck.detected:
        matched = {f.pattern_matched for f in result.firebase_appcheck.findings}
        if "PlayIntegrityAppCheckProviderFactory" in str(matched):
            result.firebase_appcheck.summary = "Firebase App Check with Play Integrity provider"
        else:
            result.firebase_appcheck.summary = "Firebase App Check detected"

    if result.safetynet.detected:
        result.safetynet.summary = "Legacy SafetyNet API detected (deprecated)"

    if result.play_asset_delivery.detected:
        result.play_asset_delivery.summary = "Play Asset Delivery in use"

    if result.manifest_analysis.detected:
        result.manifest_analysis.summary = f"{len(result.manifest_analysis.findings)} manifest indicator(s) found"

    # Risk classification (order matters — highest risk first)
    integrity_matched = {f.pattern_matched for f in result.play_integrity.findings}
    has_api_classes = any(p in integrity_matched for p in INTEGRITY_API_CLASS_PATTERNS)
    has_token_requests = any(p in integrity_matched for p in INTEGRITY_TOKEN_REQUEST_PATTERNS)
    has_verdicts = any(p in integrity_matched for p in INTEGRITY_VERDICT_PATTERNS + INTEGRITY_APP_ACCESS_RISK_PATTERNS)
    has_sideload_block = any(p in integrity_matched for p in SIDELOAD_BLOCK_VERDICTS)

    # Corroboration gate: token requests, verdicts, and sideload block verdicts
    # only count if at least one API class is also present. This prevents
    # false positives from short strings matching unrelated code.
    if not has_api_classes:
        has_token_requests = False
        has_verdicts = False
        has_sideload_block = False

    if result.auto_protection.detected:
        result.risk_level = RiskLevel.CRITICAL
        result.risk_description = RISK_DESCRIPTIONS[RiskLevel.CRITICAL]
    elif result.play_integrity.detected and has_sideload_block:
        result.risk_level = RiskLevel.HIGH
        result.risk_description = (
            "App explicitly checks for sideloaded installs and likely redirects "
            "to Play Store. Developer needs to handle UNLICENSED verdicts gracefully."
        )
    elif result.play_integrity.detected and has_token_requests and has_verdicts:
        result.risk_level = RiskLevel.HIGH
        result.risk_description = (
            "App requests integrity tokens and inspects verdicts. Sideloaded "
            "installs will likely be blocked or degraded."
        )
    elif result.play_integrity.detected and has_token_requests:
        result.risk_level = RiskLevel.MEDIUM
        result.risk_description = RISK_DESCRIPTIONS[RiskLevel.MEDIUM]
    elif result.play_integrity.detected and has_api_classes:
        result.risk_level = RiskLevel.LOW
        result.risk_description = RISK_DESCRIPTIONS[RiskLevel.LOW]
    elif result.firebase_appcheck.detected:
        result.risk_level = RiskLevel.MEDIUM
        result.risk_description = (
            "Firebase App Check is present. May block API access for "
            "sideloaded installs depending on server-side configuration."
        )
    elif result.safetynet.detected:
        result.risk_level = RiskLevel.LOW
        result.risk_description = (
            "Legacy SafetyNet detected (deprecated). May still affect "
            "sideloaded installs but is being phased out."
        )
    elif result.play_asset_delivery.detected:
        result.risk_level = RiskLevel.INFO
        result.risk_description = RISK_DESCRIPTIONS[RiskLevel.INFO]
    else:
        result.risk_level = RiskLevel.NONE
        result.risk_description = RISK_DESCRIPTIONS[RiskLevel.NONE]
