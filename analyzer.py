"""Core analysis engine for Play Integrity detection in APK files."""

import re
import zipfile
from io import BytesIO

from models import AnalysisResult, Finding, LayerResult, RiskLevel, RISK_DESCRIPTIONS
from detection_patterns import (
    PAIRIP_FILE_INDICATORS,
    INTEGRITY_API_CLASSES,
    INTEGRITY_TOKEN_METHODS,
    INTEGRITY_VERDICT_FIELD_NAMES,
    SIDELOAD_ENFORCEMENT_STRINGS,
    SAFETYNET_CLASS_PATHS,
    FIREBASE_PLAY_INTEGRITY_PROVIDER,
    FIREBASE_APPCHECK_INFORMATIONAL,
    PLAY_ASSET_DELIVERY_INDICATORS,
    META_INF_INDICATORS,
)


def _search_text(text, patterns, source, category):
    findings = []
    seen = set()
    for pattern in patterns:
        if pattern in text and pattern not in seen:
            seen.add(pattern)
            findings.append(Finding(category=category, source_file=source, pattern_matched=pattern))
    return findings


def _extract_package_name_from_binary_manifest(manifest_data):
    LIBRARY_PREFIXES = (
        "com.google.", "com.android.", "org.apache.", "com.squareup.",
        "com.facebook.", "org.jetbrains.", "io.reactivex.", "com.jakewharton.",
        "org.chromium.", "com.unity3d.", "org.json.", "io.flutter.",
        "com.appsflyer.", "com.adjust.", "com.crashlytics.", "com.newrelic.",
        "com.airbnb.", "org.intellij.", "com.bumptech.", "io.sentry.",
    )
    for encoding in ['utf-16-le', 'latin-1']:
        try:
            text = manifest_data.decode(encoding, errors='ignore')
        except Exception:
            continue
        matches = re.findall(
            r'((?:com|org|net|io|app|me|dev)\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,6})', text
        )
        if not matches:
            continue
        candidates = [m for m in matches if not m.startswith(LIBRARY_PREFIXES)]
        if candidates:
            return candidates[0]
    return "Unknown"


def analyze_apk(file_data, file_name):
    result = AnalysisResult(file_name=file_name, file_size_mb=round(len(file_data) / (1024 * 1024), 2))
    try:
        apk_io = BytesIO(file_data)
        with zipfile.ZipFile(apk_io, 'r') as apk:
            all_files = apk.namelist()
            _scan_pairip_files(all_files, result)
            _scan_dex_files(apk, all_files, result)
            _scan_manifest_package_name(apk, result)
            _scan_meta_inf(apk, all_files, result)
    except zipfile.BadZipFile:
        result.error = "Invalid APK file — not a valid ZIP archive."
        return result
    except Exception as e:
        result.error = f"Error analyzing APK: {e}"
        return result
    _classify_risk(result)
    return result


def _scan_pairip_files(all_files, result):
    for file_path in all_files:
        basename = file_path.split("/")[-1]
        if basename in PAIRIP_FILE_INDICATORS:
            parts = file_path.split("/")
            arch = parts[1] if len(parts) >= 3 else "unknown"
            finding = Finding(
                category="Auto Protection (pairip)", source_file=file_path,
                pattern_matched=basename, detail=f"Native library found: {file_path} (arch: {arch})",
            )
            result.auto_protection.findings.append(finding)
            result.all_findings.append(finding)


def _scan_dex_files(apk, all_files, result):
    dex_files = sorted(f for f in all_files if f.endswith('.dex'))
    for dex_name in dex_files:
        dex_data = apk.read(dex_name)
        dex_text = dex_data.decode('latin-1')

        for pattern_list in [INTEGRITY_API_CLASSES, INTEGRITY_TOKEN_METHODS,
                             INTEGRITY_VERDICT_FIELD_NAMES, SIDELOAD_ENFORCEMENT_STRINGS]:
            findings = _search_text(dex_text, pattern_list, dex_name, "Play Integrity API")
            result.play_integrity.findings.extend(findings)
            result.all_findings.extend(findings)

        findings = _search_text(dex_text, SAFETYNET_CLASS_PATHS, dex_name, "SafetyNet (Legacy)")
        result.safetynet.findings.extend(findings)
        result.all_findings.extend(findings)

        findings = _search_text(dex_text, FIREBASE_PLAY_INTEGRITY_PROVIDER, dex_name, "Firebase App Check")
        result.firebase_appcheck.findings.extend(findings)
        result.all_findings.extend(findings)

        findings = _search_text(dex_text, FIREBASE_APPCHECK_INFORMATIONAL, dex_name, "Firebase App Check (informational)")
        result.informational.findings.extend(findings)
        result.all_findings.extend(findings)

        findings = _search_text(dex_text, PLAY_ASSET_DELIVERY_INDICATORS, dex_name, "Play Asset Delivery (informational)")
        result.informational.findings.extend(findings)
        result.all_findings.extend(findings)


def _scan_manifest_package_name(apk, result):
    try:
        manifest_data = apk.read('AndroidManifest.xml')
    except KeyError:
        return
    result.package_name = _extract_package_name_from_binary_manifest(manifest_data)


def _scan_meta_inf(apk, all_files, result):
    meta_files = [f for f in all_files if f.startswith('META-INF/') or f.endswith('.properties')]
    for file_path in meta_files:
        try:
            data = apk.read(file_path)
            if len(data) > 1_000_000:
                continue
            text = data.decode('latin-1')
        except Exception:
            continue
        for pattern in META_INF_INDICATORS:
            if pattern in text:
                finding = Finding(
                    category="Dependencies (informational)", source_file=file_path,
                    pattern_matched=pattern, detail=f"Dependency reference in {file_path}",
                )
                result.informational.findings.append(finding)
                result.all_findings.append(finding)


def _classify_risk(result):
    result.auto_protection.detected = len(result.auto_protection.findings) > 0
    result.play_integrity.detected = len(result.play_integrity.findings) > 0
    result.firebase_appcheck.detected = len(result.firebase_appcheck.findings) > 0
    result.safetynet.detected = len(result.safetynet.findings) > 0
    result.informational.detected = len(result.informational.findings) > 0

    if result.auto_protection.detected:
        archs = set()
        for f in result.auto_protection.findings:
            parts = f.source_file.split("/")
            if len(parts) >= 3:
                archs.add(parts[1])
        arch_str = ", ".join(sorted(archs)) if archs else "detected"
        result.auto_protection.summary = f"pairip native library found ({arch_str})"

    if result.play_integrity.detected:
        matched = {f.pattern_matched for f in result.play_integrity.findings}
        has_standard = any("Standard" in p for p in matched)
        api_type = "Standard API" if has_standard else "Classic API"
        parts_list = [api_type]
        if any(p in matched for p in INTEGRITY_TOKEN_METHODS):
            parts_list.append("token requests")
        if any(p in matched for p in INTEGRITY_VERDICT_FIELD_NAMES):
            parts_list.append("verdict inspection")
        if any(p in matched for p in SIDELOAD_ENFORCEMENT_STRINGS):
            parts_list.append("sideload enforcement")
        result.play_integrity.summary = ", ".join(parts_list)

    if result.firebase_appcheck.detected:
        result.firebase_appcheck.summary = "Firebase App Check with Play Integrity provider"
    if result.safetynet.detected:
        result.safetynet.summary = "Legacy SafetyNet API detected (deprecated)"
    if result.informational.detected:
        result.informational.summary = f"{len(result.informational.findings)} informational indicator(s)"

    integrity_matched = {f.pattern_matched for f in result.play_integrity.findings}
    has_api_classes = any(p in integrity_matched for p in INTEGRITY_API_CLASSES)
    has_token_methods = has_api_classes and any(p in integrity_matched for p in INTEGRITY_TOKEN_METHODS)
    has_verdict_fields = has_api_classes and any(p in integrity_matched for p in INTEGRITY_VERDICT_FIELD_NAMES)
    has_sideload_enforcement = has_api_classes and any(p in integrity_matched for p in SIDELOAD_ENFORCEMENT_STRINGS)

    if result.auto_protection.detected:
        result.risk_level = RiskLevel.CRITICAL
        result.risk_description = RISK_DESCRIPTIONS[RiskLevel.CRITICAL]
    elif has_api_classes and has_sideload_enforcement:
        result.risk_level = RiskLevel.HIGH
        result.risk_description = (
            "App explicitly checks for sideloaded installs (UNRECOGNIZED_VERSION / "
            "GET_LICENSED found). Sideloading will likely trigger a block or redirect to the Play Store."
        )
    elif has_api_classes and has_token_methods and has_verdict_fields:
        result.risk_level = RiskLevel.HIGH
        result.risk_description = (
            "App requests integrity tokens and inspects verdict fields. "
            "Sideloaded installs will likely be blocked or degraded."
        )
    elif has_api_classes and has_token_methods:
        result.risk_level = RiskLevel.MEDIUM
        result.risk_description = RISK_DESCRIPTIONS[RiskLevel.MEDIUM]
    elif result.firebase_appcheck.detected:
        result.risk_level = RiskLevel.MEDIUM
        result.risk_description = (
            "Firebase App Check uses Play Integrity as its provider. "
            "May block API access for sideloaded installs."
        )
    elif has_api_classes:
        result.risk_level = RiskLevel.LOW
        result.risk_description = RISK_DESCRIPTIONS[RiskLevel.LOW]
    elif result.safetynet.detected:
        result.risk_level = RiskLevel.LOW
        result.risk_description = "Legacy SafetyNet detected (deprecated). May still affect sideloaded installs."
    else:
        result.risk_level = RiskLevel.NONE
        result.risk_description = RISK_DESCRIPTIONS[RiskLevel.NONE]
