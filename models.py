"""Data classes for analysis results."""

from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    NONE = "NONE"


RISK_COLORS = {
    RiskLevel.CRITICAL: "#8B0000",
    RiskLevel.HIGH: "#DC3545",
    RiskLevel.MEDIUM: "#FD7E14",
    RiskLevel.LOW: "#FFC107",
    RiskLevel.INFO: "#17A2B8",
    RiskLevel.NONE: "#28A745",
}

RISK_DESCRIPTIONS = {
    RiskLevel.CRITICAL: (
        "Auto Protection is enabled. Google injects pairip library which "
        "blocks unlicensed installs automatically. Sideloading WILL be blocked. "
        "Developer must disable Auto Protection in Play Console and upload a new build."
    ),
    RiskLevel.HIGH: (
        "App explicitly checks for sideloaded installs and likely redirects "
        "to Play Store. Developer needs to handle UNLICENSED verdicts gracefully."
    ),
    RiskLevel.MEDIUM: (
        "App requests integrity tokens. Behavior depends on server-side "
        "verdict handling which cannot be determined from static analysis alone."
    ),
    RiskLevel.LOW: (
        "Play Integrity library is bundled but no active enforcement detected "
        "in client code. May use server-side checking or may not enforce at all."
    ),
    RiskLevel.INFO: (
        "Uses Play Asset Delivery. Sideloaded installs may fail to download "
        "on-demand assets, causing crashes or missing content."
    ),
    RiskLevel.NONE: (
        "No integrity enforcement detected. Sideloading should work normally."
    ),
}

RISK_RECOMMENDATIONS = {
    RiskLevel.CRITICAL: (
        "**Disable Auto Protection** in Play Console → App Integrity → Remove protection. "
        "Upload a new build — the pairip library is injected at upload time so changes "
        "won't take effect until a new APK/AAB is uploaded."
    ),
    RiskLevel.HIGH: (
        "Modify integrity verdict handling to allow UNLICENSED installs from known installers. "
        "Use `appAccessRiskVerdict` to distinguish known installers (Digital Turbine, Galaxy Store) "
        "from unknown sideloading."
    ),
    RiskLevel.MEDIUM: (
        "Verify server-side verdict handling allows third-party installers. "
        "Request the developer to allowlist known installer package names."
    ),
    RiskLevel.LOW: (
        "Library is present but likely inactive on the client side. Monitor for updates "
        "that may activate enforcement. Consider verifying with a test sideload."
    ),
    RiskLevel.INFO: (
        "Ensure that on-demand asset packs are available or bundled in the sideloaded APK. "
        "Consider using a universal APK that includes all assets."
    ),
    RiskLevel.NONE: (
        "No action needed. App should sideload and run normally."
    ),
}

CODE_SNIPPET = '''\
// Instead of blocking UNLICENSED installs:
if (appLicensingVerdict.equals("LICENSED") ||
     appLicensingVerdict.equals("UNLICENSED")) {
    // Allow app usage for both Play Store and known third-party installers
} else {
    // Handle UNEVALUATED or unknown values
}'''


@dataclass
class Finding:
    """A single detection finding."""
    category: str
    source_file: str
    pattern_matched: str
    detail: str = ""


@dataclass
class LayerResult:
    """Results for a single detection layer."""
    name: str
    detected: bool = False
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""


@dataclass
class AnalysisResult:
    """Complete analysis result for an APK."""
    package_name: str = "Unknown"
    file_name: str = ""
    file_size_mb: float = 0.0
    risk_level: RiskLevel = RiskLevel.NONE
    risk_description: str = ""
    auto_protection: LayerResult = field(default_factory=lambda: LayerResult("Auto Protection (pairip)"))
    play_integrity: LayerResult = field(default_factory=lambda: LayerResult("Play Integrity API"))
    firebase_appcheck: LayerResult = field(default_factory=lambda: LayerResult("Firebase App Check"))
    safetynet: LayerResult = field(default_factory=lambda: LayerResult("SafetyNet (Legacy)"))
    play_asset_delivery: LayerResult = field(default_factory=lambda: LayerResult("Play Asset Delivery"))
    manifest_analysis: LayerResult = field(default_factory=lambda: LayerResult("Manifest Analysis"))
    all_findings: list[Finding] = field(default_factory=list)
    error: str = ""
