"""All detection string patterns organized by category."""

# =============================================================================
# Layer 1: Auto Protection / pairip Detection (MOST IMPORTANT)
# =============================================================================

PAIRIP_FILE_PATTERNS = [
    "libpairip.so",
    "libpairipcore.so",
]

PAIRIP_DEX_PATTERNS = [
    "com.google.android.play.core.integrity.al",
    "com/google/android/play/core/integrity/al",
    "pairip",
]

PAIRIP_MANIFEST_PATTERNS = [
    "pairip",
    "com.google.android.play.core.missingsplits",
    "MissingSplitsDetectingApplication",
]

# =============================================================================
# Layer 2: Play Integrity API Detection (Developer-Integrated)
# =============================================================================

INTEGRITY_API_CLASS_PATTERNS = [
    "com/google/android/play/core/integrity/IntegrityManager",
    "com/google/android/play/core/integrity/IntegrityManagerFactory",
    "com/google/android/play/core/integrity/IntegrityTokenRequest",
    "com/google/android/play/core/integrity/IntegrityTokenResponse",
    "com/google/android/play/core/integrity/StandardIntegrityManager",
    "com/google/android/play/core/integrity/StandardIntegrityTokenProvider",
]

INTEGRITY_TOKEN_REQUEST_PATTERNS = [
    "requestIntegrityToken",
    "prepareIntegrityToken",
]

INTEGRITY_VERDICT_PATTERNS = [
    "appRecognitionVerdict",
    "PLAY_RECOGNIZED",
    "UNRECOGNIZED_VERSION",
    "UNEVALUATED",
    "deviceRecognitionVerdict",
    "appLicensingVerdict",
    "NO_LICENSE",
    "LICENSED",
    "UNLICENSED",
    "GET_LICENSED",
]

INTEGRITY_APP_ACCESS_RISK_PATTERNS = [
    "appAccessRiskVerdict",
    "KNOWN_INSTALLED",
    "KNOWN_CAPTURING",
    "KNOWN_CONTROLLING",
    "UNKNOWN_INSTALLED",
    "UNKNOWN_CAPTURING",
    "UNKNOWN_CONTROLLING",
]

# Combined sideload-specific verdicts (subset used for risk escalation)
SIDELOAD_BLOCK_VERDICTS = [
    "UNRECOGNIZED_VERSION",
    "GET_LICENSED",
]

# =============================================================================
# Layer 3: Legacy SafetyNet Detection
# =============================================================================

SAFETYNET_PATTERNS = [
    "com/google/android/gms/safetynet/SafetyNet",
    "com/google/android/gms/safetynet/SafetyNetClient",
    "com/google/android/gms/safetynet/SafetyNetApi",
    "SafetyNetClient",
]

# =============================================================================
# Layer 4: Firebase App Check Detection
# =============================================================================

FIREBASE_APPCHECK_PATTERNS = [
    "com/google/firebase/appcheck/FirebaseAppCheck",
    "com/google/firebase/appcheck/AppCheckToken",
    "com/google/firebase/appcheck/playintegrity/PlayIntegrityAppCheckProviderFactory",
    "FirebaseAppCheck",
    "AppCheckProviderFactory",
    "installAppCheckProviderFactory",
]

# =============================================================================
# Layer 5: Manifest and Resource Analysis
# =============================================================================

MANIFEST_PLAY_CORE_PATTERNS = [
    "com.google.android.play.core",
    "com.google.android.play.core.assetpacks",
    "com.google.android.play.core.missingsplits.MissingSplitsDetectingApplication",
    "getInstallerPackageName",
    "getInstallSourceInfo",
]

PLAY_ASSET_DELIVERY_PATTERNS = [
    "com.google.android.play.core.assetpacks",
    "AssetPackManager",
    "AssetPackStates",
    "onDemand",
]

META_INF_PATTERNS = [
    "play-services-integrity",
]
