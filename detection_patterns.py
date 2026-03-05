"""All detection string patterns organized by category."""

# =============================================================================
# Layer 1: Auto Protection / pairip Detection (MOST IMPORTANT)
# Detection is file-listing only: check for libpairip.so in the APK ZIP entries.
# =============================================================================

PAIRIP_FILE_PATTERNS = [
    "libpairip.so",
    "libpairipcore.so",
]

# DEX patterns limited to specific obfuscated class paths (no short strings)
PAIRIP_DEX_PATTERNS = [
    "com.google.android.play.core.integrity.al",
    "com/google/android/play/core/integrity/al",
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

# Only long, unique-to-Play-Integrity field names and verdict values.
# Removed short/generic strings like LICENSED, UNLICENSED, UNEVALUATED, NO_LICENSE
# that match Apache license text, npm metadata, etc.
INTEGRITY_VERDICT_PATTERNS = [
    "appRecognitionVerdict",
    "deviceRecognitionVerdict",
    "appLicensingVerdict",
    "PLAY_RECOGNIZED",
    "UNRECOGNIZED_VERSION",
    "GET_LICENSED",
]

# Only the unique field name — individual enum values are too generic.
INTEGRITY_APP_ACCESS_RISK_PATTERNS = [
    "appAccessRiskVerdict",
]

# Combined sideload-specific verdicts (subset used for risk escalation)
SIDELOAD_BLOCK_VERDICTS = [
    "UNRECOGNIZED_VERSION",
    "GET_LICENSED",
]

# =============================================================================
# Layer 3: Legacy SafetyNet Detection
# Full class paths only — no short standalone strings.
# =============================================================================

SAFETYNET_PATTERNS = [
    "com/google/android/gms/safetynet/SafetyNet",
    "com/google/android/gms/safetynet/SafetyNetClient",
    "com/google/android/gms/safetynet/SafetyNetApi",
]

# =============================================================================
# Layer 4: Firebase App Check Detection
# Only the Play Integrity-specific provider triggers risk scoring.
# =============================================================================

FIREBASE_APPCHECK_PATTERNS = [
    "com/google/firebase/appcheck/playintegrity/PlayIntegrityAppCheckProviderFactory",
]

# =============================================================================
# Layer 5: Manifest and Resource Analysis
# =============================================================================

MANIFEST_PLAY_CORE_PATTERNS = [
    "com.google.android.play.core.assetpacks",
]

PLAY_ASSET_DELIVERY_PATTERNS = [
    "com/google/android/play/core/assetpacks/AssetPackManager",
    "com/google/android/play/core/assetpacks/AssetPackStates",
]

META_INF_PATTERNS = [
    "play-services-integrity",
]
