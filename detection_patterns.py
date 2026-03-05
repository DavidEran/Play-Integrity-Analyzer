"""All detection string patterns organized by category."""

PAIRIP_FILE_INDICATORS = [
    "libpairip.so",
    "libpairipcore.so",
]

INTEGRITY_API_CLASSES = [
    "com/google/android/play/core/integrity/IntegrityManager",
    "com/google/android/play/core/integrity/IntegrityManagerFactory",
    "com/google/android/play/core/integrity/IntegrityTokenRequest",
    "com/google/android/play/core/integrity/IntegrityTokenResponse",
    "com/google/android/play/core/integrity/StandardIntegrityManager",
    "com/google/android/play/core/integrity/StandardIntegrityTokenProvider",
    "com/google/android/play/core/integrity/StandardIntegrityTokenRequest",
]

INTEGRITY_TOKEN_METHODS = [
    "requestIntegrityToken",
    "prepareIntegrityToken",
]

INTEGRITY_VERDICT_FIELD_NAMES = [
    "appRecognitionVerdict",
    "deviceRecognitionVerdict",
    "appLicensingVerdict",
    "appAccessRiskVerdict",
]

SIDELOAD_ENFORCEMENT_STRINGS = [
    "UNRECOGNIZED_VERSION",
    "GET_LICENSED",
    "PLAY_RECOGNIZED",
]

SAFETYNET_CLASS_PATHS = [
    "com/google/android/gms/safetynet/SafetyNet",
    "com/google/android/gms/safetynet/SafetyNetClient",
    "com/google/android/gms/safetynet/SafetyNetApi",
]

FIREBASE_PLAY_INTEGRITY_PROVIDER = [
    "com/google/firebase/appcheck/playintegrity/PlayIntegrityAppCheckProviderFactory",
]

FIREBASE_APPCHECK_INFORMATIONAL = [
    "com/google/firebase/appcheck/FirebaseAppCheck",
    "com/google/firebase/appcheck/AppCheckToken",
]

PLAY_ASSET_DELIVERY_INDICATORS = [
    "com/google/android/play/core/assetpacks/AssetPackManager",
    "com/google/android/play/core/assetpacks/AssetPackStates",
]

META_INF_INDICATORS = [
    "play-services-integrity",
    "play-integrity",
]
