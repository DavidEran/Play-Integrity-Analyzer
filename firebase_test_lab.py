"""Firebase Test Lab integration for cloud device testing.

Provides a simple interface to run APK sideload tests on real and virtual
devices via Google Cloud's Firebase Test Lab.  Users supply a service-account
JSON key; the module handles upload, test creation, polling, and result
retrieval.

Required GCP setup (one-time):
    1. Enable the Cloud Testing API and Cloud Tool Results API.
    2. Create a service account with roles:
       - Cloud Test Service Agent  (roles/cloudtestservice.testAdmin)
       - Storage Admin              (roles/storage.admin)  — or scoped to bucket
    3. Download the JSON key.
"""

import io
import json
import re
import time
import uuid
from datetime import datetime, timezone

from google.auth.transport.requests import Request
from google.oauth2 import service_account
from googleapiclient import discovery
from google.cloud import storage


# ---------------------------------------------------------------------------
# Popular devices — curated subset shown by default in the UI
# ---------------------------------------------------------------------------

POPULAR_DEVICES = [
    {"id": "redfin", "name": "Pixel 5", "api_levels": [30]},
    {"id": "oriole", "name": "Pixel 6", "api_levels": [31, 33]},
    {"id": "cheetah", "name": "Pixel 7", "api_levels": [33]},
    {"id": "shiba", "name": "Pixel 8", "api_levels": [34]},
    {"id": "tokay", "name": "Pixel 9", "api_levels": [35]},
    {"id": "caiman", "name": "Pixel 9 Pro", "api_levels": [35]},
    {"id": "samsung_s21", "name": "Samsung Galaxy S21", "api_levels": [30]},
    {"id": "samsung_s23", "name": "Samsung Galaxy S23", "api_levels": [33]},
    {"id": "samsung_s24", "name": "Samsung Galaxy S24", "api_levels": [34]},
    {"id": "a52sxq", "name": "Samsung Galaxy A52", "api_levels": [30]},
    {"id": "MediumPhone.arm", "name": "Virtual Medium Phone (ARM)", "api_levels": [30, 33, 34]},
    {"id": "SmallPhone.arm", "name": "Virtual Small Phone (ARM)", "api_levels": [30, 33, 34]},
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
]


def _build_credentials(sa_json: dict):
    """Build Google credentials from a parsed service-account JSON dict."""
    creds = service_account.Credentials.from_service_account_info(
        sa_json, scopes=_SCOPES,
    )
    creds.refresh(Request())
    return creds


def _bucket_name(project_id: str) -> str:
    return f"{project_id}-sideload-tests"


# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------


class FirebaseTestLab:
    """Thin wrapper around the Cloud Testing + GCS APIs."""

    def __init__(self, service_account_info: dict):
        self._sa_info = service_account_info
        self._project_id = service_account_info["project_id"]
        self._creds = _build_credentials(service_account_info)
        self._testing = discovery.build(
            "testing", "v1", credentials=self._creds,
        )
        self._tool_results = discovery.build(
            "toolresults", "v1beta3", credentials=self._creds,
        )
        self._storage = storage.Client(
            project=self._project_id, credentials=self._creds,
        )

    # -- public properties ---------------------------------------------------

    @property
    def project_id(self) -> str:
        return self._project_id

    # -- device catalog ------------------------------------------------------

    def list_available_devices(self):
        """Fetch the full device catalog from Firebase Test Lab.

        Returns a list of dicts with id, name, brand, api_levels, form
        (PHYSICAL / VIRTUAL).
        """
        resp = (
            self._testing.testEnvironmentCatalog()
            .get(environmentType="ANDROID", projectId=self._project_id)
            .execute()
        )
        models = resp.get("androidDeviceCatalog", {}).get("models", [])
        devices = []
        for m in models:
            api_levels = sorted(int(v) for v in m.get("supportedVersionIds", []))
            devices.append({
                "id": m["id"],
                "name": m.get("name", m["id"]),
                "brand": m.get("manufacturer", ""),
                "form": m.get("form", ""),
                "api_levels": api_levels,
            })
        return devices

    # -- GCS helpers ---------------------------------------------------------

    def _ensure_bucket(self):
        """Create the GCS bucket if it doesn't exist. Returns bucket name."""
        name = _bucket_name(self._project_id)
        bucket = self._storage.bucket(name)
        if not bucket.exists():
            bucket.storage_class = "STANDARD"
            self._storage.create_bucket(bucket, location="us-central1")
            # Set lifecycle: auto-delete objects after 1 day
            bucket.reload()
            bucket.lifecycle_rules = [
                {"action": {"type": "Delete"}, "condition": {"age": 1}},
            ]
            bucket.patch()
        return name

    def _upload_apk(self, apk_bytes: bytes, filename: str) -> str:
        """Upload APK bytes to GCS and return the gs:// URI."""
        bucket_name = self._ensure_bucket()
        blob_name = f"apks/{uuid.uuid4().hex[:12]}_{filename}"
        bucket = self._storage.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        blob.upload_from_file(io.BytesIO(apk_bytes), content_type="application/vnd.android.package-archive")
        return f"gs://{bucket_name}/{blob_name}"

    # -- test execution ------------------------------------------------------

    def create_robo_test(
        self,
        apk_bytes: bytes,
        apk_filename: str,
        device_id: str,
        api_level: int,
        timeout_sec: int = 120,
        locale: str = "en",
        orientation: str = "portrait",
    ) -> dict:
        """Upload APK and create a Robo test matrix.

        Returns the full testMatrix response (includes ``testMatrixId``).
        """
        gcs_uri = self._upload_apk(apk_bytes, apk_filename)
        bucket_name = self._ensure_bucket()

        body = {
            "projectId": self._project_id,
            "testSpecification": {
                "testTimeout": f"{timeout_sec}s",
                "androidRoboTest": {
                    "appApk": {"gcsPath": gcs_uri},
                },
            },
            "environmentMatrix": {
                "androidDeviceList": {
                    "androidDevices": [
                        {
                            "androidModelId": device_id,
                            "androidVersionId": str(api_level),
                            "locale": locale,
                            "orientation": orientation,
                        }
                    ]
                }
            },
            "resultStorage": {
                "googleCloudStorage": {
                    "gcsPath": f"gs://{bucket_name}/results/",
                },
            },
        }

        resp = (
            self._testing.projects()
            .testMatrices()
            .create(projectId=self._project_id, body=body)
            .execute()
        )
        return resp

    def get_matrix_state(self, matrix_id: str) -> dict:
        """Poll the test matrix for its current state.

        Returns the full testMatrix resource.  Key fields:
        - ``state``: VALIDATING | PENDING | RUNNING | FINISHED | ERROR | ...
        - ``testExecutions``: list of per-device results once finished.
        """
        return (
            self._testing.projects()
            .testMatrices()
            .get(projectId=self._project_id, testMatrixId=matrix_id)
            .execute()
        )

    def wait_for_completion(self, matrix_id: str, poll_interval: int = 10,
                            max_wait: int = 600, progress_callback=None) -> dict:
        """Block until the test matrix finishes or times out.

        *progress_callback* is called with ``(state_str, elapsed_sec)`` each
        poll cycle, useful for updating a Streamlit UI.

        Returns the final testMatrix resource.
        """
        start = time.monotonic()
        terminal_states = {"FINISHED", "ERROR", "UNSUPPORTED_ENVIRONMENT",
                           "INCOMPATIBLE_ENVIRONMENT", "CANCELLED", "INVALID"}

        while True:
            matrix = self.get_matrix_state(matrix_id)
            state = matrix.get("state", "UNKNOWN")
            elapsed = int(time.monotonic() - start)

            if progress_callback:
                progress_callback(state, elapsed)

            if state in terminal_states:
                return matrix

            if elapsed > max_wait:
                return matrix  # caller decides how to handle timeout

            time.sleep(poll_interval)

    # -- result parsing with root-cause analysis ------------------------------

    def _resolve_results_dir(self, matrix: dict, execution: dict) -> str:
        """Find the GCS results directory for an execution.

        Firebase Test Lab stores results at a path like:
            gs://bucket/results/<matrixId>/<executionId>/
        The ``resultStorage`` field lives on the **matrix**, not on
        individual executions.  We combine the matrix-level GCS prefix
        with the execution's ``id`` (or ``toolResultsStep.executionId``)
        to build the full path.
        """
        # 1. Matrix-level resultStorage (always present)
        matrix_gcs = (
            matrix.get("resultStorage", {})
            .get("googleCloudStorage", {})
            .get("gcsPath", "")
        )
        if not matrix_gcs:
            return ""

        # Normalise trailing slash
        if not matrix_gcs.endswith("/"):
            matrix_gcs += "/"

        # 2. Try to find the execution-specific subdirectory.
        #    The API nests results under <matrixId>/<executionId>/
        exec_id = execution.get("id", "")
        matrix_id = matrix.get("testMatrixId", "")

        # Try the most specific path first, then fall back
        candidates = []
        if matrix_id and exec_id:
            candidates.append(f"{matrix_gcs}{matrix_id}/{exec_id}/")
        if matrix_id:
            candidates.append(f"{matrix_gcs}{matrix_id}/")
        candidates.append(matrix_gcs)

        # Check which prefix actually has blobs in it
        for candidate in candidates:
            if not candidate.startswith("gs://"):
                continue
            path = candidate[5:]
            parts = path.split("/", 1)
            bucket_name = parts[0]
            prefix = parts[1] if len(parts) > 1 else ""
            try:
                bucket = self._storage.bucket(bucket_name)
                # Just check if there's at least one blob
                page = bucket.list_blobs(prefix=prefix, max_results=1)
                if any(True for _ in page):
                    return candidate
            except Exception:
                continue

        # Fall back to the matrix-level path even if empty
        return matrix_gcs

    def parse_results(self, matrix: dict) -> list[dict]:
        """Convert a finished testMatrix into result dicts with root-cause
        analysis based on downloaded logcat and activity transitions.

        Each dict has keys: device, api_level, outcome, verdict,
        verdict_summary, root_causes, logcat_excerpt, video_url,
        screenshot_urls, logcat_url, duration_seconds.
        """
        results = []
        for execution in matrix.get("testExecutions", []):
            env = execution.get("environment", {}).get("androidDevice", {})
            device_id = env.get("androidModelId", "unknown")
            api_level = env.get("androidVersionId", "?")
            step_state = execution.get("state", "UNKNOWN")

            # Handle infra errors before downloading artifacts
            if step_state in (
                "ERROR", "UNSUPPORTED_ENVIRONMENT",
                "INCOMPATIBLE_ENVIRONMENT",
            ):
                error_msg = execution.get("testDetails", {}).get(
                    "errorMessage", "Test infrastructure error",
                )
                results.append({
                    "device": device_id,
                    "api_level": api_level,
                    "outcome": step_state,
                    "verdict": "FAIL",
                    "verdict_summary": f"Test Lab error: {error_msg}",
                    "root_causes": [],
                    "logcat_excerpt": "",
                    "video_url": None,
                    "screenshot_urls": [],
                    "logcat_url": None,
                    "duration_seconds": 0,
                })
                continue

            # Resolve the correct GCS directory for this execution
            results_dir = self._resolve_results_dir(matrix, execution)
            artifacts = self._collect_artifacts(results_dir)
            logcat_text = artifacts.get("logcat_text", "")

            # Run root-cause analysis on the logcat
            root_causes = _analyze_logcat(logcat_text)

            # Determine verdict
            has_blocking = bool(root_causes)

            # Check for crash with no Play Store involvement
            crash_patterns = re.compile(
                r"FATAL EXCEPTION|AndroidRuntime.*?Error|"
                r"Process.*?has died|Force finishing activity",
                re.IGNORECASE,
            )
            has_crash = bool(crash_patterns.search(logcat_text))

            if has_blocking:
                verdict = "FAIL"
                categories = [rc["category_label"] for rc in root_causes]
                verdict_summary = (
                    f"Sideload Blocked: {', '.join(categories)} detected"
                )
            elif has_crash:
                verdict = "FAIL"
                verdict_summary = "App Crash — no Play Store involvement detected"
            else:
                verdict = "PASS"
                verdict_summary = "Sideload Safe — no blocking detected"

            # Build a concise logcat excerpt (relevant lines only)
            logcat_excerpt = _build_logcat_excerpt(logcat_text, root_causes)

            results.append({
                "device": device_id,
                "api_level": api_level,
                "outcome": step_state,
                "verdict": verdict,
                "verdict_summary": verdict_summary,
                "root_causes": root_causes,
                "logcat_excerpt": logcat_excerpt,
                "video_url": artifacts.get("video"),
                "screenshot_urls": artifacts.get("screenshots", []),
                "logcat_url": artifacts.get("logcat_url"),
                "duration_seconds": 0,
            })

        return results

    def _collect_artifacts(self, gcs_dir: str) -> dict:
        """Download logcat text and collect signed URLs for media artifacts.

        Firebase Test Lab stores results with names like:
            logcat, logcat.txt, bugreport.txt, video.mp4,
            screen-0.png, screen-1.png, ...
        They may also be nested in subdirectories like
            test_cases/<testname>/ or artifacts/.
        We recursively list all blobs under the prefix and classify them.
        """
        artifacts = {
            "screenshots": [],
            "video": None,
            "logcat_url": None,
            "logcat_text": "",
        }

        if not gcs_dir or not gcs_dir.startswith("gs://"):
            return artifacts

        path = gcs_dir[5:]  # strip "gs://"
        parts = path.split("/", 1)
        bucket_name = parts[0]
        prefix = parts[1] if len(parts) > 1 else ""

        try:
            bucket = self._storage.bucket(bucket_name)
            blobs = list(bucket.list_blobs(prefix=prefix, max_results=500))

            logcat_candidates = []

            for blob in blobs:
                name_lower = blob.name.lower()
                basename = name_lower.rsplit("/", 1)[-1]

                # Video
                if basename.endswith(".mp4") or basename.startswith("video"):
                    if artifacts["video"] is None:
                        artifacts["video"] = blob.generate_signed_url(
                            expiration=3600,
                        )

                # Screenshots
                elif basename.endswith((".png", ".jpg", ".jpeg")):
                    artifacts["screenshots"].append(
                        blob.generate_signed_url(expiration=3600)
                    )

                # Logcat — collect all candidates, pick the best one after
                elif (
                    basename in ("logcat", "logcat.txt")
                    or basename.startswith("logcat")
                    or "logcat" in basename
                ) and not basename.endswith((".png", ".jpg", ".mp4")):
                    logcat_candidates.append(blob)

            # Pick the largest logcat file (most complete)
            if logcat_candidates:
                logcat_candidates.sort(
                    key=lambda b: b.size or 0, reverse=True,
                )
                best_logcat = logcat_candidates[0]
                artifacts["logcat_url"] = best_logcat.generate_signed_url(
                    expiration=3600,
                )
                try:
                    artifacts["logcat_text"] = best_logcat.download_as_text(
                        encoding="utf-8",
                    )
                except Exception:
                    try:
                        raw = best_logcat.download_as_bytes()
                        artifacts["logcat_text"] = raw.decode(
                            "utf-8", errors="replace",
                        )
                    except Exception:
                        pass

        except Exception:
            pass  # Artifacts are best-effort

        return artifacts


# ---------------------------------------------------------------------------
# Root-cause analysis engine
# ---------------------------------------------------------------------------

# Detection categories, checked in priority order.  Each category has:
#   - logcat_patterns: regex patterns to search for in logcat text
#   - activity_patterns: regex for activity transitions (optional)
#   - category_label: human-readable name
#   - description: full explanation for the report
#   - recommendation: what to tell the developer

_DETECTION_CATEGORIES = [
    {
        "category": "play_auto_protect",
        "category_label": "Play Auto Protect",
        "logcat_patterns": [
            r"AutoProtect",
            r"Play\s*[Pp]rotect",
            r"Get this app from Play",
            r"DENY_APP",
            r"PlayAutoInstallDenyReportService",
            r"Integrity.*?sideload",
            r"com\.android\.vending.*AutoProtect",
        ],
        "activity_patterns": [
            r"com\.android\.vending.*AutoProtect",
            r"com\.android\.vending.*PlayAutoInstall",
        ],
        "description": (
            "Play Auto Protect \u2014 Google injected an install-time protection "
            "that blocks sideloaded installs. The app redirects to the Play Store "
            "with a \u2018Get this app from Play\u2019 dialog. The developer must "
            "disable Auto Protect in Play Console under App Integrity settings, "
            "or request a DT-compatible distribution."
        ),
        "recommendation": (
            "Developer must disable Auto Protect in Play Console under "
            "App Integrity settings, or request a DT-compatible distribution."
        ),
    },
    {
        "category": "play_licensing",
        "category_label": "Play Licensing (LVL)",
        "logcat_patterns": [
            r"GET_LICENSED",
            r"NOT_LICENSED",
            r"LicenseChecker",
            r"LicenseValidator",
            r"ServerManagedPolicy",
            r"license\s+check",
            r"com\.android\.vending\.licensing",
            r"ILicensingService",
        ],
        "activity_patterns": [
            r"com\.android\.vending.*[Ll]icense",
        ],
        "description": (
            "Play Licensing (LVL) \u2014 The app uses Google Play\u2019s License "
            "Verification Library. Sideloaded installs return NOT_LICENSED because "
            "the user has no Play Store purchase record. The developer must remove "
            "or relax the LVL check for DT preload builds."
        ),
        "recommendation": (
            "Developer must remove or relax the LVL check for DT preload builds."
        ),
    },
    {
        "category": "play_integrity_api",
        "category_label": "Play Integrity API",
        "logcat_patterns": [
            r"IntegrityService",
            r"IntegrityManager",
            r"requestIntegrityToken",
            r"play\.core\.integrity",
            r"INTEGRITY_",
            r"integrity\s+verdict",
            r"attestation.*integrity",
            r"com\.google\.android\.play\.core\.integrity",
        ],
        "activity_patterns": [],
        "description": (
            "Play Integrity API \u2014 The app requests a Play Integrity token and "
            "the server-side validation rejected the sideloaded install. The "
            "developer must allowlist DT\u2019s installer package or adjust their "
            "integrity verdict handling."
        ),
        "recommendation": (
            "Developer must allowlist DT\u2019s installer package or adjust "
            "their integrity verdict handling."
        ),
    },
    {
        "category": "installer_source_check",
        "category_label": "Installer Source Check",
        "logcat_patterns": [
            r"getInstallingPackageName",
            r"getInstallSource",
            r"installSource",
            r"invalid\s+installer",
            r"unknown\s+source",
            r"installer.*com\.android\.vending",
            r"PackageManager.*installer",
        ],
        "activity_patterns": [],
        "description": (
            "Installer Source Check \u2014 The app explicitly checks which store "
            "installed it and blocks non-Play Store installs. The developer must "
            "allowlist DT\u2019s installer package name."
        ),
        "recommendation": (
            "Developer must allowlist DT\u2019s installer package name."
        ),
    },
    {
        "category": "firebase_app_check",
        "category_label": "Firebase App Check",
        "logcat_patterns": [
            r"AppCheck",
            r"app\s*check",
            r"attestation\s+failed",
            r"firebaseappcheck",
            r"403.*firebase",
            r"firebase.*403",
        ],
        "activity_patterns": [],
        "description": (
            "Firebase App Check \u2014 The app\u2019s backend APIs reject requests "
            "from sideloaded installs because App Check attestation fails. The "
            "developer must configure App Check to accept DT-distributed builds."
        ),
        "recommendation": (
            "Developer must configure App Check to accept DT-distributed builds."
        ),
    },
    {
        "category": "play_store_redirect",
        "category_label": "Play Store Redirect (Generic)",
        "logcat_patterns": [
            r"market://details",
            r"play\.google\.com/store",
            r"ACTION_VIEW.*market",
            r"com\.android\.vending",
            r"Starting.*com\.android\.vending",
        ],
        "activity_patterns": [
            r"com\.android\.vending",
        ],
        "description": (
            "Play Store Redirect \u2014 The app redirects to the Google Play Store "
            "listing. Could not determine the specific mechanism. Manual "
            "investigation recommended. See logcat excerpt below."
        ),
        "recommendation": (
            "Could not determine the specific mechanism. Manual investigation "
            "recommended."
        ),
    },
]


def _analyze_logcat(logcat_text: str) -> list[dict]:
    """Scan logcat text for all matching anti-sideload categories.

    Returns a list of root-cause dicts, each with:
        category, category_label, description, recommendation, evidence
    """
    if not logcat_text:
        return []

    root_causes = []
    # Track which generic-redirect evidence lines were already claimed
    # by a more specific category so we don't double-count.
    claimed_evidence_lines: set[str] = set()

    for cat in _DETECTION_CATEGORIES:
        evidence_lines: list[str] = []

        # Search logcat line-by-line for pattern matches
        for pattern_str in cat["logcat_patterns"]:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for line in logcat_text.splitlines():
                if pattern.search(line):
                    stripped = line.strip()
                    if stripped and stripped not in evidence_lines:
                        evidence_lines.append(stripped)

        # Also check activity transition patterns
        for pattern_str in cat.get("activity_patterns", []):
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for line in logcat_text.splitlines():
                if pattern.search(line):
                    stripped = line.strip()
                    if stripped and stripped not in evidence_lines:
                        evidence_lines.append(stripped)

        if not evidence_lines:
            continue

        # For the generic "play_store_redirect" category, skip if ALL its
        # evidence lines were already claimed by a more specific category.
        if cat["category"] == "play_store_redirect":
            unique = [l for l in evidence_lines if l not in claimed_evidence_lines]
            if not unique:
                continue
            evidence_lines = unique

        # Record these lines as claimed
        for l in evidence_lines:
            claimed_evidence_lines.add(l)

        # Cap evidence to 20 lines per category for readability
        root_causes.append({
            "category": cat["category"],
            "category_label": cat["category_label"],
            "description": cat["description"],
            "recommendation": cat["recommendation"],
            "evidence": evidence_lines[:20],
        })

    return root_causes


def _build_logcat_excerpt(logcat_text: str, root_causes: list[dict]) -> str:
    """Build a concise logcat excerpt containing only the lines relevant
    to the detected root causes, plus a few lines of surrounding context.
    """
    if not logcat_text or not root_causes:
        # If no root causes but we have logcat, return last 50 lines
        if logcat_text:
            lines = logcat_text.splitlines()
            return "\n".join(lines[-50:])
        return ""

    # Collect all evidence line texts
    evidence_texts: set[str] = set()
    for rc in root_causes:
        for line in rc["evidence"]:
            evidence_texts.add(line.strip())

    # Find matching line indices and include 2 lines of context each side
    all_lines = logcat_text.splitlines()
    relevant_indices: set[int] = set()
    for i, line in enumerate(all_lines):
        if line.strip() in evidence_texts:
            for j in range(max(0, i - 2), min(len(all_lines), i + 3)):
                relevant_indices.add(j)

    if not relevant_indices:
        return "\n".join(all_lines[-50:])

    # Build excerpt with "..." gaps between non-contiguous sections
    sorted_indices = sorted(relevant_indices)
    excerpt_lines: list[str] = []
    prev_idx = -2
    for idx in sorted_indices:
        if idx > prev_idx + 1:
            excerpt_lines.append("...")
        excerpt_lines.append(all_lines[idx])
        prev_idx = idx

    # Cap at 200 lines
    return "\n".join(excerpt_lines[:200])


# ---------------------------------------------------------------------------
# Quick validation helper (used by the UI before running a full test)
# ---------------------------------------------------------------------------


def validate_service_account(sa_json: dict) -> tuple[bool, str]:
    """Check that a service-account JSON is structurally valid and can auth.

    Returns (ok, message).
    """
    required_keys = {"type", "project_id", "private_key", "client_email"}
    missing = required_keys - set(sa_json.keys())
    if missing:
        return False, f"Missing keys in service account JSON: {missing}"

    if sa_json.get("type") != "service_account":
        return False, f"Expected type 'service_account', got '{sa_json.get('type')}'"

    try:
        creds = _build_credentials(sa_json)
        # Try a lightweight API call
        testing = discovery.build("testing", "v1", credentials=creds)
        testing.testEnvironmentCatalog().get(
            environmentType="ANDROID", projectId=sa_json["project_id"],
        ).execute()
        return True, f"Authenticated as {sa_json['client_email']} (project: {sa_json['project_id']})"
    except Exception as exc:
        return False, f"Authentication failed: {exc}"
