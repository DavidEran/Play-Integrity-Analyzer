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

    # -- result parsing ------------------------------------------------------

    def parse_results(self, matrix: dict) -> list[dict]:
        """Convert a finished testMatrix into a list of result dicts
        compatible with the existing sideload-test result format.

        Each dict has keys: device, api_level, outcome, verdict,
        verdict_reason, video_url, screenshot_urls, logcat_url,
        duration_seconds.
        """
        results = []
        for execution in matrix.get("testExecutions", []):
            env = execution.get("environment", {}).get("androidDevice", {})
            device_id = env.get("androidModelId", "unknown")
            api_level = env.get("androidVersionId", "?")

            outcome = execution.get("testDetails", {}).get("errorMessage", "")
            tool_outputs = execution.get("toolResultsStep", {})
            step_state = execution.get("state", "UNKNOWN")

            # Map Firebase outcome to our verdict scheme
            verdict, reason = self._map_outcome(execution)

            # Collect artifact URLs from GCS
            result_storage = execution.get("resultStorage", {}).get(
                "googleCloudStorage", {}
            )
            results_dir = result_storage.get("gcsPath", "")

            artifact_urls = self._collect_artifacts(results_dir)

            results.append({
                "device": device_id,
                "api_level": api_level,
                "outcome": step_state,
                "verdict": verdict,
                "verdict_reason": reason,
                "video_url": artifact_urls.get("video"),
                "screenshot_urls": artifact_urls.get("screenshots", []),
                "logcat_url": artifact_urls.get("logcat"),
                "duration_seconds": 0,
            })

        return results

    def _map_outcome(self, execution: dict) -> tuple[str, str]:
        """Map a Firebase Test Lab execution result to PASS/FAIL/REVIEW."""
        state = execution.get("state", "")

        if state in ("ERROR", "UNSUPPORTED_ENVIRONMENT", "INCOMPATIBLE_ENVIRONMENT"):
            error_msg = execution.get("testDetails", {}).get(
                "errorMessage", "Test infrastructure error"
            )
            return "FAIL", f"Test Lab error: {error_msg}"

        # Check the test issue details if available
        details = execution.get("testDetails", {})
        progress = details.get("progressMessages", [])

        # When finished, check the tool results outcome
        tool_step = execution.get("toolResultsStep", {})
        outcome_summary = ""

        # The outcome is in the testExecution directly for v1
        test_details = execution.get("testDetails", {})

        # Check for specific failure signals in progress messages
        progress_text = " ".join(progress).lower()
        if any(kw in progress_text for kw in [
            "play protect", "license", "integrity", "not installed",
            "play store", "anti-sideload",
        ]):
            return "FAIL", f"Anti-sideload signal detected in test output"

        if state == "FINISHED":
            # No obvious failure signals — but we can't inspect UI keywords
            # from the robo test alone, so REVIEW if there were any issues
            if "error" in progress_text or "crash" in progress_text:
                return "REVIEW", "App crashed or errored during robo test"
            return "PASS", "Robo test completed — no blocking detected"

        return "REVIEW", f"Test ended in state: {state}"

    def _collect_artifacts(self, gcs_dir: str) -> dict:
        """List artifact URLs from a GCS results directory."""
        artifacts = {"screenshots": [], "video": None, "logcat": None}

        if not gcs_dir or not gcs_dir.startswith("gs://"):
            return artifacts

        # Parse bucket and prefix from gs:// URI
        path = gcs_dir[5:]  # strip "gs://"
        parts = path.split("/", 1)
        bucket_name = parts[0]
        prefix = parts[1] if len(parts) > 1 else ""

        try:
            bucket = self._storage.bucket(bucket_name)
            blobs = list(bucket.list_blobs(prefix=prefix, max_results=100))

            for blob in blobs:
                name_lower = blob.name.lower()
                public_url = blob.public_url

                if name_lower.endswith(".mp4") or "video" in name_lower:
                    # Generate a signed URL instead (bucket is private)
                    artifacts["video"] = blob.generate_signed_url(
                        expiration=3600,
                    )
                elif name_lower.endswith(".png") or name_lower.endswith(".jpg"):
                    artifacts["screenshots"].append(
                        blob.generate_signed_url(expiration=3600)
                    )
                elif "logcat" in name_lower:
                    artifacts["logcat"] = blob.generate_signed_url(
                        expiration=3600,
                    )
        except Exception:
            pass  # Artifacts are best-effort

        return artifacts


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
