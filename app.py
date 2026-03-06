"""Play Integrity Analyzer — Streamlit App."""

import csv
import io
import json
import os
import shutil
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from analyzer import analyze_apk
from models import AnalysisResult, RiskLevel, RISK_COLORS, RISK_RECOMMENDATIONS, CODE_SNIPPET

st.set_page_config(page_title="Play Integrity Analyzer", page_icon="🔍", layout="wide")
st.title("Play Integrity Analyzer")
st.caption("Detect Google Play Integrity API and Auto Protection (pairip) in Android APKs to assess sideloading risk.")

tab_single, tab_batch, tab_sideload, tab_cloud = st.tabs(
    ["Single APK Analysis", "Batch Analysis", "Sideload Test", "Cloud Device Test"]
)


def _risk_badge(risk_level):
    color = RISK_COLORS[risk_level]
    text_color = "#FFFFFF" if risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.NONE) else "#000000"
    return (
        f'<span style="background-color:{color};color:{text_color};'
        f'padding:6px 18px;border-radius:6px;font-weight:bold;font-size:1.3em;">'
        f'{risk_level.value}</span>'
    )


def _render_result(result):
    if result.error:
        st.error(f"Analysis failed: {result.error}")
        return

    st.markdown("---")
    col1, col2 = st.columns([1, 3])
    with col1:
        st.markdown(_risk_badge(result.risk_level), unsafe_allow_html=True)
    with col2:
        st.markdown(f"**Package:** `{result.package_name}`")
        st.markdown(f"**File:** {result.file_name} ({result.file_size_mb} MB)")
        st.markdown(f"**Verdict:** {result.risk_description}")
    st.markdown("---")

    st.subheader("Detection Details")
    for layer in [result.auto_protection, result.play_integrity, result.firebase_appcheck, result.safetynet]:
        status = "detected" if layer.detected else "not detected"
        icon = "🔴" if layer.detected else "✅"
        with st.expander(f"{icon} {layer.name} — {status}", expanded=layer.detected):
            if not layer.detected:
                st.write("No indicators found.")
            else:
                st.write(f"**Summary:** {layer.summary}")
                st.write(f"**Findings ({len(layer.findings)}):**")
                for f in layer.findings:
                    detail = f" — {f.detail}" if f.detail else ""
                    st.markdown(f"- `{f.pattern_matched}` in `{f.source_file}`{detail}")

    if result.informational.detected:
        with st.expander(f"ℹ️ {result.informational.name} — {len(result.informational.findings)} finding(s)  *(does not affect risk level)*"):
            st.caption("These indicators are shown for reference but do not affect the risk classification.")
            for f in result.informational.findings:
                detail = f" — {f.detail}" if f.detail else ""
                st.markdown(f"- `{f.pattern_matched}` in `{f.source_file}`{detail}")

    st.subheader("Developer Recommendations")
    recommendation = RISK_RECOMMENDATIONS.get(result.risk_level, "")
    if recommendation:
        st.info(recommendation)
    if result.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM):
        st.markdown("**Recommended verdict handling code:**")
        st.code(CODE_SNIPPET, language="java")

    st.subheader("Raw Findings")
    if result.all_findings:
        table_data = [
            {"Category": f.category, "Source File": f.source_file, "Pattern Matched": f.pattern_matched,
             "Affects Risk": "No" if "informational" in f.category.lower() else "Yes", "Detail": f.detail}
            for f in result.all_findings
        ]
        st.dataframe(table_data, use_container_width=True)
        csv_buf = io.StringIO()
        writer = csv.DictWriter(csv_buf, fieldnames=["Category", "Source File", "Pattern Matched", "Affects Risk", "Detail"])
        writer.writeheader()
        writer.writerows(table_data)
        st.download_button("Download findings as CSV", csv_buf.getvalue(),
                           file_name=f"{result.file_name}_findings.csv", mime="text/csv")
    else:
        st.write("No findings to display.")


with tab_single:
    uploaded_file = st.file_uploader("Upload an APK file", type=["apk"], key="single_upload")
    if uploaded_file is not None:
        st.write(f"**File:** {uploaded_file.name} ({uploaded_file.size / (1024*1024):.2f} MB)")
        if st.button("Analyze", key="analyze_single"):
            with st.spinner("Analyzing APK..."):
                file_data = uploaded_file.read()
                result = analyze_apk(file_data, uploaded_file.name)
                st.session_state["single_result"] = result
    if "single_result" in st.session_state:
        _render_result(st.session_state["single_result"])


with tab_batch:
    uploaded_files = st.file_uploader("Upload multiple APK files", type=["apk"],
                                      accept_multiple_files=True, key="batch_upload")
    if uploaded_files:
        st.write(f"**{len(uploaded_files)} file(s) selected**")
        if st.button("Analyze All", key="analyze_batch"):
            results = []
            progress = st.progress(0)
            for i, f in enumerate(uploaded_files):
                with st.spinner(f"Analyzing {f.name}..."):
                    file_data = f.read()
                    r = analyze_apk(file_data, f.name)
                    results.append(r)
                progress.progress((i + 1) / len(uploaded_files))
            st.session_state["batch_results"] = results

    if "batch_results" in st.session_state:
        results = st.session_state["batch_results"]
        st.subheader("Batch Results Summary")
        summary_data = [
            {"File": r.file_name, "Package": r.package_name, "Size (MB)": r.file_size_mb,
             "Risk Level": r.risk_level.value,
             "Verdict": r.risk_description[:100] + ("..." if len(r.risk_description) > 100 else ""),
             "Findings": len(r.all_findings)}
            for r in results
        ]
        st.dataframe(summary_data, use_container_width=True)
        csv_buf = io.StringIO()
        writer = csv.DictWriter(csv_buf, fieldnames=["File", "Package", "Size (MB)", "Risk Level", "Verdict", "Findings"])
        writer.writeheader()
        writer.writerows(summary_data)
        st.download_button("Download batch summary as CSV", csv_buf.getvalue(),
                           file_name="batch_analysis_summary.csv", mime="text/csv")
        st.subheader("Detailed Results")
        for r in results:
            with st.expander(f"{r.file_name} — {r.risk_level.value}"):
                _render_result(r)


# ---------------------------------------------------------------------------
# Sideload Test Tab
# ---------------------------------------------------------------------------


def _verdict_badge(verdict):
    """Return a styled badge for PASS/FAIL/REVIEW verdict."""
    colors = {"PASS": "#28a745", "FAIL": "#dc3545", "REVIEW": "#ffc107"}
    text_colors = {"PASS": "#FFFFFF", "FAIL": "#FFFFFF", "REVIEW": "#000000"}
    color = colors.get(verdict, "#6c757d")
    text_color = text_colors.get(verdict, "#FFFFFF")
    return (
        f'<span style="background-color:{color};color:{text_color};'
        f'padding:6px 18px;border-radius:6px;font-weight:bold;font-size:1.3em;">'
        f'{verdict}</span>'
    )


def _run_sideload_test(apk_path, timeout, screenshots_dir, serial):
    """Run sideload test for a single APK using the sideload_test module."""
    import sideload_test as st_mod
    result = st_mod.test_single_apk(apk_path, timeout, screenshots_dir, serial=serial)
    return result


def _render_sideload_result(result):
    """Render a single sideload test result."""
    verdict = result.get("verdict", "FAIL")

    st.markdown("---")
    col1, col2 = st.columns([1, 3])
    with col1:
        st.markdown(_verdict_badge(verdict), unsafe_allow_html=True)
    with col2:
        pkg = result.get("package_name", "Unknown")
        app_name = result.get("app_name") or pkg
        st.markdown(f"**App:** {app_name}")
        st.markdown(f"**Package:** `{pkg}`")
        if result.get("version"):
            st.markdown(f"**Version:** {result['version']}")
        st.markdown(f"**Install:** {result.get('install_result', 'N/A')}")
    st.markdown("---")

    st.markdown(f"**Verdict Reason:** {result.get('verdict_reason', 'N/A')}")
    st.markdown(f"**Duration:** {result.get('duration_seconds', 0)}s")

    signals = result.get("signals", {})

    # Foreground changes
    fg_changes = signals.get("foreground_changes", [])
    if fg_changes:
        with st.expander(f"🔄 Foreground Activity Changes ({len(fg_changes)})"):
            for change in fg_changes:
                st.markdown(f"- **T+{change['time']}s:** `{change['activity']}`")

    # Keyword matches
    kw_matches = signals.get("keyword_matches", [])
    if kw_matches:
        tier1 = [m for m in kw_matches if m.get("tier") == 1]
        tier2 = [m for m in kw_matches if m.get("tier") == 2]
        if tier1:
            with st.expander(f"🔴 Tier 1 — Hard Block Signals ({len(tier1)})", expanded=True):
                for m in tier1:
                    st.markdown(f"- **T+{m['time']}s:** \"{m['text']}\" (`{m['node_class']}`)")
        if tier2:
            with st.expander(f"⚠️ Tier 2 — Soft Signals ({len(tier2)})"):
                for m in tier2:
                    st.markdown(f"- **T+{m['time']}s:** \"{m['text']}\" (`{m['node_class']}`)")

    # Logcat signals
    logcat = signals.get("logcat_signals", [])
    if logcat:
        with st.expander(f"📋 Logcat Signals ({len(logcat)})"):
            st.code("\n".join(logcat[:50]), language="text")

    # Screenshots
    screenshots = signals.get("screenshots", [])
    if screenshots:
        with st.expander(f"📸 Screenshots ({len(screenshots)})"):
            cols = st.columns(min(len(screenshots), 3))
            for idx, ss_path in enumerate(screenshots):
                if os.path.exists(ss_path):
                    cols[idx % 3].image(ss_path, caption=os.path.basename(ss_path))


with tab_sideload:
    st.subheader("Runtime Sideload Test")
    st.caption(
        "Upload APKs, and the tool will automatically install them on a virtual Android device, "
        "launch them, and check for anti-sideload blocking (Play Auto Protect, licensing, integrity checks). "
        "No phone or technical setup required."
    )

    from emulator_provisioner import (
        get_emulator_status, shutdown_emulator, is_provisioned,
        start_provision_background, start_boot_background,
        read_provision_status, clear_provision_status,
    )
    import sideload_test as st_mod

    # Check current state
    emu_status = get_emulator_status()
    bg_status = read_provision_status()

    # ---- Background task in progress? Show status and auto-refresh ----
    if bg_status and bg_status.get("state") == "running":
        st.info(f"⏳ {bg_status.get('message', 'Working...')}")
        st.caption("This page refreshes automatically every 3 seconds.")
        time.sleep(3)
        st.rerun()

    elif bg_status and bg_status.get("state") == "error":
        st.error(f"Setup failed: {bg_status.get('error', 'Unknown error')}")
        if st.button("🔄 Retry Setup", key="retry_provision"):
            clear_provision_status()
            st.rerun()

    elif bg_status and bg_status.get("state") == "done" and not emu_status["avd_exists"]:
        # Done message but AVD not detected yet — clear and refresh
        clear_provision_status()
        st.rerun()

    elif bg_status and bg_status.get("state") == "done":
        # Show done briefly then clear
        st.success(f"✅ {bg_status.get('message', 'Done!')}")
        clear_provision_status()

    # ---- Step 1: One-time setup (download SDK + emulator) ----
    if not emu_status["avd_exists"] and (not bg_status or bg_status.get("state") not in ("running",)):
        st.info(
            "**First-time setup required.** The tool needs to download an Android emulator (~2 GB). "
            "This only happens once — after that, tests start instantly."
        )
        if st.button("⬇️ Download & Set Up Emulator", key="provision_emu", type="primary"):
            start_provision_background()
            st.rerun()

    elif emu_status["avd_exists"]:
        # ---- Step 2: Emulator is provisioned, manage its lifecycle ----
        if emu_status["emulator_running"]:
            serial = emu_status["running_serial"]
            from adb_provisioner import get_device_model as _get_model
            device_model = _get_model(serial)
            st.success(f"✅ Virtual device running: {device_model} (`{serial}`)")

            col_stop, _ = st.columns([1, 3])
            with col_stop:
                if st.button("⏹️ Stop Emulator", key="stop_emu"):
                    shutdown_emulator(serial)
                    st.rerun()
        elif not bg_status or bg_status.get("state") != "running":
            serial = None
            st.warning("Virtual device is not running.")
            if st.button("▶️ Start Virtual Device", key="start_emu", type="primary"):
                start_boot_background()
                st.rerun()

        # ---- Step 3: Upload & test APKs (only when emulator is running) ----
        if emu_status["emulator_running"]:
            serial = emu_status["running_serial"]

            st.markdown("---")
            st.subheader("Upload APKs to Test")

            sideload_files = st.file_uploader(
                "Upload APK file(s)",
                type=["apk"],
                accept_multiple_files=True,
                key="sideload_upload",
            )

            timeout_val = st.slider(
                "Monitor timeout (seconds)", min_value=5, max_value=120, value=30, key="sideload_timeout"
            )

            screenshots_dir = "./screenshots"

            if sideload_files:
                st.write(f"**{len(sideload_files)} APK(s) selected**")

                if st.button("🚀 Run Sideload Test", key="run_sideload", type="primary"):
                    all_results = []
                    progress = st.progress(0)

                    for i, uploaded in enumerate(sideload_files):
                        status_container = st.status(f"Testing: {uploaded.name}", expanded=True)
                        with status_container:
                            with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
                                tmp.write(uploaded.read())
                                tmp_path = tmp.name

                            try:
                                info = st_mod.extract_apk_info(tmp_path)
                                display_name = info["app_label"] or info["package_name"] or uploaded.name
                                st.write(f"**App:** {display_name}")
                                if info["package_name"]:
                                    st.write(f"**Package:** `{info['package_name']}`")

                                st.write("⏳ Running sideload test...")
                                result = _run_sideload_test(
                                    tmp_path, timeout_val, screenshots_dir, serial
                                )
                                result["apk_file"] = uploaded.name
                                all_results.append(result)

                                verdict = result.get("verdict", "FAIL")
                                if verdict == "PASS":
                                    st.write(f"✅ **PASS:** {result.get('verdict_reason', '')}")
                                elif verdict == "FAIL":
                                    st.write(f"❌ **FAIL:** {result.get('verdict_reason', '')}")
                                else:
                                    st.write(f"⚠️ **REVIEW:** {result.get('verdict_reason', '')}")
                            finally:
                                os.unlink(tmp_path)

                        progress.progress((i + 1) / len(sideload_files))

                    st.session_state["sideload_results"] = all_results

            if "sideload_results" in st.session_state:
                results = st.session_state["sideload_results"]

                # Summary
                st.subheader("Results Summary")
                pass_count = sum(1 for r in results if r.get("verdict") == "PASS")
                fail_count = sum(1 for r in results if r.get("verdict") == "FAIL")
                review_count = sum(1 for r in results if r.get("verdict") == "REVIEW")

                col_p, col_f, col_r = st.columns(3)
                col_p.metric("PASS", pass_count)
                col_f.metric("FAIL", fail_count)
                col_r.metric("REVIEW", review_count)

                summary_data = [
                    {
                        "APK": r.get("apk_file", ""),
                        "Package": r.get("package_name", ""),
                        "App Name": r.get("app_name", ""),
                        "Verdict": r.get("verdict", ""),
                        "Reason": (r.get("verdict_reason", "")[:80] + "...") if len(r.get("verdict_reason", "")) > 80 else r.get("verdict_reason", ""),
                        "Duration (s)": r.get("duration_seconds", 0),
                    }
                    for r in results
                ]
                st.dataframe(summary_data, use_container_width=True)

                st.subheader("Detailed Results")
                for r in results:
                    verdict = r.get("verdict", "FAIL")
                    icon = {"PASS": "✅", "FAIL": "❌", "REVIEW": "⚠️"}.get(verdict, "❓")
                    label = f"{icon} {r.get('apk_file', 'Unknown')} — {verdict}"
                    with st.expander(label, expanded=(verdict != "PASS")):
                        _render_sideload_result(r)

                from adb_provisioner import get_device_model as _get_model_report
                device_model_report = _get_model_report(serial)
                report = {
                    "test_run": {
                        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "device": device_model_report,
                        "adb_serial": serial,
                        "tool_version": st_mod.TOOL_VERSION,
                    },
                    "results": results,
                    "summary": {
                        "total": len(results),
                        "pass": pass_count,
                        "fail": fail_count,
                        "review": review_count,
                    },
                }
                st.download_button(
                    "📥 Download JSON Report",
                    json.dumps(report, indent=2),
                    file_name="sideload_report.json",
                    mime="application/json",
                )

# ---------------------------------------------------------------------------
# Cloud Device Test Tab (Firebase Test Lab)
# ---------------------------------------------------------------------------


def _cloud_verdict_badge(verdict):
    colors = {"PASS": "#28a745", "FAIL": "#dc3545", "REVIEW": "#ffc107"}
    text_colors = {"PASS": "#FFFFFF", "FAIL": "#FFFFFF", "REVIEW": "#000000"}
    color = colors.get(verdict, "#6c757d")
    text_color = text_colors.get(verdict, "#FFFFFF")
    return (
        f'<span style="background-color:{color};color:{text_color};'
        f'padding:6px 18px;border-radius:6px;font-weight:bold;font-size:1.3em;">'
        f'{verdict}</span>'
    )


with tab_cloud:
    st.subheader("Cloud Device Test")
    st.caption(
        "Test APKs on real phones and tablets via Firebase Test Lab. "
        "Upload a Google Cloud service account key, pick a device, and click test. "
        "Free tier: 5 physical device tests/day, 10 virtual device tests/day."
    )

    # ---- Step 1: Service account setup ----
    with st.expander("🔑 Google Cloud Setup (one-time)", expanded="ftl_client" not in st.session_state):
        st.markdown(
            "**Quick setup (5 minutes):**\n"
            "1. Go to [Google Cloud Console](https://console.cloud.google.com)\n"
            "2. Create a project (or use existing)\n"
            "3. Enable **Cloud Testing API** and **Cloud Tool Results API**\n"
            "4. Go to **IAM > Service Accounts** → Create one\n"
            "5. Grant roles: *Cloud Test Service Agent* + *Storage Admin*\n"
            "6. Create a JSON key and upload it below"
        )
        sa_file = st.file_uploader(
            "Upload service account JSON key",
            type=["json"],
            key="sa_key_upload",
        )
        if sa_file is not None:
            try:
                sa_json = json.loads(sa_file.read())
            except json.JSONDecodeError:
                st.error("Invalid JSON file.")
                sa_json = None

            if sa_json and st.button("🔗 Connect", key="connect_gcp"):
                with st.spinner("Validating credentials..."):
                    from firebase_test_lab import validate_service_account, FirebaseTestLab
                    ok, msg = validate_service_account(sa_json)
                if ok:
                    st.success(msg)
                    st.session_state["ftl_sa_json"] = sa_json
                    st.session_state["ftl_client"] = FirebaseTestLab(sa_json)
                    st.rerun()
                else:
                    st.error(msg)

    # ---- Connected state ----
    if "ftl_client" in st.session_state:
        ftl: "FirebaseTestLab" = st.session_state["ftl_client"]
        st.success(f"Connected to project **{ftl.project_id}**")

        if st.button("Disconnect", key="disconnect_gcp"):
            del st.session_state["ftl_client"]
            del st.session_state["ftl_sa_json"]
            st.rerun()

        st.markdown("---")

        # ---- Step 2: Pick device ----
        st.subheader("Select Device")

        # Fetch catalog once per session
        if "ftl_devices" not in st.session_state:
            with st.spinner("Loading device catalog..."):
                try:
                    from firebase_test_lab import POPULAR_DEVICES
                    st.session_state["ftl_devices"] = POPULAR_DEVICES
                    try:
                        full_catalog = ftl.list_available_devices()
                        st.session_state["ftl_full_catalog"] = full_catalog
                    except Exception:
                        st.session_state["ftl_full_catalog"] = []
                except Exception as e:
                    st.error(f"Failed to load devices: {e}")
                    st.session_state["ftl_devices"] = []
                    st.session_state["ftl_full_catalog"] = []

        show_all = st.checkbox("Show all available devices", key="show_all_devices")
        device_list = (
            st.session_state.get("ftl_full_catalog", [])
            if show_all
            else st.session_state.get("ftl_devices", [])
        )

        if device_list:
            device_options = {
                f"{d['name']} ({d.get('brand', '')}) — API {', '.join(str(a) for a in d.get('api_levels', [])[-3:])}".strip(): d
                for d in device_list
                if d.get("api_levels")
            }
            selected_label = st.selectbox(
                "Device",
                options=list(device_options.keys()),
                key="ftl_device_select",
            )
            selected_device = device_options[selected_label]

            # API level picker
            available_apis = selected_device.get("api_levels", [])
            default_api = available_apis[-1] if available_apis else 34
            selected_api = st.selectbox(
                "Android API level",
                options=available_apis,
                index=len(available_apis) - 1 if available_apis else 0,
                key="ftl_api_select",
            )
        else:
            st.warning("No devices available.")
            selected_device = None
            selected_api = None

        st.markdown("---")

        # ---- Step 3: Upload & test ----
        st.subheader("Upload APK & Test")

        cloud_apk = st.file_uploader(
            "Upload APK file",
            type=["apk"],
            key="cloud_apk_upload",
        )

        test_timeout = st.slider(
            "Robo test timeout (seconds)",
            min_value=30,
            max_value=300,
            value=120,
            step=30,
            key="ftl_timeout",
        )

        if cloud_apk and selected_device:
            st.write(f"**APK:** {cloud_apk.name} ({cloud_apk.size / (1024*1024):.1f} MB)")
            st.write(f"**Device:** {selected_device['name']} — API {selected_api}")

            if st.button("🚀 Run Cloud Test", key="run_cloud_test", type="primary"):
                apk_bytes = cloud_apk.read()

                # Create test
                with st.spinner("Uploading APK and creating test..."):
                    try:
                        matrix = ftl.create_robo_test(
                            apk_bytes=apk_bytes,
                            apk_filename=cloud_apk.name,
                            device_id=selected_device["id"],
                            api_level=selected_api,
                            timeout_sec=test_timeout,
                        )
                        matrix_id = matrix["testMatrixId"]
                        st.info(f"Test created: `{matrix_id}`")
                    except Exception as e:
                        st.error(f"Failed to create test: {e}")
                        matrix_id = None

                # Poll for completion
                if matrix_id:
                    status_text = st.empty()
                    progress_bar = st.progress(0)

                    def _update_progress(state, elapsed):
                        status_text.info(f"⏳ State: **{state}** ({elapsed}s elapsed)")
                        # Rough progress estimate (tests usually take 2-5 min)
                        pct = min(elapsed / (test_timeout + 120), 0.95)
                        progress_bar.progress(pct)

                    try:
                        final_matrix = ftl.wait_for_completion(
                            matrix_id,
                            poll_interval=10,
                            max_wait=test_timeout + 300,
                            progress_callback=_update_progress,
                        )
                        progress_bar.progress(1.0)
                        status_text.empty()

                        state = final_matrix.get("state", "UNKNOWN")
                        if state == "FINISHED":
                            st.success("Test completed!")
                        else:
                            st.warning(f"Test ended with state: {state}")

                        # Parse & display results
                        results = ftl.parse_results(final_matrix)
                        st.session_state["cloud_results"] = results
                        st.session_state["cloud_matrix"] = final_matrix
                        st.session_state["cloud_apk_name"] = cloud_apk.name

                    except Exception as e:
                        st.error(f"Error during test: {e}")

        # ---- Display results ----
        if "cloud_results" in st.session_state:
            results = st.session_state["cloud_results"]
            st.markdown("---")
            st.subheader("Cloud Test Results")

            for r in results:
                verdict = r.get("verdict", "REVIEW")
                col1, col2 = st.columns([1, 3])
                with col1:
                    st.markdown(_cloud_verdict_badge(verdict), unsafe_allow_html=True)
                with col2:
                    st.markdown(f"**Device:** {r['device']} — API {r['api_level']}")
                    st.markdown(f"**Verdict:** {r['verdict_reason']}")

                # Video
                if r.get("video_url"):
                    with st.expander("🎬 Test Video"):
                        st.video(r["video_url"])

                # Screenshots
                if r.get("screenshot_urls"):
                    with st.expander(f"📸 Screenshots ({len(r['screenshot_urls'])})"):
                        cols = st.columns(min(len(r["screenshot_urls"]), 3))
                        for idx, url in enumerate(r["screenshot_urls"]):
                            cols[idx % 3].image(url)

                # Logcat
                if r.get("logcat_url"):
                    st.markdown(f"[📋 View Logcat]({r['logcat_url']})")

            # JSON download
            cloud_report = {
                "test_run": {
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "service": "Firebase Test Lab",
                    "project": ftl.project_id,
                    "apk": st.session_state.get("cloud_apk_name", ""),
                },
                "results": results,
            }
            st.download_button(
                "📥 Download JSON Report",
                json.dumps(cloud_report, indent=2),
                file_name="cloud_test_report.json",
                mime="application/json",
                key="download_cloud_report",
            )
