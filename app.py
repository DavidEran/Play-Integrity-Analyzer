"""Play Integrity Analyzer — Streamlit App."""

import csv
import io

import streamlit as st

from analyzer import analyze_apk
from models import AnalysisResult, RiskLevel, RISK_COLORS, RISK_RECOMMENDATIONS, CODE_SNIPPET

st.set_page_config(page_title="Play Integrity Analyzer", page_icon="🔍", layout="wide")
st.title("Play Integrity Analyzer")
st.caption("Detect Google Play Integrity API and Auto Protection (pairip) in Android APKs to assess sideloading risk.")

tab_single, tab_batch = st.tabs(["Single APK Analysis", "Batch Analysis"])


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
