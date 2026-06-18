from __future__ import annotations

import os
import time

import altair as alt
import pandas as pd
import streamlit as st

from auth import verify_password
from configuration import mongodb_configuration_error
from dashboard_data import (
    SEVERITY_ORDER,
    build_overview,
    filter_findings,
    filter_runs,
    findings_frame,
    load_findings,
    load_runs,
    parse_timestamp,
    runs_frame,
    severity_rows,
    stage_frame,
)


SESSION_SECONDS = 8 * 60 * 60
PIPELINE_STATUS_ORDER = ("COMPLETED", "BLOCKED", "ERROR")
PIPELINE_STATUS_COLORS = ("#1f883d", "#d1242f", "#d1242f")


st.set_page_config(
    page_title="Security Pipeline Monitor",
    page_icon=":shield:",
    layout="wide",
)


def setting(name: str, default: str = "") -> str:
    try:
        value = st.secrets.get(name)
    except FileNotFoundError:
        value = None
    return str(value or os.getenv(name.upper(), default))


def authenticated() -> bool:
    login_time = st.session_state.get("login_time", 0)
    if st.session_state.get("authenticated") and time.time() - login_time < SESSION_SECONDS:
        return True
    st.session_state["authenticated"] = False
    return False


def login() -> None:
    st.title("Security Pipeline Monitor")
    st.caption("Private access to sanitized CI security metrics")
    password_hash = setting("dashboard_password_hash")
    if not password_hash:
        st.error("Dashboard password hash is not configured.")
        st.stop()
    with st.form("login_form", clear_on_submit=True):
        password = st.text_input("Dashboard password", type="password")
        submitted = st.form_submit_button("Sign in", width="stretch")
    if submitted:
        if verify_password(password, password_hash):
            st.session_state["authenticated"] = True
            st.session_state["login_time"] = time.time()
            st.rerun()
            return
        st.error("Invalid password.")


def format_time(value: object) -> str:
    if not value:
        return "Never"
    parsed = parse_timestamp(value)
    if parsed is None:
        return "Unknown"
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


@st.cache_data(ttl=30, show_spinner=False)
def cached_runs(uri: str, database: str, days: int) -> list[dict]:
    return load_runs(uri, database, days=days)


@st.cache_data(ttl=30, show_spinner=False)
def cached_findings(uri: str, database: str, run_ids: tuple[str, ...]) -> list[dict]:
    return load_findings(uri, database, list(run_ids))


def render_dashboard() -> None:
    with st.sidebar:
        st.header("SecMonitor")
        st.caption("Security pipeline operations")
        days = st.select_slider("History", options=[7, 14, 30, 60, 90], value=30)
        if st.button("Refresh data", width="stretch"):
            st.cache_data.clear()
            st.rerun()
        if st.button("Log out", width="stretch"):
            st.session_state.clear()
            st.rerun()

    st.title("Security pipeline overview")
    st.caption("Scanner health, policy decisions, and sanitized execution history")

    uri = setting("mongodb_uri")
    database = setting("mongodb_database", "security_monitor")
    configuration_error = mongodb_configuration_error(uri)
    if configuration_error:
        st.error(configuration_error)
        st.stop()
    try:
        runs = cached_runs(uri, database, days)
    except Exception as exc:
        st.error(f"Monitoring database is unavailable: {str(exc)[:300]}")
        st.stop()

    if not runs:
        st.info("No monitoring runs are available for the selected period.")
        st.stop()

    overview = build_overview(runs)
    latest_value = overview.get("latest")
    if not isinstance(latest_value, dict):
        st.error("Latest monitoring run has an invalid data shape.")
        st.stop()
        return
    latest: dict = latest_value
    findings_value = latest.get("findings_by_severity")
    findings = findings_value if isinstance(findings_value, dict) else {}
    findings_by_tool = latest.get("findings_by_tool")
    total_findings = sum(
        int(value)
        for value in findings_by_tool.values()
    ) if isinstance(findings_by_tool, dict) else 0

    status, decision, finding_metric, duration, gemini = st.columns(5)
    status.metric("Pipeline status", latest.get("pipeline_status", "UNKNOWN"))
    decision.metric("Final decision", latest.get("final_decision") or "UNAVAILABLE")
    finding_metric.metric("Findings", total_findings, f"{findings.get('CRITICAL', 0)} critical")
    duration.metric("Duration", f"{latest.get('duration_seconds', 0)}s")
    gemini.metric("Gemini", "Available" if latest.get("llm_available") else "Unavailable")
    st.caption(f"Latest run: {format_time(latest.get('run_finished_at'))}")

    health_tab, trends_tab, findings_tab, history_tab = st.tabs(("Health", "Trends", "Findings", "Run history"))

    with health_tab:
        left, right = st.columns((2, 1))
        with left:
            st.subheader("Scanner health")
            scanner_rows = [
                {"scanner": name.title(), "status": details.get("status", "UNKNOWN"), "error": details.get("error") or ""}
                for name, details in latest.get("scanner_health", {}).items()
            ]
            st.dataframe(scanner_rows, hide_index=True, width="stretch")
        with right:
            st.subheader("Run outcomes")
            counts = pd.DataFrame([
                {"status": key, "runs": value}
                for key, value in overview["status_counts"].items()
            ])
            st.bar_chart(counts, x="status", y="runs", horizontal=True)

        severity = pd.DataFrame(severity_rows(latest.get("findings_by_severity", {})))
        severity_chart = alt.Chart(severity).mark_bar().encode(
            x=alt.X("severity:N", title="Severity", sort=list(SEVERITY_ORDER)),
            y=alt.Y("findings:Q", title="Findings"),
            color=alt.Color(
                "severity:N",
                title="Severity",
                scale=alt.Scale(
                    domain=list(SEVERITY_ORDER),
                    range=["#dc2626", "#f97316", "#eab308", "#16a34a"],
                ),
            ),
            tooltip=("severity:N", "findings:Q"),
        )
        st.subheader("Latest findings by severity")
        st.altair_chart(severity_chart, width="stretch")

    with trends_tab:
        frame = runs_frame(reversed(runs))
        if frame.empty:
            st.info("No trend data is available.")
        else:
            duration_chart = alt.Chart(frame).mark_line(point=True).encode(
                x=alt.X("started:T", title="Run time"),
                y=alt.Y("duration_seconds:Q", title="Seconds"),
                color=alt.Color(
                    "status:N",
                    title="Status",
                    scale=alt.Scale(
                        domain=list(PIPELINE_STATUS_ORDER),
                        range=list(PIPELINE_STATUS_COLORS),
                    ),
                ),
                tooltip=("run_id", "status", "duration_seconds", "started"),
            ).properties(title="Pipeline duration")
            st.altair_chart(duration_chart, width="stretch")

            severity_chart = alt.Chart(frame).transform_fold(
                ["high", "critical"], as_=["severity", "findings"]
            ).mark_bar().encode(
                x=alt.X("started:T", title="Run time"),
                y=alt.Y("findings:Q", title="Findings"),
                color=alt.Color("severity:N", scale=alt.Scale(domain=["high", "critical"], range=["#f59e0b", "#ef4444"])),
                tooltip=("run_id", "severity:N", "findings:Q"),
            ).properties(title="High and critical findings")
            st.altair_chart(severity_chart, width="stretch")

            availability = round(frame["gemini_available"].mean() * 100, 1)
            st.metric("Gemini availability", f"{availability}%", f"Last {len(frame)} runs")

    with findings_tab:
        run_ids = tuple(str(run.get("run_id") or run.get("github", {}).get("run_id", "")) for run in runs)
        try:
            finding_records = cached_findings(uri, database, run_ids)
        except Exception as exc:
            st.error(f"Detailed findings are unavailable: {str(exc)[:300]}")
            finding_records = []
        frame = findings_frame(finding_records)
        if any(run.get("findings_truncated") for run in runs):
            st.warning("One or more runs reached the configured finding limit; displayed details may be incomplete.")
        if frame.empty:
            st.info("No detailed findings are available. Legacy runs contain aggregate counts only.")
        else:
            first, second, third = st.columns(3)
            run_options = ["ALL", *run_ids]
            pending_run = st.session_state.pop("pending_finding_run_id", None)
            if pending_run in run_options:
                st.session_state["findings_run_filter"] = pending_run
            if st.session_state.get("findings_run_filter") not in run_options:
                st.session_state["findings_run_filter"] = "ALL"
            selected_run = str(
                first.selectbox("Run", run_options, key="findings_run_filter") or "ALL"
            )
            severity = str(
                second.selectbox("Severity", ["ALL", *SEVERITY_ORDER]) or "ALL"
            )
            tools = [
                "ALL",
                *sorted(str(value) for value in frame["tool"].dropna().unique()),
            ]
            tool = str(third.selectbox("Scanner", tools) or "ALL")
            fourth, fifth, sixth = st.columns(3)
            finding_type = fourth.text_input("Type or rule")
            file_filter = fifth.text_input("File")
            search = sixth.text_input("Search findings", placeholder="Message, commit, run ID...")
            filtered_findings = filter_findings(
                frame,
                run_id=selected_run,
                severity=severity,
                tool=tool,
                finding_type=finding_type,
                file=file_filter,
                search=search,
            )
            st.metric("Matching findings", len(filtered_findings))
            page_size = st.selectbox("Rows per page", (25, 50, 100), index=1)
            page_count = max(1, (len(filtered_findings) + page_size - 1) // page_size)
            if st.session_state.get("findings_page", 1) > page_count:
                st.session_state["findings_page"] = 1
            page = st.number_input("Page", min_value=1, max_value=page_count, key="findings_page")
            start = (int(page) - 1) * page_size
            visible = filtered_findings.iloc[start:start + page_size].copy()
            severity_colors = {
                "CRITICAL": "background-color: #fee2e2; color: #991b1b",
                "HIGH": "background-color: #ffedd5; color: #9a3412",
                "MEDIUM": "background-color: #fef9c3; color: #854d0e",
                "LOW": "background-color: #dcfce7; color: #166534",
            }
            styled = visible.style.map(
                lambda value: severity_colors.get(str(value), ""),
                subset=["severity"],
            )
            st.dataframe(styled, hide_index=True, width="stretch")
            st.download_button(
                "Export filtered CSV",
                filtered_findings.to_csv(index=False).encode("utf-8"),
                file_name="security-findings.csv",
                mime="text/csv",
            )

    with history_tab:
        filter_one, filter_two = st.columns((1, 2))
        selected_status = str(
            filter_one.selectbox(
                "Status", ("ALL", "COMPLETED", "BLOCKED", "ERROR")
            ) or "ALL"
        )
        search = filter_two.text_input("Search", placeholder="Run ID, repository, branch, or commit")
        filtered = filter_runs(runs, status=selected_status, search=search)
        frame = runs_frame(filtered)
        if frame.empty:
            st.info("No runs match the selected filters.")
        else:
            table = frame[["run_id", "started", "status", "decision", "repository", "branch", "commit", "findings", "duration_seconds"]]
            st.dataframe(table, hide_index=True, width="stretch")
            selected_id = str(
                st.selectbox("Inspect run", frame["run_id"].astype(str).tolist()) or ""
            )
            selected = next(run for run in filtered if str(run.get("run_id") or run.get("github", {}).get("run_id")) == selected_id)
            st.subheader(f"Run {selected_id}")
            detail_one, detail_two, detail_three = st.columns(3)
            detail_one.metric("Policy", selected.get("policy_decision") or "UNAVAILABLE")
            detail_two.metric("Final", selected.get("final_decision") or "UNAVAILABLE")
            detail_three.metric("Duration", f"{selected.get('duration_seconds', 0)}s")
            stages = stage_frame(selected)
            if not stages.empty:
                st.dataframe(stages, hide_index=True, width="stretch")
            if selected.get("error"):
                st.error(f"{selected['error'].get('category')}: {selected['error'].get('message')}")
            run_url = selected.get("github", {}).get("run_url")
            if run_url:
                st.link_button("Open GitHub Actions run", run_url)
            if st.button("Filter Findings tab to this run"):
                st.session_state["pending_finding_run_id"] = selected_id
                st.info("Findings filter updated. Open the Findings tab to inspect this run.")


if not authenticated():
    login()
else:
    render_dashboard()
