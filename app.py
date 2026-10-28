import os
import json
from datetime import datetime

import pandas as pd
import streamlit as st

# ============================================================
# SENTINELX — INCIDENT COMMAND CENTER
# ============================================================

st.set_page_config(
    page_title="SentinelX | Incident Command",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.stApp {
    background: #080b16;
    color: #e8ecf8;
}
.block-container {
    max-width: 1700px;
    padding-top: 1.2rem;
    padding-bottom: 2rem;
}
[data-testid="stSidebar"] {
    background: #0b1020;
    border-right: 1px solid #252d48;
}
[data-testid="stMetric"] {
    background: linear-gradient(145deg,#141c30,#0d1424);
    border: 1px solid #293451;
    border-radius: 13px;
    padding: 16px;
}
[data-testid="stMetricLabel"] {
    color: #9eafd0 !important;
}
[data-testid="stMetricValue"] {
    color: #f5f7ff !important;
    font-weight: 750;
}
.stTabs [data-baseweb="tab-list"] {
    gap: 15px;
    background: #0b1020;
}
.stTabs [data-baseweb="tab"] {
    color: #aab7d2;
}
.stTabs [aria-selected="true"] {
    color: #83a8ff !important;
}
.stButton button, .stDownloadButton button {
    border-radius: 8px;
}
.sx-header {
    background: linear-gradient(110deg,#111a30,#123f4c);
    border: 1px solid #30425e;
    border-radius: 16px;
    padding: 25px;
    margin-bottom: 22px;
}
.sx-header h1 {
    color: #ffffff;
    font-size: 2.15rem;
    margin: 0;
}
.sx-header p {
    color: #b5c8e3;
    margin: 7px 0 0 0;
}
.sx-panel {
    background: #101728;
    border: 1px solid #28334d;
    border-radius: 13px;
    padding: 16px;
    margin-bottom: 12px;
}
.sx-muted {
    color: #91a2c2;
    font-size: 0.85rem;
}
hr {
    border-color: #28334d;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="sx-header">
    <h1>🛡️ SentinelX</h1>
    <p>CYBER THREAT CORRELATION · INCIDENT INVESTIGATION · RESPONSE</p>
    <p>Evidence-driven security analytics and explainable incident triage</p>
</div>
""", unsafe_allow_html=True)

# ============================================================
# DATA INPUT — NO SOURCE-SELECTION SCENARIO
# ============================================================

REQUIRED = {
    "timestamp", "username", "source_ip", "event", "status"
}


@st.cache_data
def load_bundled_data():
    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "sentinelx_sample_events_1500.csv"
    )

    if not os.path.exists(path):
        return None

    return pd.read_csv(path)


def normalize_events(raw):
    df = raw.copy()
    df.columns = [
        str(c).strip().lower() for c in df.columns
    ]

    missing = REQUIRED - set(df.columns)

    if missing:
        raise ValueError(
            "Missing required columns: "
            + ", ".join(sorted(missing))
        )

    for col in ["username", "source_ip", "event", "status"]:
        df[col] = (
            df[col].fillna("unknown").astype(str).str.strip()
        )

    if "asset" not in df.columns:
        df["asset"] = "unspecified"

    if "details" not in df.columns:
        df["details"] = ""

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce"
    )

    df = df.dropna(subset=["timestamp"]).copy()
    df = df.sort_values("timestamp").reset_index(drop=True)

    df["event_norm"] = (
        df["event"].str.lower().str.replace(" ", "_", regex=False)
    )
    df["status_norm"] = df["status"].str.lower()

    return df


# ============================================================
# DETECTION ENGINE
# ============================================================

def detect_events(df, threshold=4):
    alerts = []

    auth_events = {
        "login", "login_failure", "login_success",
        "authentication", "auth", "authentication_failure",
        "authentication_success", "failed_login",
        "successful_login", "vpn_login"
    }

    def add_alert(severity, rule, user, ip, rows,
                  explanation, next_check, recommendation, score):

        alerts.append({
            "severity": severity,
            "rule": rule,
            "entity": str(user),
            "source_ip": str(ip),
            "event_count": len(rows),
            "first_seen": rows["timestamp"].min(),
            "last_seen": rows["timestamp"].max(),
            "evidence_rows": ", ".join(
                str(int(x) + 2) for x in rows.index[:12]
            ),
            "explanation": explanation,
            "next_validation": next_check,
            "recommended_action": recommendation,
            "risk_score": min(100, score)
        })

    # Rule 1: Repeated authentication failures
    failures = df[
        df["event_norm"].isin(auth_events)
        & df["status_norm"].isin(
            ["failed", "failure", "denied", "blocked", "error"]
        )
    ]

    for (user, ip), group in failures.groupby(
        ["username", "source_ip"]
    ):
        if len(group) >= threshold:
            add_alert(
                "HIGH",
                "Repeated authentication failures",
                user, ip, group,
                f"{len(group)} failed authentication events "
                f"for this account and source IP.",
                "Check subsequent successful logins, MFA results "
                "and whether the user recognizes the activity.",
                "Review identity-provider logs and follow the "
                "organization's account-protection procedure.",
                72 + min(20, len(group))
            )

    # Rule 2: Failure followed by successful login
    for (user, ip), group in df.groupby(
        ["username", "source_ip"]
    ):
        failed = group[
            group["status_norm"].isin(
                ["failed", "failure", "denied", "blocked"]
            )
        ]

        succeeded = group[
            group["status_norm"].isin(
                ["success", "successful", "allowed"]
            )
            & group["event_norm"].isin(auth_events)
        ]

        for _, success in succeeded.iterrows():
            prior = failed[
                failed["timestamp"].between(
                    success["timestamp"] - pd.Timedelta(minutes=20),
                    success["timestamp"]
                )
            ]

            if len(prior) >= 2:
                sequence = group[
                    (group["timestamp"] >= prior["timestamp"].min())
                    & (group["timestamp"] <= success["timestamp"])
                ]

                add_alert(
                    "CRITICAL",
                    "Failure-to-success sequence",
                    user, ip, sequence,
                    f"{len(prior)} failed attempts were followed "
                    "by a successful login within 20 minutes.",
                    "Validate MFA, device identity, session details "
                    "and the user's recognition of the login.",
                    "Escalate for analyst review. Contain the "
                    "account only under approved procedures.",
                    92
                )
                break

    # Rule 3: Privilege changes
    privilege_events = {
        "privilege_change", "role_change",
        "privilege_escalation", "admin_role_granted",
        "privilege_escalation_attempt"
    }

    for idx, row in df[
        df["event_norm"].isin(privilege_events)
    ].iterrows():
        add_alert(
            "HIGH", "Privilege or role change",
            row["username"], row["source_ip"], df.loc[[idx]],
            f"Privilege-related event on {row['asset']}. "
            f"Details: {row['details']}.",
            "Verify the change request, approver and actor authorization.",
            "Review identity audit logs and investigate "
            "unauthorized privilege changes.",
            78
        )

    # Rule 4: Data movement
    data_events = {
        "data_export", "bulk_download", "mass_download",
        "database_export", "bulk_data_export"
    }

    for idx, row in df[
        df["event_norm"].isin(data_events)
    ].iterrows():
        add_alert(
            "HIGH", "Potential bulk data movement",
            row["username"], row["source_ip"], df.loc[[idx]],
            f"Data export observed on {row['asset']}. "
            "The event alone does not prove data exfiltration.",
            "Check export volume, destination, business purpose "
            "and data-owner approval.",
            "Preserve relevant logs and validate the activity "
            "with the data owner.",
            76
        )

    # Rule 5: Security-setting changes
    security_events = {
        "security_setting_change", "mfa_disabled",
        "logging_disabled", "audit_logging_disabled",
        "firewall_rule_change"
    }

    for idx, row in df[
        df["event_norm"].isin(security_events)
    ].iterrows():
        add_alert(
            "HIGH", "Security control configuration change",
            row["username"], row["source_ip"], df.loc[[idx]],
            f"Security configuration event: {row['details']}.",
            "Verify the change ticket, approver and before/after settings.",
            "Check security-control effectiveness and follow "
            "the approved change-management process.",
            82
        )

    # Rule 6: Failed changes
    for idx, row in df[
        df["event_norm"].isin(
            {"change", "deployment", "config_change"}
        )
        & df["status_norm"].isin(
            {"failed", "denied", "rejected"}
        )
    ].iterrows():
        add_alert(
            "MEDIUM", "Failed or rejected change",
            row["username"], row["source_ip"], df.loc[[idx]],
            f"Change on {row['asset']} was marked {row['status']}.",
            "Review the change request, approval and deployment logs.",
            "Investigate repeated attempts and reconcile "
            "with the authorized change calendar.",
            48
        )

    columns = [
        "severity", "rule", "entity", "source_ip", "event_count",
        "first_seen", "last_seen", "evidence_rows", "explanation",
        "next_validation", "recommended_action", "risk_score"
    ]

    result = pd.DataFrame(alerts, columns=columns)

    if not result.empty:
        result = result.drop_duplicates(
            subset=["rule", "entity", "source_ip", "first_seen"]
        )
        result = result.sort_values(
            "risk_score", ascending=False
        ).reset_index(drop=True)

    return result


# ============================================================
# EVIDENCE-DRIVEN NEXT-CHECK ENGINE
# ============================================================

def next_check_engine(events, alert):
    user = str(alert["entity"])
    ip = str(alert["source_ip"])

    start = pd.to_datetime(alert["first_seen"])
    end = pd.to_datetime(alert["last_seen"])

    window = events[
        (events["timestamp"] >= start - pd.Timedelta(minutes=20))
        & (events["timestamp"] <= end + pd.Timedelta(minutes=20))
    ]

    related = window[
        (window["username"] == user)
        | (window["source_ip"] == ip)
    ]

    event_types = set(related["event_norm"])
    details = " ".join(
        related["details"].fillna("").astype(str).str.lower()
    )

    checks = []

    def recommend(priority, title, reason, evidence):
        checks.append({
            "Priority": priority,
            "Next investigation check": title,
            "Reason": reason,
            "Evidence to collect": evidence
        })

    rule = str(alert["rule"]).lower()

    if "authentication" in rule or "failure-to-success" in rule:
        recommend(
            1, "Validate MFA and identity-provider outcome",
            "Authentication activity needs identity verification.",
            "MFA result, identity-provider audit record and session ID."
        )

        if not any(x in event_types for x in [
            "mfa_challenge", "mfa_result", "mfa_verification"
        ]):
            recommend(
                1, "Evidence gap: MFA result missing",
                "The supplied event window has no explicit MFA result.",
                "MFA success/failure record from the identity provider."
            )

        if not any(x in event_types for x in [
            "device_posture", "endpoint_check", "device_compliance"
        ]):
            recommend(
                2, "Verify device identity and posture",
                "No device compliance event is present in this window.",
                "Device ID, managed-device status and endpoint telemetry."
            )

        recommend(
            3, "Validate sign-in context",
            "Confirm whether the source and timing fit expected activity.",
            "Authorized location, VPN context and sign-in risk telemetry."
        )

    if "privilege" in rule or any(
        x in event_types for x in [
            "privilege_change", "role_change", "admin_role_granted"
        ]
    ):
        if not any(x in details for x in [
            "ticket", "approved", "change request", "request id"
        ]):
            recommend(
                1, "Verify privilege-change approval",
                "No obvious approval reference appears in event details.",
                "Change ticket, approver and role assignment audit record."
            )

        recommend(
            2, "Review actions after privilege elevation",
            "Elevated access may increase the impact of suspicious activity.",
            "Subsequent admin actions and accessed assets."
        )

    if "data" in rule or any(
        x in event_types for x in [
            "data_export", "bulk_download",
            "mass_download", "database_export"
        ]
    ):
        if not any(x in details for x in [
            "approved export", "business purpose", "ticket"
        ]):
            recommend(
                1, "Validate export purpose and approval",
                "The supplied details do not establish business approval.",
                "Export request, data-owner approval and reference ID."
            )

        recommend(
            2, "Inspect export volume and destination",
            "A data-export event alone does not prove exfiltration.",
            "Bytes exported, destination, job ID and DLP records."
        )

    if "security control" in rule or any(
        x in event_types for x in [
            "security_setting_change", "mfa_disabled",
            "logging_disabled", "audit_logging_disabled"
        ]
    ):
        recommend(
            1, "Confirm change request and maintenance window",
            "Verify that the configuration change was authorized.",
            "Change ticket, approver and before/after configuration."
        )

        recommend(
            2, "Check telemetry continuity",
            "Security-setting changes may reduce visibility.",
            "Audit pipeline status and log-source heartbeat."
        )

    if not checks:
        recommend(
            1, "Confirm the event with the system owner",
            "Additional context is required before drawing a conclusion.",
            "Owner confirmation and related source-system records."
        )

    seen = set()
    unique = []

    for check in sorted(checks, key=lambda item: item["Priority"]):
        if check["Next investigation check"] not in seen:
            unique.append(check)
            seen.add(check["Next investigation check"])

    return unique[:5]


# ============================================================
# SIDEBAR AND DATA LOADING
# ============================================================

with st.sidebar:
    st.markdown("## 🛡️ SentinelX")
    st.caption("INCIDENT CONTROLS")

    threshold = st.slider(
        "Failed-login alert threshold", 3, 10, 4
    )

    st.markdown("---")
    st.markdown("### Security event input")

    uploaded = st.file_uploader(
        "Upload authorized security logs",
        type=["csv"],
        help="Upload a CSV export to analyze it."
    )

    st.caption(
        "Required: timestamp, username, source_ip, event, status. "
        "Optional: asset, details."
    )

    bundled = load_bundled_data()

    if bundled is not None:
        st.download_button(
            "Download event dataset",
            bundled.to_csv(index=False),
            file_name="sentinelx_sample_events_1500.csv",
            mime="text/csv",
            use_container_width=True
        )

try:
    if uploaded is not None:
        raw = pd.read_csv(uploaded)
        data_source = "Uploaded security logs"
    elif bundled is not None:
        raw = bundled
        data_source = "Bundled event dataset"
    else:
        st.error(
            "No bundled CSV found. Add "
            "sentinelx_sample_events_1500.csv beside app.py "
            "or upload a CSV using the sidebar."
        )
        st.stop()

    events = normalize_events(raw)
    alerts = detect_events(events, threshold)

except Exception as error:
    st.error(f"Unable to process input: {error}")
    st.stop()


# ============================================================
# INCIDENT COMMAND DASHBOARD
# ============================================================

tabs = st.tabs([
    "Incident Command",
    "Event Explorer",
    "Attack Storylines",
    "Threat Context",
    "Response Playbooks",
    "Export & Methodology"
])

with tabs[0]:
    st.markdown("## Incident Command Center")
    st.caption(
        f"Data source: {data_source} · "
        "Detections require analyst validation."
    )

    incident_count = len(alerts)
    critical = (
        int((alerts["severity"] == "CRITICAL").sum())
        if not alerts.empty else 0
    )
    high = (
        int((alerts["severity"] == "HIGH").sum())
        if not alerts.empty else 0
    )
    users = (
        alerts["entity"].nunique()
        if not alerts.empty else 0
    )
    clusters = (
        alerts[["entity", "source_ip"]].drop_duplicates().shape[0]
        if not alerts.empty else 0
    )

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("EVENTS ANALYZED", f"{len(events):,}")
    m2.metric("INCIDENTS TO TRIAGE", f"{incident_count:,}")
    m3.metric("CRITICAL PRIORITY", f"{critical:,}")
    m4.metric("HIGH PRIORITY", f"{high:,}")
    m5.metric("CORRELATED CLUSTERS", f"{clusters:,}")

    left, right = st.columns([1.7, 1])

    with left:
        st.markdown("### Incident Queue")

        if not alerts.empty:
            queue = alerts.copy()

            severity_order = {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3
            }

            queue["order"] = queue["severity"].map(severity_order)
            queue = queue.sort_values(
                ["order", "risk_score"],
                ascending=[True, False]
            ).reset_index(drop=True)

            queue["case_id"] = [
                f"SX-{1001 + i:04d}" for i in range(len(queue))
            ]
            queue["status"] = "Needs review"

            display = queue[[
                "case_id", "severity", "rule", "entity",
                "source_ip", "first_seen", "risk_score", "status"
            ]].rename(columns={
                "case_id": "CASE ID",
                "severity": "PRIORITY",
                "rule": "DETECTION",
                "entity": "IDENTITY",
                "source_ip": "SOURCE IP",
                "first_seen": "FIRST SEEN",
                "risk_score": "RISK",
                "status": "STATUS"
            })

            st.dataframe(
                display,
                use_container_width=True,
                hide_index=True,
                height=330
            )

            selected = st.selectbox(
                "Investigate incident",
                queue.index,
                format_func=lambda i: (
                    f"{queue.loc[i, 'case_id']} · "
                    f"{queue.loc[i, 'severity']} · "
                    f"{queue.loc[i, 'rule']} · "
                    f"{queue.loc[i, 'entity']}"
                )
            )

            incident = queue.loc[selected]

            st.markdown("### Investigation details")

            st.markdown(
                f"**Case:** {incident['case_id']}  \n"
                f"**Detection:** {incident['rule']}  \n"
                f"**Priority:** {incident['severity']}  \n"
                f"**Identity:** {incident['entity']}  \n"
                f"**Source IP:** {incident['source_ip']}  \n"
                f"**Risk score:** {incident['risk_score']}/100"
            )

            st.markdown("**Why this was detected**")
            st.write(incident["explanation"])

            st.markdown("**Next validation step**")
            st.write(incident["next_validation"])

            st.markdown("**Recommended response**")
            st.write(incident["recommended_action"])

            st.caption(
                "Supporting CSV row references: "
                + str(incident["evidence_rows"])
            )

            st.markdown("### Evidence-driven next checks")

            for check in next_check_engine(events, incident):
                with st.container(border=True):
                    st.markdown(
                        f"**Priority {check['Priority']} — "
                        f"{check['Next investigation check']}**"
                    )
                    st.write(check["Reason"])
                    st.caption(
                        "Evidence to collect: "
                        + check["Evidence to collect"]
                    )

        else:
            st.success(
                "No detections matched the current rules. "
                "Review the input data and configured threshold."
            )

    with right:
        st.markdown("### Priority distribution")

        if not alerts.empty:
            severity_counts = alerts.groupby("severity").size()
            st.bar_chart(severity_counts)
        else:
            st.info("No alerts available.")

        st.markdown("### Event activity")

        trend = (
            events.set_index("timestamp")
            .resample("15min")
            .size()
            .rename("Events")
        )
        st.area_chart(trend)

        st.markdown("### Top detection categories")

        if not alerts.empty:
            categories = (
                alerts.groupby("rule").size()
                .sort_values(ascending=True)
                .tail(8)
                .rename("Cases")
            )
            st.bar_chart(categories)

    st.caption(
        "Incident queue entries are rule-triggered candidates, "
        "not confirmed breaches. Use authorized logs for real investigations."
    )


# ============================================================
# EVENT EXPLORER
# ============================================================

with tabs[1]:
    st.subheader("Security Event Explorer")

    c1, c2, c3 = st.columns(3)

    user_filter = c1.selectbox(
        "Username",
        ["All"] + sorted(events["username"].unique().tolist())
    )
    event_filter = c2.selectbox(
        "Event type",
        ["All"] + sorted(events["event"].unique().tolist())
    )
    status_filter = c3.selectbox(
        "Status",
        ["All"] + sorted(events["status"].unique().tolist())
    )

    filtered = events.copy()

    if user_filter != "All":
        filtered = filtered[filtered["username"] == user_filter]

    if event_filter != "All":
        filtered = filtered[filtered["event"] == event_filter]

    if status_filter != "All":
        filtered = filtered[filtered["status"] == status_filter]

    st.dataframe(
        filtered.drop(
            columns=["event_norm", "status_norm"],
            errors="ignore"
        ),
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        f"Displaying {len(filtered):,} of {len(events):,} events."
    )


# ============================================================
# ATTACK STORYLINES
# ============================================================

with tabs[2]:
    st.subheader("Attack Storyline Engine")

    st.write(
        "Related detections are grouped by username and source IP. "
        "The engine identifies possible evidence gaps and suggests "
        "the next validation steps. Correlation alone does not prove "
        "that an attack occurred."
    )

    if alerts.empty:
        st.info("No investigation threads are currently available.")
    else:
        pairs = (
            alerts.assign(
                thread=alerts["entity"] + " | " + alerts["source_ip"]
            )["thread"]
            .drop_duplicates()
            .tolist()
        )

        chosen = st.selectbox("Investigation thread", pairs)
        user, ip = chosen.split(" | ", 1)

        related_alerts = alerts[
            (alerts["entity"] == user)
            & (alerts["source_ip"] == ip)
        ]

        story_events = events[
            (events["username"] == user)
            | (events["source_ip"] == ip)
        ].sort_values("timestamp")

        st.markdown(f"**Identity:** `{user}` · **Source IP:** `{ip}`")
        st.markdown("### Correlated event timeline")

        columns = [
            c for c in [
                "timestamp", "username", "source_ip",
                "event", "status", "asset", "details"
            ] if c in story_events.columns
        ]

        st.dataframe(
            story_events[columns].head(100),
            use_container_width=True,
            hide_index=True
        )

        for _, alert in related_alerts.iterrows():
            with st.expander(
                f"{alert['severity']} · {alert['rule']}"
            ):
                st.write(alert["explanation"])
                st.write(
                    "**Evidence rows:** " + alert["evidence_rows"]
                )
                st.write(
                    "**Next validation:** " + alert["next_validation"]
                )
                st.write(
                    "**Recommended response:** "
                    + alert["recommended_action"]
                )

                for check in next_check_engine(events, alert):
                    st.markdown(
                        f"**Priority {check['Priority']}: "
                        f"{check['Next investigation check']}**"
                    )
                    st.write(check["Reason"])
                    st.caption(check["Evidence to collect"])


# ============================================================
# THREAT CONTEXT
# ============================================================

with tabs[3]:
    st.subheader("Threat Context & Indicator Explorer")

    context = (
        events.groupby("source_ip")
        .agg(
            events=("source_ip", "size"),
            users=("username", "nunique"),
            event_types=("event", "nunique"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max")
        )
        .reset_index()
        .sort_values("events", ascending=False)
    )

    st.dataframe(context, use_container_width=True, hide_index=True)

    indicator = st.text_input(
        "Search username, source IP, asset or event detail"
    )

    if indicator:
        matches = events[
            events.astype(str).apply(
                lambda col: col.str.contains(
                    indicator, case=False, na=False
                )
            ).any(axis=1)
        ]

        st.write(f"{len(matches)} matching events")
        st.dataframe(
            matches.drop(
                columns=["event_norm", "status_norm"],
                errors="ignore"
            ),
            use_container_width=True,
            hide_index=True
        )

    st.warning(
        "This module summarizes observed indicators. "
        "It does not query an external threat-intelligence service "
        "or independently confirm malicious reputation."
    )


# ============================================================
# RESPONSE PLAYBOOKS
# ============================================================

with tabs[4]:
    st.subheader("Incident Response Playbooks")

    playbooks = {
        "Authentication failures": [
            "Confirm the account owner and source device.",
            "Review identity-provider logs and MFA results.",
            "Check whether failures were followed by success.",
            "Follow approved account protection procedures.",
            "Record evidence and document the outcome."
        ],
        "Failure followed by success": [
            "Validate the session, device and MFA outcome.",
            "Review activity after successful authentication.",
            "Contact the account owner using a trusted channel.",
            "Preserve relevant logs and investigate related activity.",
            "Contain the account or session if confirmed and authorized."
        ],
        "Privilege change": [
            "Locate the change request and approval.",
            "Confirm the actor's authorization.",
            "Review activity performed with elevated access.",
            "Remove unauthorized access under approved procedures.",
            "Document findings and review least-privilege controls."
        ],
        "Potential data movement": [
            "Confirm the business purpose and data-owner approval.",
            "Inspect export volume, destination and access history.",
            "Preserve relevant logs and system metadata.",
            "Escalate to incident response or privacy teams if appropriate.",
            "Do not assume exfiltration from a single event."
        ],
        "Security configuration change": [
            "Verify the approved change and maintenance window.",
            "Compare before-and-after settings.",
            "Confirm logging and MFA remain effective.",
            "Restore secure settings if unauthorized and approved.",
            "Document the investigation and change history."
        ]
    }

    selected_playbook = st.selectbox(
        "Choose a response playbook",
        list(playbooks.keys())
    )

    st.markdown("### Analyst checklist")

    for i, step in enumerate(playbooks[selected_playbook]):
        st.checkbox(step, key=f"playbook_{selected_playbook}_{i}")


# ============================================================
# REPORT EXPORT AND METHODOLOGY
# ============================================================

with tabs[5]:
    st.subheader("Export Investigation Reports")

    report = {
        "product": "SentinelX",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "data_source": data_source,
        "event_count": len(events),
        "alert_count": len(alerts),
        "method": (
            "Rule-based event triage, user/source correlation "
            "and evidence-gap next-check heuristics."
        ),
        "limitations": [
            "Rule-triggered detections require analyst validation.",
            "No live SIEM ingestion.",
            "No external threat-intelligence lookup.",
            "Risk scores are not calibrated probabilities.",
            "Correlated events do not prove attribution.",
            "The bundled dataset is for testing."
        ],
        "alerts": (
            alerts.to_dict(orient="records")
            if not alerts.empty else []
        )
    }

    st.download_button(
        "Download investigation report (JSON)",
        json.dumps(report, indent=2, default=str),
        file_name="sentinelx_investigation_report.json",
        mime="application/json"
    )

    csv_report = (
        alerts.to_csv(index=False)
        if not alerts.empty
        else "severity,rule,entity,source_ip\n"
    )

    st.download_button(
        "Download detections (CSV)",
        csv_report,
        file_name="sentinelx_alerts.csv",
        mime="text/csv"
    )

    st.markdown("### Detection methodology")

    st.markdown("""
    - **Inputs:** timestamped CSV logs with username, source IP,
      event type and status.
    - **Detection:** repeated login failures, failure-to-success
      sequences, privilege changes, data exports, security-setting
      changes and rejected change events.
    - **Explainability:** each alert includes a rule, evidence-row
      references, explanation and recommended validation.
    - **Next-check engine:** deterministic evidence-gap heuristics
      prioritize follow-up checks and identify evidence to collect.
    - **Limitations:** no live SIEM ingestion, endpoint telemetry,
      automated containment or external indicator-reputation feed.
    """)

st.divider()
st.caption(
    "SentinelX Incident Command Prototype · "
    "Rule-based decision support · Analyst validation required"
)
