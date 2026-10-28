import os
import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="SentinelX | Incident Command",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -------------------- Visual system --------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');
:root { --bg:#080d18; --panel:#101827; --panel2:#141f32; --line:#26344c; --muted:#91a1bd; --text:#edf3ff; --blue:#75a7ff; --cyan:#51d6d0; }
.stApp { background: radial-gradient(ellipse at 75% 0%, #152b45 0%, #0a1120 35%, #080d18 70%); color:var(--text); font-family:'DM Sans',sans-serif; }
[data-testid="stHeader"] { background:rgba(8,13,24,.85); }
.block-container { max-width:1600px; padding-top:1.25rem; padding-bottom:2rem; }
[data-testid="stSidebar"] { background:linear-gradient(180deg,#0d1627,#0a101d); border-right:1px solid var(--line); }
[data-testid="stSidebar"] * { color:#dce7fb; }
h1,h2,h3 { font-family:'Space Grotesk',sans-serif !important; letter-spacing:-.025em; }
h1 { font-size:2rem !important; }
h2 { font-size:1.35rem !important; }
h3 { font-size:1.05rem !important; }
p, label, .stMarkdown { color:#dce6f8; }
.sx-hero { padding:25px 28px; border-radius:20px; border:1px solid #304967; background:linear-gradient(115deg,rgba(21,36,60,.97),rgba(14,75,86,.92)); box-shadow:0 18px 48px rgba(0,0,0,.22); margin-bottom:18px; position:relative; overflow:hidden; }
.sx-hero:after { content:""; position:absolute; width:240px;height:240px;right:-70px;top:-115px;border:1px solid rgba(117,167,255,.2);border-radius:50%;box-shadow:0 0 0 25px rgba(117,167,255,.035),0 0 0 55px rgba(117,167,255,.025); }
.sx-kicker { color:#8fe5e2; font-size:.72rem; font-weight:700; letter-spacing:.17em; text-transform:uppercase; }
.sx-title { font-family:'Space Grotesk',sans-serif; font-size:2.35rem; font-weight:700; color:#fff; margin-top:5px; line-height:1.15; }
.sx-subtitle { color:#c1d2e9; font-size:1rem; margin-top:9px; }
.sx-status { display:inline-block; padding:5px 10px; border-radius:99px; background:rgba(81,214,208,.12); border:1px solid rgba(81,214,208,.3); color:#8de7df; font-size:.75rem; font-weight:700; margin-top:16px; }
.sx-section { display:flex; align-items:center; gap:10px; margin:12px 0 14px 0; }
.sx-section-bar { width:4px; height:23px; border-radius:10px; background:linear-gradient(#75a7ff,#51d6d0); }
.sx-card { background:linear-gradient(145deg,rgba(19,29,47,.96),rgba(13,21,35,.96)); border:1px solid #283750; border-radius:16px; padding:17px 18px; min-height:118px; box-shadow:0 8px 22px rgba(0,0,0,.12); }
.sx-card-label { color:#9eafca; font-size:.78rem; font-weight:600; letter-spacing:.045em; text-transform:uppercase; }
.sx-card-value { color:#f3f7ff; font-family:'Space Grotesk',sans-serif; font-size:2rem; font-weight:700; margin-top:9px; line-height:1.1; }
.sx-card-foot { color:#8c9db9; font-size:.75rem; margin-top:8px; }
.sx-panel { background:rgba(15,24,40,.9); border:1px solid #27364f; border-radius:16px; padding:17px; margin-bottom:12px; }
.sx-panel-title { color:#eef4ff; font-weight:700; font-size:1rem; margin-bottom:3px; }
.sx-panel-sub { color:#91a3c0; font-size:.78rem; margin-bottom:12px; }
.sx-pill { display:inline-block; padding:4px 8px; border-radius:7px; font-size:.72rem; font-weight:700; border:1px solid #34445f; background:#17233a; color:#bcd0f0; }
div[data-testid="stMetric"] { background:linear-gradient(145deg,#142139,#101827); border:1px solid #293a55; padding:16px 18px; border-radius:15px; }
[data-testid="stMetricLabel"] { color:#a5b5ce !important; font-size:.8rem; }
[data-testid="stMetricValue"] { color:#f5f8ff !important; font-family:'Space Grotesk',sans-serif; }
.stTabs [data-baseweb="tab-list"] { gap:8px; border-bottom:1px solid #263650; }
.stTabs [data-baseweb="tab"] { background:#101827; border:1px solid #263650; border-radius:9px 9px 0 0; padding:10px 15px; color:#b8c7df; }
.stTabs [aria-selected="true"] { background:#1a2b46 !important; color:#8eb7ff !important; border-color:#43638e !important; }
.stButton button, .stDownloadButton button { border-radius:10px; border:1px solid #38577e; background:linear-gradient(100deg,#24446d,#1a6370); color:#f5f9ff; font-weight:600; }
.stButton button:hover, .stDownloadButton button:hover { border-color:#7fb2ff; color:white; }
[data-testid="stFileUploader"] { background:#111c2e; border:1px dashed #45617e; border-radius:12px; padding:8px; }
[data-testid="stDataFrame"] { border:1px solid #283750; border-radius:12px; overflow:hidden; }
div[data-baseweb="select"] > div { background:#111c2e; border-color:#344761; }
.stAlert { border-radius:12px; }
hr { border-color:#263650; }
footer { visibility:hidden; }
#MainMenu { visibility:hidden; }
</style>
""", unsafe_allow_html=True)

# -------------------- Data helpers --------------------
REQUIRED = {"timestamp", "username", "source_ip", "event", "status"}

@st.cache_data
def load_bundled_data():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinelx_sample_events_1500.csv")
    if os.path.exists(path):
        return pd.read_csv(path)
    return None

def normalize_events(raw):
    df = raw.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    missing = REQUIRED - set(df.columns)
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
    for col in ["username", "source_ip", "event", "status"]:
        df[col] = df[col].fillna("unknown").astype(str).str.strip()
    if "asset" not in df.columns:
        df["asset"] = "unspecified"
    if "details" not in df.columns:
        df["details"] = ""
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).copy()
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["event_norm"] = df["event"].str.lower().str.replace(" ", "_", regex=False)
    df["status_norm"] = df["status"].str.lower()
    return df

def detect_events(df, threshold=4):
    alerts = []
    auth_events = {"login", "login_failure", "login_success", "authentication", "auth",
                   "authentication_failure", "authentication_success", "failed_login",
                   "successful_login", "vpn_login"}
    def add(severity, rule, user, ip, rows, explanation, next_check, recommendation, score):
        alerts.append({
            "severity": severity, "rule": rule, "entity": str(user), "source_ip": str(ip),
            "event_count": len(rows), "first_seen": rows["timestamp"].min(),
            "last_seen": rows["timestamp"].max(),
            "evidence_rows": ", ".join(str(int(x)+2) for x in rows.index[:12]),
            "explanation": explanation, "next_validation": next_check,
            "recommended_action": recommendation, "risk_score": min(100, score)
        })
    failures = df[df["event_norm"].isin(auth_events) & df["status_norm"].isin(
        ["failed", "failure", "denied", "blocked", "error"])]
    for (user, ip), group in failures.groupby(["username", "source_ip"]):
        if len(group) >= threshold:
            add("HIGH", "Repeated authentication failures", user, ip, group,
                f"{len(group)} failed authentication events for this account and source IP.",
                "Check subsequent successful logins, MFA results and whether the user recognizes the activity.",
                "Review identity-provider logs and follow the organization's account-protection procedure.",
                72 + min(20, len(group)))
    for (user, ip), group in df.groupby(["username", "source_ip"]):
        failed = group[group["status_norm"].isin(["failed", "failure", "denied", "blocked"])]
        succeeded = group[group["status_norm"].isin(["success", "successful", "allowed"]) &
                          group["event_norm"].isin(auth_events)]
        for _, success in succeeded.iterrows():
            prior = failed[failed["timestamp"].between(
                success["timestamp"] - pd.Timedelta(minutes=20), success["timestamp"])]
            if len(prior) >= 2:
                sequence = group[(group["timestamp"] >= prior["timestamp"].min()) &
                                 (group["timestamp"] <= success["timestamp"])]
                add("CRITICAL", "Failure-to-success sequence", user, ip, sequence,
                    f"{len(prior)} failed attempts were followed by a successful login within 20 minutes.",
                    "Validate MFA, device identity, session details and the user's recognition of the login.",
                    "Escalate for analyst review. Contain the account only under approved procedures.", 92)
                break
    rules = [
        ({"privilege_change", "role_change", "privilege_escalation", "admin_role_granted"},
         "HIGH", "Privilege or role change", 78,
         "Verify the change request, approver and actor authorization.",
         "Review identity audit logs and investigate unauthorized privilege changes."),
        ({"data_export", "bulk_download", "mass_download", "database_export", "bulk_data_export"},
         "HIGH", "Potential bulk data movement", 76,
         "Check export volume, destination, business purpose and data-owner approval.",
         "Preserve relevant logs and validate the activity with the data owner."),
        ({"security_setting_change", "mfa_disabled", "logging_disabled", "audit_logging_disabled",
          "firewall_rule_change"}, "HIGH", "Security control configuration change", 82,
         "Verify the change ticket, approver and before/after settings.",
         "Check security-control effectiveness and follow the approved change-management process.")
    ]
    for event_names, severity, rule, score, check, action in rules:
        for idx, row in df[df["event_norm"].isin(event_names)].iterrows():
            add(severity, rule, row["username"], row["source_ip"], df.loc[[idx]],
                f"Event on {row['asset']}: {row['details']}.",
                check, action, score)
    result = pd.DataFrame(alerts)
    if not result.empty:
        result = result.drop_duplicates(subset=["rule", "entity", "source_ip", "first_seen"])
        result = result.sort_values("risk_score", ascending=False).reset_index(drop=True)
    return result

def next_checks(events, alert):
    user, ip = str(alert["entity"]), str(alert["source_ip"])
    start, end = pd.to_datetime(alert["first_seen"]), pd.to_datetime(alert["last_seen"])
    window = events[(events["timestamp"] >= start-pd.Timedelta(minutes=20)) &
                    (events["timestamp"] <= end+pd.Timedelta(minutes=20))]
    related = window[(window["username"] == user) | (window["source_ip"] == ip)]
    types = set(related["event_norm"])
    checks = []
    def add(priority, title, reason, evidence):
        checks.append({"Priority": priority, "Next check": title, "Why": reason, "Evidence to collect": evidence})
    rule = str(alert["rule"]).lower()
    if "authentication" in rule or "failure-to-success" in rule:
        add(1, "Validate MFA and identity-provider outcome",
            "The login sequence needs identity verification.", "MFA result, identity-provider record and session ID.")
        if not types.intersection({"mfa_challenge", "mfa_result", "mfa_verification"}):
            add(1, "Evidence gap: MFA result not present",
                "No explicit MFA event appears in the supplied time window.", "MFA success/failure record.")
        add(2, "Verify device identity and sign-in context",
            "Confirm whether the device and source are expected.", "Device ID, VPN context and sign-in telemetry.")
    if "privilege" in rule:
        add(1, "Verify privilege-change approval", "Authorization is not established by the event alone.",
            "Change ticket, approver and role assignment record.")
    if "data" in rule:
        add(1, "Validate export purpose and approval", "The event does not establish business approval.",
            "Export request, data-owner approval and reference ID.")
    if "security control" in rule:
        add(1, "Confirm configuration change authorization", "Verify the change was approved.",
            "Change ticket and before/after configuration.")
        add(2, "Check telemetry continuity", "A configuration change may affect security visibility.",
            "Audit pipeline status and log-source heartbeat.")
    if not checks:
        add(1, "Confirm event with system owner", "More context is needed before a conclusion.",
            "Owner confirmation and source-system records.")
    return checks[:5]

# -------------------- Sidebar --------------------
with st.sidebar:
    st.markdown("### 🛡️ SENTINELX")
    st.caption("SECURITY OPERATIONS")
    st.markdown("---")
    st.markdown("**Detection configuration**")
    threshold = st.slider("Failed-login threshold", 3, 10, 4)
    st.markdown("**Event ingestion**")
    uploaded = st.file_uploader("Upload security event CSV", type=["csv"])
    st.caption("Required: timestamp, username, source_ip, event, status")
    st.caption("Optional: asset, details")
    bundled = load_bundled_data()
    if bundled is not None:
        st.download_button("↓ Download sample dataset", bundled.to_csv(index=False),
                           "sentinelx_sample_events_1500.csv", "text/csv", use_container_width=True)
    st.markdown("---")
    st.caption("MODE · RULE-BASED TRIAGE")
    st.caption("Analyst validation required")

try:
    if uploaded is not None:
        raw = pd.read_csv(uploaded)
        source_label = "Uploaded security logs"
    elif bundled is not None:
        raw = bundled
        source_label = "Bundled dataset"
    else:
        st.error("No dataset available. Upload a CSV to begin.")
        st.stop()
    events = normalize_events(raw)
    alerts = detect_events(events, threshold)
except Exception as e:
    st.error(f"Could not process the input: {e}")
    st.stop()

# -------------------- Hero and status --------------------
st.markdown("""
<div class="sx-hero">
 <div class="sx-kicker">Security Operations · Incident Intelligence</div>
 <div class="sx-title">SentinelX <span style="color:#76b7ff">/</span> Incident Command</div>
 <div class="sx-subtitle">Investigate suspicious activity. Connect evidence. Prioritize the next action.</div>
 <div class="sx-status">● ANALYSIS READY</div>
</div>
""", unsafe_allow_html=True)

status_col1, status_col2 = st.columns([3, 1])
with status_col1:
    st.caption(f"DATA SOURCE  /  {source_label}  ·  {len(events):,} valid timestamped events")
with status_col2:
    st.caption(f"UPDATED  /  {datetime.now().strftime('%H:%M:%S')}")

tabs = st.tabs(["◈ Command Center", "⌕ Event Explorer", "⤳ Attack Storylines",
                "◎ Threat Context", "☷ Response Playbooks", "⇩ Reports & Methodology"])

# -------------------- Command Center --------------------
with tabs[0]:
    critical = int((alerts["severity"] == "CRITICAL").sum()) if not alerts.empty else 0
    high = int((alerts["severity"] == "HIGH").sum()) if not alerts.empty else 0
    clusters = alerts[["entity", "source_ip"]].drop_duplicates().shape[0] if not alerts.empty else 0
    cols = st.columns(4)
    metrics = [
        ("EVENTS ANALYZED", f"{len(events):,}", "Timestamped records"),
        ("DETECTIONS", f"{len(alerts):,}", "Rule-triggered candidates"),
        ("HIGH / CRITICAL", f"{high+critical:,}", "Priority for triage"),
        ("IDENTITY / IP PAIRS", f"{clusters:,}", "Observed alert pairs")
    ]
    for col, (label, value, foot) in zip(cols, metrics):
        with col:
            st.markdown(f'<div class="sx-card"><div class="sx-card-label">{label}</div><div class="sx-card-value">{value}</div><div class="sx-card-foot">{foot}</div></div>', unsafe_allow_html=True)

    st.markdown("")
    left, right = st.columns([1.7, 1])
    with left:
        st.markdown('<div class="sx-section"><div class="sx-section-bar"></div><h3 style="margin:0">Priority incident queue</h3></div>', unsafe_allow_html=True)
        if not alerts.empty:
            q = alerts.copy()
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            q["priority_order"] = q["severity"].map(order)
            q = q.sort_values(["priority_order", "risk_score"], ascending=[True, False]).reset_index(drop=True)
            q["case_id"] = [f"SX-{1001+i:04d}" for i in range(len(q))]
            st.dataframe(q[["case_id", "severity", "rule", "entity", "source_ip", "risk_score"]].rename(
                columns={"case_id":"CASE ID","severity":"PRIORITY","rule":"DETECTION","entity":"IDENTITY","source_ip":"SOURCE IP","risk_score":"RISK"}),
                use_container_width=True, hide_index=True, height=340)
            selected = st.selectbox("Open an incident", q.index, format_func=lambda i:
                f"{q.loc[i,'case_id']} · {q.loc[i,'severity']} · {q.loc[i,'rule']} · {q.loc[i,'entity']}")
            incident = q.loc[selected]
            with st.container(border=True):
                st.markdown(f"**{incident['case_id']} · {incident['rule']}**")
                a, b, c = st.columns(3)
                a.metric("Priority", incident["severity"])
                b.metric("Risk score", f"{incident['risk_score']}/100")
                c.metric("Related events", int(incident["event_count"]))
                st.write(incident["explanation"])
                st.caption("Evidence row references: " + str(incident["evidence_rows"]))
                st.markdown("**Recommended next validation**")
                st.write(incident["next_validation"])
                st.markdown("**Response guidance**")
                st.write(incident["recommended_action"])
                st.markdown("**Evidence-driven next checks**")
                for check in next_checks(events, incident):
                    st.markdown(f"**P{check['Priority']} · {check['Next check']}** — {check['Why']}")
                    st.caption("Collect: " + check["Evidence to collect"])
        else:
            st.success("No detections matched the current rules.")
    with right:
        st.markdown('<div class="sx-section"><div class="sx-section-bar"></div><h3 style="margin:0">Severity distribution</h3></div>', unsafe_allow_html=True)
        if not alerts.empty:
            st.bar_chart(alerts.groupby("severity").size())
        else:
            st.info("No detections to chart.")
        st.markdown('<div class="sx-section"><div class="sx-section-bar"></div><h3 style="margin:0">Event volume over time</h3></div>', unsafe_allow_html=True)
        st.area_chart(events.set_index("timestamp").resample("15min").size().rename("Events"))
        st.markdown('<div class="sx-section"><div class="sx-section-bar"></div><h3 style="margin:0">Top detection types</h3></div>', unsafe_allow_html=True)
        if not alerts.empty:
            st.bar_chart(alerts.groupby("rule").size().sort_values().tail(7))

    st.info("Detections are rule-triggered candidates, not confirmed breaches. Scores are prioritization heuristics, not probabilities.")

# -------------------- Event Explorer --------------------
with tabs[1]:
    st.markdown("## Event Explorer")
    c1, c2, c3 = st.columns(3)
    uf = c1.selectbox("Identity", ["All"] + sorted(events["username"].unique().tolist()))
    ef = c2.selectbox("Event type", ["All"] + sorted(events["event"].unique().tolist()))
    sf = c3.selectbox("Status", ["All"] + sorted(events["status"].unique().tolist()))
    view = events.copy()
    if uf != "All": view = view[view["username"] == uf]
    if ef != "All": view = view[view["event"] == ef]
    if sf != "All": view = view[view["status"] == sf]
    st.caption(f"{len(view):,} records match the selected filters.")
    st.dataframe(view.drop(columns=["event_norm","status_norm"], errors="ignore"), use_container_width=True, hide_index=True)
    st.download_button("Export filtered events", view.to_csv(index=False), "filtered_events.csv", "text/csv")

# -------------------- Attack Storylines --------------------
with tabs[2]:
    st.markdown("## Attack Storylines")
    st.write("Explore event sequences associated with an identity or source IP. Correlation is a lead for investigation, not proof of attribution.")
    if alerts.empty:
        st.info("No alert-linked storylines available.")
    else:
        q = alerts.copy()
        q["thread"] = q["entity"] + " | " + q["source_ip"]
        options = q["thread"].drop_duplicates().tolist()
        chosen = st.selectbox("Investigation thread", options)
        user, ip = chosen.split(" | ", 1)
        timeline = events[(events["username"] == user) | (events["source_ip"] == ip)].sort_values("timestamp")
        st.markdown(f"**Identity:** `{user}`  ·  **Source IP:** `{ip}`")
        st.dataframe(timeline.drop(columns=["event_norm","status_norm"], errors="ignore").head(150),
                     use_container_width=True, hide_index=True)
        for _, alert in q[q["thread"] == chosen].iterrows():
            with st.expander(f"{alert['severity']} · {alert['rule']}"):
                st.write(alert["explanation"])
                st.caption("Evidence rows: " + str(alert["evidence_rows"]))
                for check in next_checks(events, alert):
                    st.markdown(f"**P{check['Priority']} · {check['Next check']}**")
                    st.write(check["Why"])
                    st.caption("Collect: " + check["Evidence to collect"])

# -------------------- Threat Context --------------------
with tabs[3]:
    st.markdown("## Threat Context")
    st.caption("Observed indicators from the uploaded dataset; no external reputation lookup is performed.")
    context = events.groupby("source_ip").agg(
        event_count=("source_ip","size"), unique_users=("username","nunique"),
        event_types=("event","nunique"), first_seen=("timestamp","min"),
        last_seen=("timestamp","max")).reset_index().sort_values("event_count", ascending=False)
    st.dataframe(context, use_container_width=True, hide_index=True)
    search = st.text_input("Search across event fields")
    if search:
        matched = events[events.astype(str).apply(lambda col: col.str.contains(search, case=False, na=False)).any(axis=1)]
        st.dataframe(matched.drop(columns=["event_norm","status_norm"], errors="ignore"), use_container_width=True, hide_index=True)

# -------------------- Response Playbooks --------------------
with tabs[4]:
    st.markdown("## Response Playbooks")
    playbooks = {
        "Authentication anomalies": [
            "Validate the account owner, source device and sign-in context.",
            "Review identity-provider records and MFA outcomes.",
            "Check whether failures were followed by successful access.",
            "Preserve relevant evidence and follow approved account-protection procedures.",
            "Document the investigation outcome."
        ],
        "Privilege changes": [
            "Locate the change request and approval.",
            "Verify the actor's authorization.",
            "Review subsequent activity performed with elevated access.",
            "Escalate or contain only under approved incident-response procedures.",
            "Record evidence and remediation."
        ],
        "Potential data movement": [
            "Confirm the business purpose and data-owner approval.",
            "Review export volume, destination and access history.",
            "Preserve relevant logs and metadata.",
            "Escalate to the appropriate security or privacy team if warranted.",
            "Do not infer exfiltration from one event alone."
        ],
        "Security configuration changes": [
            "Verify the approved change and maintenance window.",
            "Compare before-and-after configuration.",
            "Confirm logging and MFA remain effective.",
            "Follow approved recovery procedures if the change was unauthorized.",
            "Document findings and review change controls."
        ]
    }
    selected_pb = st.selectbox("Playbook", list(playbooks.keys()))
    for i, step in enumerate(playbooks[selected_pb]):
        st.checkbox(step, key=f"pb_{selected_pb}_{i}")

# -------------------- Reports --------------------
with tabs[5]:
    st.markdown("## Reports & Methodology")
    report = {
        "product": "SentinelX",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source_label,
        "events_analyzed": len(events),
        "detections": alerts.to_dict(orient="records") if not alerts.empty else [],
        "methodology": "Rule-based detection, identity/IP correlation and evidence-gap heuristics.",
        "limitations": [
            "Rule-triggered detections require analyst validation.",
            "No live SIEM ingestion or external threat-intelligence lookup.",
            "Risk scores are heuristic priorities, not calibrated probabilities.",
            "Correlated events do not prove attribution."
        ]
    }
    st.download_button("Download investigation report (JSON)", json.dumps(report, indent=2, default=str),
                       "sentinelx_investigation_report.json", "application/json")
    st.download_button("Download detections (CSV)",
                       alerts.to_csv(index=False) if not alerts.empty else "severity,rule,entity,source_ip\n",
                       "sentinelx_detections.csv", "text/csv")
    st.markdown("### Detection methodology")
    st.write("The platform validates CSV fields, applies deterministic event rules, prioritizes findings, correlates events by identity/source IP, and recommends evidence to collect.")
    st.markdown("### Current limitations")
    st.write("This prototype does not ingest live SIEM streams, block IPs, disable accounts, query external reputation services, or prove malicious intent. The bundled dataset is synthetic test data.")
    st.markdown("### Evaluation metrics to report")
    st.write("Use labeled test cases to measure precision, recall, false-positive rate, correlation accuracy, and processing time.")

st.divider()
st.caption("SENTINELX · Incident intelligence prototype · Rule-based decision support · Analyst validation required")
