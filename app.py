import streamlit as st
import pandas as pd
import json, io
from datetime import datetime

st.set_page_config(page_title='SentinelX | Security Intelligence', page_icon='🛡️', layout='wide', initial_sidebar_state='expanded')
st.markdown(r'''<style>
:root{color-scheme:dark} .stApp{background:#080b16;color:#e8ecf8}.block-container{padding-top:1rem;padding-bottom:2rem;max-width:1700px}
[data-testid="stSidebar"]{background:#0b1020;border-right:1px solid #222a43}
[data-testid="stMetric"]{background:linear-gradient(145deg,#11182a,#0e1424);border:1px solid #252d48;border-radius:14px;padding:15px 17px;min-height:105px}
[data-testid="stMetricLabel"]{color:#a8b4d2!important;font-size:.83rem}[data-testid="stMetricValue"]{color:#f6f8ff!important;font-weight:750}
.stTabs [data-baseweb="tab-list"]{gap:22px;background:#0b1020;border-bottom:1px solid #29314a;padding:0 8px}.stTabs [data-baseweb="tab"]{height:48px;color:#a9b6d2}.stTabs [aria-selected="true"]{color:#7ea6ff!important;border-bottom-color:#648bff!important}
[data-testid="stVerticalBlockBorderWrapper"]{border-color:#252d48!important;border-radius:14px!important;background:#0d1221}
[data-testid="stDataFrame"]{border:1px solid #252d48;border-radius:10px;overflow:hidden}
.stButton>button,.stDownloadButton>button{border:1px solid #34456e;border-radius:8px;background:#151f37;color:#e9efff}
.stSelectbox label,.stRadio label,.stSlider label,.stFileUploader label{color:#b6c3df!important}
hr{border-color:#242d46}.sx-brand{display:flex;align-items:center;gap:12px;padding:3px 0 16px}.sx-logo{width:38px;height:38px;display:flex;align-items:center;justify-content:center;border-radius:11px;background:linear-gradient(135deg,#304caa,#172451);font-size:21px}.sx-brand h1{font-size:1.35rem;margin:0;color:#f7f9ff}.sx-brand p{font-size:.75rem;margin:2px 0 0;color:#8d9bbd}.sx-head{display:flex;justify-content:space-between;align-items:center;margin:3px 0 16px}.sx-head h2{font-size:1.25rem;margin:0;color:#f1f4ff}.sx-head span{color:#95a4c5;font-size:.8rem}.sx-panel{border:1px solid #252d48;background:linear-gradient(145deg,#101627,#0d1220);border-radius:14px;padding:16px;margin-bottom:12px;min-height:150px}.sx-panel h4{font-size:.9rem;margin:0 0 12px;color:#e2e8fb}.sx-muted{color:#8796b7;font-size:.78rem}.sx-alert{padding:10px 12px;border:1px solid #493047;border-radius:9px;background:#1b1425;margin:7px 0}.sx-pill{display:inline-block;padding:3px 7px;border-radius:99px;font-size:.68rem;background:#35202b;color:#ff9eae;margin-right:7px}.sx-status{color:#73e2b2;font-size:.78rem}
</style>''', unsafe_allow_html=True)
st.markdown('<div class="sx-brand"><div class="sx-logo">🛡️</div><div><h1>SentinelX</h1><p>THREAT INTELLIGENCE & SECURITY OPERATIONS</p></div></div>', unsafe_allow_html=True)

SAMPLE = '''timestamp,username,source_ip,event,status,asset,details
2026-10-28 09:00:01,akshay,198.51.100.23,login,failed,vpn-gateway,invalid password
2026-10-28 09:00:12,akshay,198.51.100.23,login,failed,vpn-gateway,invalid password
2026-10-28 09:00:20,akshay,198.51.100.23,login,failed,vpn-gateway,invalid password
2026-10-28 09:00:29,akshay,198.51.100.23,login,failed,vpn-gateway,invalid password
2026-10-28 09:00:40,akshay,198.51.100.23,login,failed,vpn-gateway,invalid password
2026-10-28 09:02:11,akshay,198.51.100.23,login,success,vpn-gateway,successful login after failures
2026-10-28 09:04:02,akshay,198.51.100.23,privilege_change,success,identity-service,role changed to administrator
2026-10-28 09:05:18,mira,192.0.2.44,login,success,finance-portal,normal login
2026-10-28 09:07:00,mira,192.0.2.44,login,failed,finance-portal,expired password
2026-10-28 09:09:31,svc_backup,203.0.113.77,login,success,backup-server,service account login
2026-10-28 09:10:10,akshay,198.51.100.23,data_export,success,customer-db,bulk export initiated
2026-10-28 09:12:42,akshay,198.51.100.23,security_setting_change,success,identity-service,mfa disabled
2026-10-28 09:13:08,akshay,198.51.100.23,login,success,customer-db,access from same source
2026-10-28 09:15:21,dev,192.0.2.19,change,failed,prod-api,change without approval reference
'''
REQUIRED={'timestamp','username','source_ip','event','status'}

@st.cache_data
def load_sample(): return pd.read_csv(io.StringIO(SAMPLE))

def analyze(raw, threshold=4):
    df=raw.copy()
    missing=REQUIRED-set(df.columns)
    if missing: raise ValueError('Missing required CSV columns: '+', '.join(sorted(missing)))
    for c in ['username','source_ip','event','status']:
        df[c]=df[c].fillna('unknown').astype(str).str.strip()
    if 'asset' not in df: df['asset']='unspecified'
    if 'details' not in df: df['details']=''
    df['timestamp']=pd.to_datetime(df['timestamp'],errors='coerce')
    df=df.dropna(subset=['timestamp']).sort_values('timestamp').reset_index(drop=True)
    df['event_norm']=df['event'].str.lower().str.replace(' ','_',regex=False)
    df['status_norm']=df['status'].str.lower()
    alerts=[]
    def add(sev, rule, user, ip, rows, explanation, next_check, response, points):
        alerts.append({'severity':sev,'rule':rule,'entity':str(user),'source_ip':str(ip),'event_count':len(rows),'first_seen':rows.timestamp.min().strftime('%Y-%m-%d %H:%M:%S'),'last_seen':rows.timestamp.max().strftime('%Y-%m-%d %H:%M:%S'),'evidence_rows':', '.join(str(int(x)+2) for x in rows.index[:12]),'explanation':explanation,'next_validation':next_check,'recommended_action':response,'risk_score':min(100,points)})
    auth_events=['login','login_failure','login_success','authentication','auth','authentication_failure','authentication_success','failed_login','successful_login','vpn_login']
    fail=df[(df.event_norm.isin(auth_events)) & df.status_norm.isin(['failed','failure','denied','blocked','error'])]
    for (u,ip),g in fail.groupby(['username','source_ip']):
        if len(g)>=threshold:
            add('HIGH','Repeated authentication failures',u,ip,g,f'{len(g)} failed authentication events for the same user and source; configured threshold is {threshold}.','Check whether a successful login followed these failures and confirm the source with the user.','Review identity-provider logs; consider a temporary protective control according to incident policy.',72+min(20,len(g)))
    # failure -> success from same user/IP within 20 minutes
    for (u,ip),g in df.groupby(['username','source_ip']):
        fg=g[g.status_norm.isin(['failed','failure','denied','blocked'])]
        sg=g[(g.status_norm.isin(['success','successful','allowed'])) & g.event_norm.isin(auth_events)]
        if not fg.empty and not sg.empty:
            for _,s in sg.iterrows():
                prior=fg[fg.timestamp.between(s.timestamp-pd.Timedelta(minutes=20),s.timestamp)]
                if len(prior)>=2:
                    add('CRITICAL','Failure-to-success sequence',u,ip,g[(g.timestamp>=prior.timestamp.min())&(g.timestamp<=s.timestamp)],f'{len(prior)} failed authentication attempts were followed by a successful login within 20 minutes from the same user/source pair. This pattern may indicate account compromise.','Validate MFA outcome, device identity, geolocation context and whether the user recognizes the session.','Escalate for analyst review; revoke sessions or reset credentials only under approved incident procedures.',92)
                    break
    for _,r in df[df.event_norm.isin(['privilege_change','role_change','privilege_escalation','admin_role_granted','privilege_escalation_attempt'])].iterrows():
        add('HIGH','Privilege or role change',r.username,r.source_ip,df.loc[[r.name]],f'Privilege-related event recorded on asset {r.asset}. Context: {r.details}.','Confirm an approved change/request and verify the actor had authority.','Review identity audit trail and remove unauthorized privilege only after validation.',78)
    for _,r in df[df.event_norm.isin(['data_export','bulk_download','mass_download','database_export','bulk_data_export'])].iterrows():
        add('HIGH','Potential bulk data movement',r.username,r.source_ip,df.loc[[r.name]],f'Data-export event observed on {r.asset}. A single event does not prove exfiltration.','Check export volume, business purpose, destination, and preceding authentication/privilege events.','Preserve relevant logs and escalate to the data owner for validation.',76)
    for _,r in df[df.event_norm.isin(['security_setting_change','mfa_disabled','logging_disabled','audit_logging_disabled','firewall_rule_change'])].iterrows():
        add('HIGH','Security control configuration change',r.username,r.source_ip,df.loc[[r.name]],f'Security-related configuration change observed: {r.details}.','Confirm the change ticket, approver, and before/after configuration.','Verify logging and MFA posture; follow change-control and incident procedures.',82)
    for _,r in df[df.event_norm.isin(['change','deployment','config_change']) & df.status_norm.isin(['failed','denied','rejected'])].iterrows():
        add('MEDIUM','Failed or rejected change event',r.username,r.source_ip,df.loc[[r.name]],f'Change event on {r.asset} was marked {r.status}. Details: {r.details}.','Check the change record, approval reference and deployment logs.','Investigate repeated attempts and reconcile with the authorized change calendar.',48)
    # Correlate all alerts into user/IP storylines; avoid duplicate identical rule alerts
    out=pd.DataFrame(alerts)
    if not out.empty:
        out=out.drop_duplicates(subset=['rule','entity','source_ip','first_seen']).sort_values('risk_score',ascending=False).reset_index(drop=True)
    return df,out


def next_check_engine(events, alert):
    """Evidence-gap analysis and deterministic next-check prioritization.
    This is a transparent decision-support heuristic, not an ML model.
    """
    user = str(alert.get('entity', ''))
    ip = str(alert.get('source_ip', ''))
    try:
        start = pd.to_datetime(alert.get('first_seen'))
        end = pd.to_datetime(alert.get('last_seen'))
        window = events[(events['timestamp'] >= start - pd.Timedelta(minutes=20)) &
                        (events['timestamp'] <= end + pd.Timedelta(minutes=20))]
    except Exception:
        window = events.copy()
    related = window[(window['username'].astype(str) == user) |
                     (window['source_ip'].astype(str) == ip)]
    ev = set(related['event_norm'].astype(str))
    details = ' '.join(related.get('details', pd.Series(dtype=str)).fillna('').astype(str).str.lower().tolist())
    checks = []
    def add(priority, check, reason, expected):
        checks.append({'priority': priority, 'check': check, 'why': reason, 'evidence_to_seek': expected})
    rule = str(alert.get('rule', '')).lower()
    if 'authentication' in rule or 'failure-to-success' in rule:
        add(1, 'Validate MFA and identity-provider outcome',
            'Authentication activity is the entry point of this storyline.',
            'MFA result, identity-provider audit record, session ID')
        if not any(x in ev for x in ['mfa_challenge','mfa_result','mfa_verification']):
            add(1, 'Evidence gap: MFA outcome not present in uploaded events',
                'The supplied records do not contain an explicit MFA result event.',
                'MFA success/failure record from the identity provider')
        if not any(x in ev for x in ['device_posture','endpoint_check','device_compliance']):
            add(2, 'Check device identity and posture',
                'The current dataset does not show a device compliance/posture event.',
                'Device ID, managed-device status, endpoint telemetry')
        if not any(x in ev for x in ['geo_login','location_check','impossible_travel']):
            add(3, 'Verify sign-in context',
                'Location or sign-in risk context is not present in this event window.',
                'Authorized location, VPN context, sign-in risk telemetry')
    if 'privilege' in rule or any(x in ev for x in ['privilege_change','role_change','privilege_escalation','admin_role_granted']):
        if not any(x in details for x in ['ticket','approved','change request','request id']):
            add(1, 'Verify approval evidence for privilege change',
                'No obvious approval reference was found in nearby event details.',
                'Change/request ID, approver, role assignment audit record')
        add(2, 'Review actions after privilege elevation',
            'Privilege changes can increase impact if followed by sensitive actions.',
            'Subsequent admin actions, accessed assets, session audit trail')
    if 'data' in rule or any(x in ev for x in ['data_export','bulk_download','mass_download','database_export','bulk_data_export']):
        if not any(x in details for x in ['approved export','business purpose','ticket']):
            add(1, 'Validate export purpose and data-owner approval',
                'The available event details do not establish an approved business purpose.',
                'Export request, data-owner approval, ticket/reference')
        add(2, 'Inspect export volume and destination',
            'A data-export event alone does not prove exfiltration.',
            'Bytes/records exported, destination, query/job ID, DLP records')
    if 'security control' in rule or any(x in ev for x in ['security_setting_change','mfa_disabled','logging_disabled','audit_logging_disabled','firewall_rule_change']):
        if not any(x in details for x in ['ticket','approved','change request','maintenance window']):
            add(1, 'Confirm change request and maintenance window',
                'No approval evidence is apparent in the supplied event details.',
                'Change ticket, approver, before/after configuration')
        add(2, 'Check telemetry continuity after the change',
            'A logging or security-setting change may reduce visibility.',
            'Audit pipeline status, log-source heartbeat, configuration diff')
    if not checks:
        add(1, 'Confirm event with system owner',
            'The rule fired, but additional context is required before making a conclusion.',
            'Owner confirmation, source-system audit record, related events')
    # Keep only the highest-priority occurrence of each check label.
    seen = set()
    unique = []
    for item in sorted(checks, key=lambda x: x['priority']):
        if item['check'] not in seen:
            unique.append(item); seen.add(item['check'])
    return unique[:5]

with st.sidebar:
    st.header('Control Center')
    st.caption('DETECTION CONFIGURATION')
    threshold=st.slider('Failed-login alert threshold',3,10,4)
    source=st.radio('Data source',['Synthetic scenario','Upload CSV'],index=0)
    uploaded=st.file_uploader('Upload security events (.csv)',type=['csv']) if source=='Upload CSV' else None
    st.caption('Required columns: timestamp, username, source_ip, event, status. Optional: asset, details.')
    st.download_button('Download sample CSV',SAMPLE,file_name='sentinelx_sample_events.csv',mime='text/csv',use_container_width=True)
try:
    raw=pd.read_csv(uploaded) if source=='Upload CSV' and uploaded is not None else load_sample()
    if source=='Upload CSV' and uploaded is None: st.info('Upload a CSV to begin, or switch to Synthetic scenario for a guided demo.'); st.stop()
    events,alerts=analyze(raw,threshold)
except Exception as e:
    st.error(f'Unable to process input: {e}'); st.stop()

# Top navigation tabs
tabs=st.tabs(['Executive Overview','Event Explorer','Attack Storylines','Threat Context','Response Playbooks','Export & Methodology'])
with tabs[0]:
    st.markdown('<div class="sx-head"><h2>Security Operations Overview</h2><span>● ANALYSIS READY &nbsp; | &nbsp; Rule-based triage</span></div>',unsafe_allow_html=True)
    m1,m2,m3,m4,m5=st.columns(5)
    m1.metric('TOTAL EVENTS',f'{len(events):,}', 'Parsed')
    m2.metric('ACTIVE ALERTS',f'{len(alerts):,}', 'Rule detections')
    critical=int((alerts.severity=='CRITICAL').sum()) if not alerts.empty else 0
    m3.metric('CRITICAL INCIDENTS',f'{critical:,}', 'Needs validation')
    m4.metric('SUSPICIOUS USERS',events[events.username.isin(alerts.entity.unique())].username.nunique() if not alerts.empty else 0, 'Correlated')
    m5.metric('SOURCE IPs',events.source_ip.nunique(), 'Observed')
    left,mid,right=st.columns([.82,1.5,1.55],gap='medium')
    with left:
        st.markdown('<div class="sx-panel"><h4>Threat Distribution by Severity</h4>',unsafe_allow_html=True)
        if not alerts.empty:
            sev=alerts.groupby('severity').size().reindex(['CRITICAL','HIGH','MEDIUM','LOW'],fill_value=0)
            st.bar_chart(sev, color='#ef526b', height=190)
            st.markdown('<span class="sx-muted">Severity is rule-based and requires analyst validation.</span></div>',unsafe_allow_html=True)
        else: st.info('No detections for current input.')
        st.markdown('<div class="sx-panel"><h4>Detection Summary</h4>',unsafe_allow_html=True)
        if not alerts.empty:
            st.metric('Average risk score',f"{alerts.risk_score.mean():.0f}/100")
            st.metric('High / Critical',int(alerts.severity.isin(['HIGH','CRITICAL']).sum()))
        st.markdown('<span class="sx-muted">Scores are prioritization indicators, not compromise probabilities.</span></div>',unsafe_allow_html=True)
    with mid:
        st.markdown('<div class="sx-panel"><h4>Attack Storyline & Correlated Events</h4><span class="sx-muted">Related activity grouped by user and source address</span>',unsafe_allow_html=True)
        if not alerts.empty:
            for _,r in alerts.head(5).iterrows():
                color='CRITICAL' if r.severity=='CRITICAL' else 'HIGH' if r.severity=='HIGH' else 'MEDIUM'
                st.markdown(f'<div class="sx-alert"><span class="sx-pill">{color}</span><b>{r["rule"]}</b><br><span class="sx-muted">{r["entity"]} · {r["source_ip"]} · Risk {r["risk_score"]}</span></div>',unsafe_allow_html=True)
        else: st.info('No storylines found.')
        st.markdown('</div>',unsafe_allow_html=True)
        st.markdown('<div class="sx-panel"><h4>Most Active Source IPs</h4>',unsafe_allow_html=True)
        ipcounts=events.groupby('source_ip').size().sort_values(ascending=False).head(5).rename('Events')
        st.bar_chart(ipcounts,color='#648bff',height=180)
        st.markdown('</div>',unsafe_allow_html=True)
    with right:
        st.markdown('<div class="sx-panel"><h4>Threat Activity Over Time</h4><span class="sx-muted">Events per timestamp interval</span>',unsafe_allow_html=True)
        trend=events.set_index('timestamp').resample('2min').size().rename('Events')
        st.line_chart(trend,color='#ff627e',height=245)
        st.markdown('</div>',unsafe_allow_html=True)
        st.markdown('<div class="sx-panel"><h4>Breakdown by Detection Type</h4>',unsafe_allow_html=True)
        if not alerts.empty:
            byrule=alerts.groupby('rule').size().sort_values(ascending=True).tail(7).rename('Alerts')
            st.bar_chart(byrule,color='#648bff',height=220)
        else: st.info('No detection types to show.')
        st.markdown('</div>',unsafe_allow_html=True)
    st.caption('SentinelX academic prototype • Data shown is synthetic unless a CSV is uploaded • Correlation does not prove attribution.')
with tabs[1]:
    st.subheader('Normalized event explorer')
    c1,c2,c3=st.columns(3)
    users=['All']+sorted(events.username.unique().tolist()); selected_user=c1.selectbox('Filter user',users)
    event_types=['All']+sorted(events.event.unique().tolist()); selected_event=c2.selectbox('Filter event type',event_types)
    statuses=['All']+sorted(events.status.unique().tolist()); selected_status=c3.selectbox('Filter status',statuses)
    filt=events.copy()
    if selected_user!='All': filt=filt[filt.username==selected_user]
    if selected_event!='All': filt=filt.event==selected_event
    if selected_status!='All': filt=filt.status==selected_status
    st.dataframe(filt.drop(columns=['event_norm','status_norm'],errors='ignore'),use_container_width=True,hide_index=True)
    st.caption(f'Showing {len(filt)} of {len(events)} valid timestamped events.')
with tabs[2]:
    st.subheader('Attack Storyline Engine')
    st.write('This prototype groups related detections by account and source IP, orders them by time, surfaces likely evidence gaps, and prioritizes follow-up checks with an explanation for each recommendation.')
    if alerts.empty: st.info('No storylines available for this dataset.')
    else:
        pairs=alerts.assign(story=alerts.entity+' | '+alerts.source_ip)['story'].drop_duplicates().tolist()
        chosen=st.selectbox('Select investigation thread',pairs)
        user,ip=chosen.split(' | ',1)
        related=alerts[(alerts.entity==user)&(alerts.source_ip==ip)].sort_values('first_seen')
        st.markdown(f'**Investigation entity:** `{user}`  ·  **Source:** `{ip}`')
        for _,r in related.iterrows():
            with st.expander(f"{r['first_seen']} — {r['severity']}: {r['rule']}",expanded=True):
                st.write('**Evidence explanation:** '+r['explanation'])
                st.write('**Source CSV row(s):** '+r['evidence_rows'])
                st.write('**Next validation question:** '+r['next_validation'])
                st.write('**Recommended next step:** '+r['recommended_action'])
                st.markdown('**Evidence-driven next checks**')
                check_items = next_check_engine(events, r)
                for chk in check_items:
                    st.markdown(f"**P{chk['priority']} · {chk['check']}**")
                    st.caption(chk['why'] + ' Evidence to seek: ' + chk['evidence_to_seek'])
        st.info('Storyline association is based on shared username/source IP and event timestamps; it does not establish attribution or prove an attack.')
with tabs[3]:
    st.subheader('Threat context & indicator handling')
    st.write('SentinelX extracts observed source IPs and summarizes their activity. It does not label an IP malicious based only on its appearance.')
    context=events.groupby('source_ip').agg(events=('source_ip','size'),users=('username','nunique'),event_types=('event','nunique'),first_seen=('timestamp','min'),last_seen=('timestamp','max')).reset_index().sort_values('events',ascending=False)
    st.dataframe(context,use_container_width=True,hide_index=True)
    indicator=st.text_input('Inspect an indicator from this dataset (IP, username, or asset)')
    if indicator:
        subset=events[events.astype(str).apply(lambda col: col.str.contains(indicator,case=False,na=False)).any(axis=1)]
        st.write(f'{len(subset)} matching event(s)')
        st.dataframe(subset.drop(columns=['event_norm','status_norm'],errors='ignore'),use_container_width=True,hide_index=True)
    st.warning('No external threat-intelligence service is queried. Reserved sample IP ranges are used for safe demonstration; enrich real indicators only through authorized sources.')
with tabs[4]:
    st.subheader('Response playbooks')
    playbooks={
      'Repeated authentication failures':['Confirm account owner and source device.','Review identity-provider logs and MFA results.','Check whether failures are followed by success.','Apply lockout/session controls according to approved policy.','Record evidence and close only after validation.'],
      'Failure-to-success sequence':['Validate session/device and MFA outcome.','Review activity after successful authentication.','Contact account owner through a trusted channel.','Preserve relevant logs; contain account/session if confirmed.','Document timeline, scope, decisions and recovery.'],
      'Privilege or role change':['Locate change ticket and approval.','Confirm actor authorization and role assignment.','Review actions performed with elevated access.','Revoke unauthorized access under approved process.','Capture evidence and review least-privilege controls.'],
      'Potential bulk data movement':['Confirm business purpose and data owner approval.','Inspect volume, destination, and access trail.','Preserve logs and relevant system metadata.','Escalate to incident response/privacy teams as appropriate.','Document confirmed scope; avoid assuming exfiltration from one event.'],
      'Security control configuration change':['Verify approved change request and maintenance window.','Compare before/after settings.','Confirm MFA/logging remain effective.','Restore secure settings if unauthorized, following policy.','Review related events and document approval trail.']}
    selected=st.selectbox('Choose playbook',list(playbooks.keys()))
    st.markdown('#### Analyst checklist')
    for i,step in enumerate(playbooks[selected]): st.checkbox(step,key=f'{selected}_{i}')
    st.caption('Playbooks are decision support. Analysts must follow organizational authorization and incident procedures.')
with tabs[5]:
    st.subheader('Export investigation artefacts')
    report={'product':'SentinelX','generated_at':datetime.utcnow().isoformat()+'Z','event_count':len(events),'alert_count':len(alerts),'method':'Deterministic rule-based event triage, user/source correlation, and evidence-gap next-check heuristics','limitations':['Synthetic data may be used','No live SIEM ingestion','No external threat-intelligence lookup','Risk scores are not calibrated probabilities','Correlated events do not prove attribution'], 'alerts':alerts.to_dict(orient='records') if not alerts.empty else []}
    st.download_button('Download alert report (JSON)',json.dumps(report,indent=2,default=str),file_name='sentinelx_investigation_report.json',mime='application/json')
    st.download_button('Download detections (CSV)',alerts.to_csv(index=False) if not alerts.empty else 'severity,rule,entity,source_ip\n',file_name='sentinelx_alerts.csv',mime='text/csv')
    st.markdown('#### Methodology and scope')
    st.markdown('''- **Inputs:** timestamped event CSVs with username, source IP, event, and status fields.\n- **Detection:** configurable failed-login threshold; failure-to-success sequence within a 20-minute window; privilege changes; data-export events; security-setting changes; rejected change events.\n- **Explainability:** each alert includes the rule, supporting event rows, rationale, next validation question, and recommended response.\n- **Proposed contribution to evaluate:** evidence-linked storyline grouping plus deterministic evidence-gap detection and prioritized next-check recommendations. Compare against independent rule alerts on a labelled synthetic dataset; do not claim market-wide uniqueness without comparative testing.\n- **Limitations:** not a production SIEM, no endpoint telemetry, no automated containment, and no external IOC reputation feed.''')

st.divider()
st.caption('SentinelX academic prototype v0.2 • Evidence-gap heuristics are deterministic decision support, not proof of compromise • Use synthetic or authorized data only')
