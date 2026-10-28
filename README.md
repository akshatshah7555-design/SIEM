# SentinelX — Explainable Cyber Threat Correlation & Investigation

## Updated features
- Professional dark SOC dashboard
- CSV event ingestion and normalization
- Rule-based detection for repeated authentication failures, failure-to-success sequences, privilege changes, data export, security configuration changes, and rejected change events
- Attack storyline view with source-row evidence
- **Evidence-driven next-check engine**: deterministic heuristics identify likely missing evidence and prioritize follow-up checks with explanations
- Event explorer, indicator context, response playbooks, JSON/CSV exports

## Run locally
```bash
pip install -r requirements.txt
streamlit run app.py
```

## Render settings
- Build command: `pip install -r requirements.txt`
- Start command: `streamlit run app.py --server.port $PORT --server.address 0.0.0.0`

## CSV schema
Required: `timestamp, username, source_ip, event, status`
Optional: `asset, details`

The detector supports common event names including `login_failure`, `login_success`, `privilege_change`, `data_export`, and `security_setting_change`.

## Important scope
SentinelX is an academic prototype. It processes uploaded/sample logs; it is not a production SIEM and does not perform live endpoint monitoring or automatic containment. The next-check engine uses transparent deterministic heuristics; it is not a trained AI model. Recommendations must be validated by an analyst. Market differentiation must be substantiated through a competitor review and measured evaluation, not asserted as an unverified first.
