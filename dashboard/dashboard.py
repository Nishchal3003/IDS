"""
dashboard.py  -  Phase 5 Streamlit monitoring dashboard.

Adapted from BSaiCharan-GH/XAI-NIDS dashboard/dashboard.py.
Extended to support 9-class coarse labels, multi-model results,
and the current workspace LabelEncoder inverse-mapping.

Run:
    python main.py dashboard
    OR directly:
    streamlit run dashboard/dashboard.py
"""

import sys
import os
import time

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# Add project root to path so imports work when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard_bridge import bridge_instance


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title = "Intelligent NIDS Dashboard",
    page_icon  = "🛡️",
    layout     = "wide",
)

st.markdown("# 🛡️ Intelligent Network Intrusion Detection System")
st.caption(
    "Real-time monitoring • PortScan & DoS detection • "
    "Random Forest / XGBoost / MLP inference • SHAP explanations"
)


# ---------------------------------------------------------------------------
# Utility helpers  (from XAI-NIDS dashboard.py)
# ---------------------------------------------------------------------------

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

ATTACK_COLOURS = {
    "BENIGN"      : "#27ae60",
    "PortScan"    : "#e67e22",
    "DoS"         : "#c0392b",
    "DDoS"        : "#8e44ad",
    "BruteForce"  : "#2980b9",
    "WebAttack"   : "#d35400",
    "Botnet"      : "#7f8c8d",
    "Infiltration": "#1abc9c",
    "Heartbleed"  : "#e74c3c",
    "NO_MODEL"    : "#bdc3c7",
    "UNKNOWN"     : "#95a5a6",
}

SEVERITY_EMOJI = {
    "NONE"    : "✅",
    "LOW"     : "🟡",
    "MEDIUM"  : "🟠",
    "HIGH"    : "🔴",
    "CRITICAL": "🚨",
}

SEVERITY_COLOURS = {
    "NONE"    : "#27ae60",
    "LOW"     : "#f39c12",
    "MEDIUM"  : "#e67e22",
    "HIGH"    : "#e74c3c",
    "CRITICAL": "#8e44ad",
}


def _protocol_name(value):
    try:
        return PROTOCOL_NAMES.get(int(float(value)), str(value))
    except (TypeError, ValueError):
        return str(value)


def _confidence_pct(value):
    try:
        return "{:.1f}%".format(float(value) * 100)
    except (TypeError, ValueError):
        return "N/A"


def _label_colour(label):
    return ATTACK_COLOURS.get(str(label), "#95a5a6")


def _decision_counts(flows):
    counts = {}
    for flow in flows:
        label = str(flow.get("final_decision", flow.get("ml_prediction", "UNKNOWN")))
        counts[label] = counts.get(label, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Sidebar controls
# ---------------------------------------------------------------------------

st.sidebar.header("Dashboard Controls")
auto_refresh   = st.sidebar.checkbox("Auto Refresh", value=True)
refresh_rate   = st.sidebar.slider("Refresh Interval (seconds)", 1, 10, 2)

st.sidebar.markdown("---")
st.sidebar.subheader("Detection Thresholds")
ps_min_ports  = st.sidebar.slider("PortScan: min unique ports", 5, 30, 10)
dos_min_syn   = st.sidebar.slider("DoS: min SYN packets", 10, 100, 20)
st.sidebar.caption("Changes take effect on next capture restart.")

if st.sidebar.button("Reset Live Counters"):
    try:
        bridge_instance.reset_counters()
        st.sidebar.success("Counters reset.")
    except Exception as _e:
        st.sidebar.error(f"Reset failed: {_e}")


# ---------------------------------------------------------------------------
# Fetch live state  (crash-proof: bad DB read returns safe empty state)
# ---------------------------------------------------------------------------

_EMPTY_SNAPSHOT = {
    "recent_flows"   : [],
    "alerts"         : [],
    "total_packets"  : 0,
    "active_flows"   : 0,
    "port_scan_count": 0,
    "dos_count"      : 0,
}

try:
    snapshot = bridge_instance.get_snapshot()
except Exception:
    snapshot = _EMPTY_SNAPSHOT.copy()

recent_flows = snapshot.get("recent_flows", [])
alerts       = snapshot.get("alerts", [])
counts       = _decision_counts(recent_flows)

# Sidebar live-status indicator (placed here because it needs recent_flows)
st.sidebar.markdown("---")
if recent_flows:
    st.sidebar.success("Live data")
elif alerts:
    st.sidebar.success("Live data (alerts)")
else:
    st.sidebar.warning("Waiting for capture...")


# ---------------------------------------------------------------------------
# System overview metrics
# ---------------------------------------------------------------------------

st.markdown("### System Overview")
m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Flows Processed",  len(recent_flows))
m2.metric("Active Flows",     snapshot.get("active_flows", 0))
m3.metric("Threat Alerts",    len(alerts))
m4.metric("Port Scans",       snapshot.get("port_scan_count", 0))
m5.metric("DoS Events",       snapshot.get("dos_count", 0))

benign_pct = (
    counts.get("BENIGN", 0) / max(len(recent_flows), 1) * 100
)
st.caption(
    "Benign: {}/{} ({:.1f}%)  |  Live window: last {} flows".format(
        counts.get("BENIGN", 0), len(recent_flows), benign_pct, len(recent_flows)
    )
)
st.markdown("---")


# ---------------------------------------------------------------------------
# Latest alert banner
# ---------------------------------------------------------------------------

if alerts:
    latest = alerts[0]
    sev    = latest.get("severity", "HIGH" if latest.get("is_attack") else "NONE")
    emoji  = SEVERITY_EMOJI.get(sev, "🚨")
    sev_col= SEVERITY_COLOURS.get(sev, "#e74c3c")
    st.markdown(
        "<div style='border-left: 6px solid {col}; padding: 10px 16px; "
        "background: #1a1a1a; border-radius: 6px; margin-bottom: 8px;'>"
        "<b>{em} {sev} SEVERITY — {label}</b><br/>"
        "<span style='color:#aaa; font-size:0.9em'>"
        "{ts} &nbsp;|&nbsp; {src}:{sp} → {dst}:{dp}<br/>"
        "<i>{reason}</i><br/>"
        "<b>Action:</b> {action}"
        "</span></div>".format(
            col    = sev_col,
            em     = emoji,
            sev    = sev,
            label  = latest.get("final_decision", "UNKNOWN"),
            ts     = latest.get("timestamp", ""),
            src    = latest.get("src_ip", "?"),
            sp     = latest.get("src_port", "?"),
            dst    = latest.get("dst_ip", "?"),
            dp     = latest.get("dst_port", "?"),
            reason = latest.get("detection_reason", "N/A"),
            action = latest.get("recommended_action", ""),
        ),
        unsafe_allow_html=True,
    )
else:
    st.success("**SYSTEM STATUS** — No malicious traffic detected in the current live session.")


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tab_live, tab_xai, tab_chart, tab_history = st.tabs([
    "Live Traffic & Alerts",
    "XAI Explanations",
    "Attack Distribution",
    "Historical Logs",
])


# ----- Tab 1: Live Traffic ---------------------------------------------------
with tab_live:
    st.subheader("Recent Analysed Flows")
    if recent_flows:
        df = pd.DataFrame(recent_flows)
        display_cols = [
            "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
            "protocol", "ml_prediction", "confidence",
            "behavioural_detection", "final_decision", "detection_reason",
        ]
        available = [c for c in display_cols if c in df.columns]
        table     = df[available].copy()

        if "protocol" in table.columns:
            table["protocol"] = table["protocol"].apply(_protocol_name)
        if "confidence" in table.columns:
            table["confidence"] = table["confidence"].apply(_confidence_pct)

        st.dataframe(table, use_container_width=True)
    else:
        st.info("No flows yet. Start capture with: python main.py capture --live")

    if alerts:
        st.subheader("Active Alerts")
        for alert in alerts[:10]:
            label  = alert.get("final_decision", "UNKNOWN")
            sev    = alert.get("severity", "HIGH" if alert.get("is_attack") else "NONE")
            emoji  = SEVERITY_EMOJI.get(sev, "🚨")
            colour = SEVERITY_COLOURS.get(sev, _label_colour(label))
            method = alert.get("detection_method", "")
            action = alert.get("recommended_action", "")
            st.markdown(
                "<div style='border-left: 4px solid {col}; padding: 6px 12px; "
                "margin-bottom: 6px; background: #1e1e1e; border-radius: 4px;'>"
                "<b>{em} {sev} — {label}</b> "
                "<span style='color:#888;font-size:0.85em'>[{method}]</span><br/>"
                "{src} → {dst} | {reason}<br/>"
                "<span style='color:#aaa;font-size:0.85em'>{action}</span>"
                "</div>".format(
                    col    = colour,
                    em     = emoji,
                    sev    = sev,
                    label  = label,
                    method = method,
                    src    = alert.get("src_ip", "?"),
                    dst    = alert.get("dst_ip", "?"),
                    reason = alert.get("detection_reason", ""),
                    action = action,
                ),
                unsafe_allow_html=True,
            )


# ----- Tab 2: XAI Explanations -----------------------------------------------
with tab_xai:
    st.subheader("🧠 Attack Explanation Panel")

    # --- Feature name → plain English translation --------------------------
    FEATURE_PLAIN = {
        "Flow Duration"                    : "How long the connection lasted",
        "Total Fwd Packets"                : "Packets sent by the source",
        "Total Backward Packets"           : "Packets sent back by the server",
        "Total Length of Fwd Packets"      : "Total data sent by source (bytes)",
        "Total Length of Bwd Packets"      : "Total data sent back by server (bytes)",
        "Flow Bytes/s"                     : "Data transfer rate (bytes per second)",
        "Flow Packets/s"                   : "Packet rate (packets per second)",
        "Fwd Packet Length Mean"           : "Average size of packets from source",
        "Bwd Packet Length Mean"           : "Average size of server response packets",
        "Flow IAT Mean"                    : "Average time between packets",
        "Flow IAT Std"                     : "Variation in time between packets",
        "Fwd IAT Mean"                     : "Average gap between source packets",
        "Bwd IAT Mean"                     : "Average gap between server packets",
        "SYN Flag Count"                   : "Connection-start packets (SYN flags)",
        "ACK Flag Count"                   : "Acknowledgement packets (ACK flags)",
        "RST Flag Count"                   : "Connection-reset packets (RST flags)",
        "PSH Flag Count"                   : "Data-push packets (PSH flags)",
        "FIN Flag Count"                   : "Connection-close packets (FIN flags)",
        "Destination Port"                 : "Target port number",
        "Fwd Packets/s"                    : "Source outgoing packet rate",
        "Bwd Packets/s"                    : "Server response packet rate",
        "Packet Length Mean"               : "Average packet size overall",
        "Packet Length Std"                : "Variation in packet sizes",
        "Average Packet Size"              : "Mean packet size in the flow",
        "Init_Win_bytes_forward"           : "Initial receive window (source side)",
        "Init_Win_bytes_backward"          : "Initial receive window (server side)",
        "Active Mean"                      : "Average active connection time",
        "Idle Mean"                        : "Average idle time in the flow",
    }

    def _plain(feature_name: str) -> str:
        return FEATURE_PLAIN.get(feature_name, feature_name.replace("_", " ").title())

    def _contribution_bar(value: float) -> str:
        """Convert SHAP value to a visual bar + label."""
        abs_v = abs(value)
        if abs_v > 0.1:
            bars, label = "█████", "STRONG"
        elif abs_v > 0.05:
            bars, label = "████ ", "HIGH"
        elif abs_v > 0.02:
            bars, label = "███  ", "MEDIUM"
        elif abs_v > 0.005:
            bars, label = "██   ", "LOW"
        else:
            bars, label = "█    ", "MINOR"
        direction = "📈 Raises" if value > 0 else "📉 Lowers"
        return f"{direction} alert likelihood &nbsp; `{bars}` {label}"

    # --- Attack type → plain English explanation ---------------------------
    ATTACK_WHAT_HAPPENED = {
        "PortScan": (
            "A **port scan** was detected. The source IP rapidly contacted many "
            "different ports on this system in a very short time. "
            "Port scanning is a reconnaissance technique — an attacker probes a "
            "target to discover which services (ports) are open and potentially "
            "exploitable. It does not cause direct harm but typically precedes "
            "a targeted attack."
        ),
        "DoS": (
            "A **Denial of Service (DoS)** attack was detected. The source IP "
            "sent a very high volume of connection-start (SYN) packets to this "
            "system while almost never completing the handshake. This is known as "
            "a **SYN Flood** — it attempts to exhaust the server's connection "
            "resources, potentially making it unresponsive to legitimate users."
        ),
        "DDoS": (
            "A **Distributed Denial of Service (DDoS)** attack was detected. "
            "High-volume traffic from multiple sources overwhelms the target, "
            "aiming to disrupt normal service availability."
        ),
        "BruteForce": (
            "A **Brute Force** attack was detected. The attacker is making "
            "repeated rapid login or authentication attempts, trying many "
            "passwords or credentials to gain unauthorised access."
        ),
        "WebAttack": (
            "A **Web Application Attack** was detected. Abnormal HTTP traffic "
            "patterns suggest the attacker is attempting to exploit a "
            "vulnerability in a web application, such as SQL injection or XSS."
        ),
        "Botnet": (
            "**Botnet** activity was detected. Traffic patterns suggest this "
            "device may be communicating with a command-and-control server "
            "as part of a botnet — a network of compromised machines."
        ),
        "Infiltration": (
            "**Network infiltration** was detected. Traffic patterns suggest "
            "lateral movement or unauthorised data access within the network."
        ),
        "Heartbleed": (
            "A **Heartbleed** exploit attempt was detected (CVE-2014-0160). "
            "This TLS vulnerability allows attackers to read server memory "
            "and steal sensitive data like passwords or private keys."
        ),
    }

    # ── Load alerts from detections table (has SHAP + severity) ────────────
    history_all = bridge_instance.get_history(limit=50)
    attack_events = [
        h for h in history_all
        if h.get("final_decision") not in ("BENIGN", "UNKNOWN", "NO_MODEL", "")
    ] if history_all else []

    if not attack_events and not alerts:
        st.info(
            "No attacks detected yet. "
            "Run a test with: `python attacks/run_tests.py` "
            "while `python main.py capture --live` is active."
        )
    else:
        # Build selector from detections table (has SHAP) or fallback to alerts
        if attack_events:
            selector_items = {
                "{} — {} | {} → {}".format(
                    e.get("timestamp", ""), e.get("final_decision", ""),
                    e.get("src_ip", "?"), e.get("dst_ip", "?"),
                ): e
                for e in attack_events
            }
        else:
            selector_items = {
                "{} — {} | {} → {}".format(
                    a.get("timestamp", ""), a.get("final_decision", ""),
                    a.get("src_ip", "?"), a.get("dst_ip", "?"),
                ): a
                for a in alerts[:20]
            }

        selected_key = st.selectbox(
            "📌 Select an alert to explain:",
            options=list(selector_items.keys()),
            index=0,
        )
        chosen = selector_items.get(selected_key, {})

        if not chosen:
            st.warning("Could not load selected alert.")
        else:
            final      = chosen.get("final_decision", "UNKNOWN")
            ml_pred    = chosen.get("ml_prediction", "NO_MODEL")
            conf       = chosen.get("confidence", 0.0) or 0.0
            behav      = chosen.get("behavioural_detection") or ""
            method     = chosen.get("detection_method", "") or (
                "Behavioural" if behav else "ML"
            )
            reason     = chosen.get("detection_reason", "")
            sev        = chosen.get("severity", "HIGH")
            action     = chosen.get("recommended_action", "")
            src_ip     = chosen.get("src_ip", "?")
            dst_ip     = chosen.get("dst_ip", "?")
            sev_col    = SEVERITY_COLOURS.get(sev, "#e74c3c")
            sev_em     = SEVERITY_EMOJI.get(sev, "🚨")

            # ── Header banner ──────────────────────────────────────────────
            st.markdown(
                "<div style='border-left:6px solid {col}; padding:12px 16px; "
                "background:#1a1a1a; border-radius:6px; margin-bottom:12px;'>"
                "<h4 style='margin:0'>{em} {sev} SEVERITY &nbsp;—— {final}</h4>"
                "<p style='color:#aaa;margin:4px 0 0'>"
                "Source: <b>{src}</b> &rarr; Target: <b>{dst}</b> &nbsp;|"
                "&nbsp; Method: <b>{method}</b></p></div>".format(
                    col=sev_col, em=sev_em, sev=sev,
                    final=final, src=src_ip, dst=dst_ip, method=method,
                ),
                unsafe_allow_html=True,
            )

            # ── Plain-English attack description ───────────────────────────
            st.markdown("**🔍 What happened?**")
            description = ATTACK_WHAT_HAPPENED.get(
                final,
                f"A **{final}** type of attack was detected. "
                f"Detection reason: {reason}"
            )
            st.markdown(description)

            st.markdown("---")

            # ── Detection summary table ────────────────────────────────────
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**🛡️ Detection Details**")
                st.markdown(f"| | |\n|---|---|")
                st.markdown(f"| Threat type | **{final}** |")
                st.markdown(f"| Severity | **{sev_em} {sev}** |")
                st.markdown(f"| Detection method | **{method}** |")
                if conf and conf > 0:
                    st.markdown(f"| ML confidence | **{conf*100:.1f}%** |")
                else:
                    st.markdown(f"| ML confidence | N/A (behavioural rule) |")
                st.markdown(f"| ML prediction | {ml_pred} |")

            with col2:
                st.markdown("**📊 Evidence Summary**")
                st.markdown(f"> {reason}")
                if action:
                    st.markdown(f"**⚠️ Recommended Action:**")
                    st.info(action)

            st.markdown("---")

            # ── SHAP / Behavioural evidence ────────────────────────────────
            shap_raw = chosen.get("top_shap_features") or {}
            if isinstance(shap_raw, str):
                import json as _json
                try:
                    shap_raw = _json.loads(shap_raw)
                except Exception:
                    shap_raw = {}

            if method in ("Behavioural",) and not shap_raw:
                # Pure behavioural detection — show rule evidence, not SHAP
                st.markdown("**📝 Why this was flagged (Behavioural Rule)**")
                if "PortScan" in final or "PortScan" in behav:
                    st.markdown(
                        "The **PortScan Detector** uses a sliding time window to track "
                        "how many unique destination ports a single source IP contacts. "
                        "When the count exceeds the threshold (default: **10 unique ports "
                        "within 5 seconds**), a PortScan alert is raised.\n\n"
                        f"**Observed:** {reason}"
                    )
                elif "SYNFlood" in behav or "DoS" in final:
                    st.markdown(
                        "The **SYN Flood Detector** monitors the ratio of SYN packets to "
                        "ACK packets from each source. In normal TCP traffic this ratio is "
                        "close to 1:1. During a SYN flood, SYN packets far outnumber ACKs "
                        "because the attacker never completes the handshake.\n\n"
                        f"**Observed:** {reason}"
                    )
                else:
                    st.markdown(f"Behavioural rule evidence: {reason}")

                st.caption(
                    "ℹ️ This detection was made by a deterministic rule — not the ML model. "
                    "No SHAP explanation applies. The evidence above is direct network observation."
                )

            elif shap_raw and isinstance(shap_raw, dict) and len(shap_raw) > 0:
                # ML was involved and SHAP is available
                st.markdown("**🧩 Which network features influenced the model? (SHAP Analysis)**")
                st.caption(
                    "ℹ️ SHAP (SHapley Additive exPlanations) shows which network measurements "
                    "most influenced the model's decision. "
                    "This indicates correlation, **not causation** — it shows "
                    "what patterns the model detected, not a guarantee that an attack occurred."
                )

                sorted_shap = sorted(
                    shap_raw.items(), key=lambda x: abs(x[1]), reverse=True
                )[:10]

                rows_html = ""
                for feat, val in sorted_shap:
                    plain   = _plain(feat)
                    bar_html= _contribution_bar(val)
                    colour  = "#e74c3c" if val > 0 else "#27ae60"
                    rows_html += (
                        f"<tr>"
                        f"<td style='padding:6px 12px; color:#ccc'>{plain}</td>"
                        f"<td style='padding:6px 12px; color:{colour}'>{bar_html}</td>"
                        f"</tr>"
                    )

                st.markdown(
                    "<table style='width:100%; border-collapse:collapse; "
                    "background:#1e1e1e; border-radius:6px;'>"
                    "<thead><tr>"
                    "<th style='padding:8px 12px; text-align:left; color:#888'>Network Feature</th>"
                    "<th style='padding:8px 12px; text-align:left; color:#888'>Contribution to Alert</th>"
                    "</tr></thead><tbody>"
                    + rows_html +
                    "</tbody></table>",
                    unsafe_allow_html=True,
                )

                # Also show bar chart (optional, more visual)
                shap_df = pd.DataFrame(
                    [(f, v) for f, v in sorted_shap],
                    columns=["Feature", "SHAP Value"],
                )
                shap_df["Feature"] = shap_df["Feature"].apply(_plain)
                fig_shap = go.Figure(go.Bar(
                    x=shap_df["SHAP Value"], y=shap_df["Feature"],
                    orientation="h",
                    marker_color=["#e74c3c" if v > 0 else "#27ae60"
                                  for v in shap_df["SHAP Value"]],
                ))
                fig_shap.update_layout(
                    title="Feature Impact on Model Prediction",
                    xaxis_title="← Reduces alert risk  |  Increases alert risk →",
                    height=350, margin=dict(l=0, r=0, t=40, b=0),
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                )
                st.plotly_chart(fig_shap, use_container_width=True)

            else:
                # ML used but SHAP not computed yet
                st.info(
                    "🕒 SHAP explanation is being computed in the background. "
                    "Refresh the dashboard in a few seconds to see it. "
                    "(SHAP runs asynchronously to avoid delaying detection.)"
                )

            # ── Class probability breakdown ────────────────────────────────
            proba = chosen.get("probabilities") or {}
            if isinstance(proba, str):
                import json as _json
                try:
                    proba = _json.loads(proba)
                except Exception:
                    proba = {}
            if proba and isinstance(proba, dict):
                st.markdown("---")
                st.markdown("**📊 Model Probability Breakdown**")
                st.caption(
                    "How confident was the model across all possible traffic categories?"
                )
                prob_df = pd.DataFrame(
                    sorted(proba.items(), key=lambda x: x[1], reverse=True),
                    columns=["Traffic Type", "Probability"],
                )
                fig_prob = go.Figure(go.Bar(
                    x=prob_df["Probability"], y=prob_df["Traffic Type"],
                    orientation="h", marker_color="#2980b9",
                ))
                fig_prob.update_layout(
                    height=300, margin=dict(l=0, r=0, t=20, b=0),
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                )
                st.plotly_chart(fig_prob, use_container_width=True)


# ----- Tab 3: Attack Distribution --------------------------------------------
with tab_chart:
    st.subheader("Attack Distribution (Current Session)")
    if counts:
        fig3 = go.Figure(go.Pie(
            labels = list(counts.keys()),
            values = list(counts.values()),
            hole   = 0.4,
            marker = dict(colors=[_label_colour(k) for k in counts.keys()]),
        ))
        fig3.update_layout(
            height        = 380,
            margin        = dict(l=0, r=0, t=20, b=0),
            plot_bgcolor  = "rgba(0,0,0,0)",
            paper_bgcolor = "rgba(0,0,0,0)",
        )
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.caption("No data yet.")


# ----- Tab 4: Historical Logs ------------------------------------------------
with tab_history:
    st.subheader("Historical Detections (SQLite)")
    history = bridge_instance.get_history(limit=200)
    if history:
        hist_df = pd.DataFrame(history)
        # Add severity emoji column if severity exists
        if "severity" in hist_df.columns:
            hist_df["risk"] = hist_df["severity"].apply(
                lambda s: SEVERITY_EMOJI.get(str(s), "") + " " + str(s)
            )
        hist_cols = [
            "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
            "final_decision", "risk" if "risk" in hist_df.columns else "ml_prediction",
            "confidence", "detection_method", "detection_reason",
        ]
        available = [c for c in hist_cols if c in hist_df.columns]
        st.dataframe(hist_df[available], use_container_width=True)

        # Filter controls
        with st.expander("🔍 Filter Events"):
            fc1, fc2 = st.columns(2)
            filter_type = fc1.selectbox(
                "Attack type",
                ["All"] + sorted(hist_df["final_decision"].dropna().unique().tolist()),
            )
            filter_src = fc2.text_input("Source IP contains", "")
            filtered = hist_df.copy()
            if filter_type != "All":
                filtered = filtered[filtered["final_decision"] == filter_type]
            if filter_src:
                filtered = filtered[
                    filtered["src_ip"].fillna("").str.contains(filter_src)
                ]
            st.caption(f"Showing {len(filtered)} / {len(hist_df)} events")
            if len(filtered) > 0:
                st.dataframe(filtered[available], use_container_width=True)
    else:
        st.info("No historical records yet.")


# ---------------------------------------------------------------------------
# Auto-refresh  (survives exceptions so frontend never permanently freezes)
# ---------------------------------------------------------------------------

if auto_refresh:
    time.sleep(refresh_rate)
    try:
        st.rerun()
    except Exception:
        pass   # Streamlit version compatibility guard
