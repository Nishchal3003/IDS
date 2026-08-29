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
    bridge_instance.reset_counters()
    st.sidebar.success("Counters reset.")


# ---------------------------------------------------------------------------
# Fetch live state
# ---------------------------------------------------------------------------

snapshot     = bridge_instance.get_snapshot()
recent_flows = snapshot.get("recent_flows", [])
alerts       = snapshot.get("alerts", [])
counts       = _decision_counts(recent_flows)


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
    st.error(
        "**LATEST ALERT — {}** | {} | {}:{} → {}:{} | Reason: {}".format(
            latest.get("final_decision", "UNKNOWN"),
            latest.get("timestamp", ""),
            latest.get("src_ip", "?"),
            latest.get("src_port", "?"),
            latest.get("dst_ip", "?"),
            latest.get("dst_port", "?"),
            latest.get("detection_reason", "N/A"),
        )
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
            colour = _label_colour(label)
            st.markdown(
                "<div style='border-left: 4px solid {}; padding: 6px 12px; "
                "margin-bottom: 6px; background: #1e1e1e; border-radius: 4px;'>"
                "<b>{}</b> — {} &rarr; {} | {}</div>".format(
                    colour,
                    label,
                    alert.get("src_ip", "?"),
                    alert.get("dst_ip", "?"),
                    alert.get("detection_reason", ""),
                ),
                unsafe_allow_html=True,
            )


# ----- Tab 2: XAI Explanations -----------------------------------------------
with tab_xai:
    st.subheader("SHAP Feature Explanations")
    st.info(
        "SHAP explanations show which network features most influenced "
        "the model prediction for each alert. "
        "Requires: pip install shap"
    )
    if alerts:
        latest = alerts[0]
        top_shap = latest.get("top_shap_features", {})
        if top_shap and isinstance(top_shap, dict):
            shap_df = pd.DataFrame(
                sorted(top_shap.items(), key=lambda x: abs(x[1]), reverse=True)[:15],
                columns=["Feature", "SHAP Value"],
            )
            fig = go.Figure(go.Bar(
                x          = shap_df["SHAP Value"],
                y          = shap_df["Feature"],
                orientation= "h",
                marker_color = [
                    "#c0392b" if v > 0 else "#27ae60"
                    for v in shap_df["SHAP Value"]
                ],
            ))
            fig.update_layout(
                title   = "Top Feature Contributions for Latest Alert",
                xaxis_title = "SHAP Value (impact on prediction)",
                height  = 400,
                margin  = dict(l=0, r=0, t=40, b=0),
                plot_bgcolor = "rgba(0,0,0,0)",
                paper_bgcolor = "rgba(0,0,0,0)",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.caption(
                "SHAP not yet computed for this alert. "
                "Run with SHAP enabled (see explainability/shap_explainer.py)."
            )
        probabilities = latest.get("probabilities", {})
        if probabilities:
            st.subheader("Class Probability Breakdown")
            prob_df = pd.DataFrame(
                sorted(probabilities.items(), key=lambda x: x[1], reverse=True),
                columns=["Class", "Probability"],
            )
            fig2 = go.Figure(go.Bar(
                x            = prob_df["Probability"],
                y            = prob_df["Class"],
                orientation  = "h",
                marker_color = "#2980b9",
            ))
            fig2.update_layout(
                height        = 300,
                margin        = dict(l=0, r=0, t=20, b=0),
                plot_bgcolor  = "rgba(0,0,0,0)",
                paper_bgcolor = "rgba(0,0,0,0)",
            )
            st.plotly_chart(fig2, use_container_width=True)
    else:
        st.caption("No alerts yet. XAI panel will populate when an attack is detected.")


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
        hist_cols = [
            "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
            "final_decision", "ml_prediction", "confidence", "detection_reason",
        ]
        available = [c for c in hist_cols if c in hist_df.columns]
        st.dataframe(hist_df[available], use_container_width=True)
    else:
        st.info("No historical records yet.")


# ---------------------------------------------------------------------------
# Auto-refresh
# ---------------------------------------------------------------------------

if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
