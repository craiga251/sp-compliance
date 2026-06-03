# SP Compliance Portal - Streamlit frontend
# Reads live data from BigQuery on GCP
# Classification engine runs at load time

import streamlit as st
import plotly.express as px
import sys
from pathlib import Path

# Add engine to path
sys.path.append(str(Path(__file__).parent))
from engine.bigquery_client import (
    get_classifications,
    get_findings_for_principal,
    get_permissions_for_principal,
    get_scan_summary,
)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SP Compliance Portal",
    page_icon="🔐",
    layout="wide"
)

# ── Tier colour mapping ───────────────────────────────────────────────────────
TIER_COLOURS = {
    "CRITICAL": "#d62728",
    "HIGH":     "#ff7f0e",
    "MEDIUM":   "#ffbb78",
    "LOW":      "#2ca02c",
}

# ── Load data from BigQuery ───────────────────────────────────────────────────
@st.cache_data(ttl=300)  # Cache for 5 minutes
def load_classifications():
    return get_classifications()

@st.cache_data(ttl=300)
def load_scan_summary():
    return get_scan_summary()

df      = load_classifications()
summary = load_scan_summary()

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🔐 Service Principal Compliance Portal")
st.caption(f"Live data from BigQuery — sp-compliance.sp_compliance")

st.divider()

# ── Summary metrics row ───────────────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total SPs",  summary.get("total_principals", len(df)))
col2.metric("Critical",   summary.get("critical_count",   len(df[df["risk_tier"] == "CRITICAL"])))
col3.metric("High",       summary.get("high_count",       len(df[df["risk_tier"] == "HIGH"])))
col4.metric("Medium",     summary.get("medium_count",     len(df[df["risk_tier"] == "MEDIUM"])))
col5.metric("Low",        summary.get("low_count",        len(df[df["risk_tier"] == "LOW"])))

st.divider()

# ── Charts row ────────────────────────────────────────────────────────────────
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("Risk Distribution")
    tier_counts = (
        df["risk_tier"]
        .value_counts()
        .reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        .reset_index()
    )
    tier_counts.columns = ["risk_tier", "count"]
    fig1 = px.bar(
        tier_counts,
        x="risk_tier",
        y="count",
        color="risk_tier",
        color_discrete_map=TIER_COLOURS,
        labels={"risk_tier": "Risk Tier", "count": "Number of SPs"},
    )
    fig1.update_layout(showlegend=False)
    st.plotly_chart(fig1, use_container_width=True)

with chart_col2:
    st.subheader("Risk Score by Principal")
    fig2 = px.bar(
        df.sort_values("score", ascending=False),
        x="principal_name",
        y="score",
        color="risk_tier",
        color_discrete_map=TIER_COLOURS,
        labels={"principal_name": "Principal", "score": "Risk Score"},
    )
    fig2.update_layout(showlegend=True, xaxis_tickangle=-45)
    st.plotly_chart(fig2, use_container_width=True)

st.divider()

# ── Filters ───────────────────────────────────────────────────────────────────
st.subheader("Principal Inventory")

filter_col1, filter_col2, filter_col3 = st.columns(3)

with filter_col1:
    tier_filter = st.multiselect(
        "Filter by Risk Tier",
        options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

with filter_col2:
    instance_options = sorted(df["sql_instance"].dropna().unique().tolist())
    instance_filter = st.multiselect(
        "Filter by SQL Instance",
        options=instance_options,
        default=instance_options
    )

with filter_col3:
    search = st.text_input("Search by Principal Name", "")

# ── Apply filters ─────────────────────────────────────────────────────────────
filtered = df[
    (df["risk_tier"].isin(tier_filter)) &
    (df["sql_instance"].isin(instance_filter))
].copy()

if search:
    filtered = filtered[
        filtered["principal_name"].str.contains(search, case=False)
    ]

# ── Inventory table ───────────────────────────────────────────────────────────
display_cols = [
    "principal_name", "risk_tier", "score",
    "principal_type", "sql_instance",
    "login_enabled", "interactive",
    "privilege_summary", "finding_count"
]

st.dataframe(
    filtered[display_cols].sort_values("score", ascending=False),
    use_container_width=True,
    hide_index=True,
)

st.divider()

# ── Drilldown ─────────────────────────────────────────────────────────────────
st.subheader("Principal Drilldown")

selected_name = st.selectbox(
    "Select a principal to inspect",
    options=df.sort_values("score", ascending=False)["principal_name"].tolist()
)

selected = df[df["principal_name"] == selected_name].iloc[0]

drill_col1, drill_col2 = st.columns(2)

with drill_col1:
    st.markdown(f"### {selected['principal_name']}")
    st.metric("Risk Score", selected["score"])
    st.write(f"**Risk Tier:** {selected['risk_tier']}")
    st.write(f"**Principal Type:** {selected['principal_type']}")
    st.write(f"**SQL Instance:** {selected['sql_instance']}")
    st.write(f"**Login Enabled:** {selected['login_enabled']}")
    st.write(f"**Interactive:** {selected['interactive']}")
    st.write(f"**Privilege Summary:** {selected['privilege_summary']}")
    st.write(f"**Recommended Action:** {selected['recommended_action']}")

with drill_col2:
    st.markdown("### Findings")
    findings_df = get_findings_for_principal(selected["principal_id"])
    if not findings_df.empty:
        for _, row in findings_df.iterrows():
            st.error(f"⚠️ {row['finding_text']}")
    else:
        st.success("✅ No findings — this principal is compliant")

    st.markdown("### Permissions")
    perms_df = get_permissions_for_principal(selected["principal_id"])
    if not perms_df.empty:
        st.dataframe(
            perms_df,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No permissions data available")