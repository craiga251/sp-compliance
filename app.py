# SP Compliance Portal - Streamlit frontend
# Reads classified SP data and renders risk dashboard + drilldown

import streamlit as st
import pandas as pd
import plotly.express as px
import sys
from pathlib import Path

# Add engine to path so we can import classifier
sys.path.append(str(Path(__file__).parent))
from engine.classifier import run_classification

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SP Compliance Portal",
    page_icon="🔐",
    layout="wide"
)

# ── Load and classify data ────────────────────────────────────────────────────
DATA_PATH = "data/principals.json"

@st.cache_data
def load_data():
    results = run_classification(DATA_PATH)
    df = pd.DataFrame(results)
    # Convert list columns to strings so dataframe renders correctly
    df["findings"] = df["findings"].apply(lambda x: " | ".join(x) if x else "None")
    return df

df = load_data()

# ── Tier colour mapping ───────────────────────────────────────────────────────
TIER_COLOURS = {
    "CRITICAL": "#d62728",
    "HIGH":     "#ff7f0e",
    "MEDIUM":   "#ffbb78",
    "LOW":      "#2ca02c",
}

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🔐 Service Principal Compliance Portal")
st.caption("Prototype — sample data only")

st.divider()

# ── Summary metrics row ───────────────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total SPs",    len(df))
col2.metric("Critical",     len(df[df["risk_tier"] == "CRITICAL"]))
col3.metric("High",         len(df[df["risk_tier"] == "HIGH"]))
col4.metric("Medium",       len(df[df["risk_tier"] == "MEDIUM"]))
col5.metric("Low",          len(df[df["risk_tier"] == "LOW"]))

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
    db_options = sorted(df["database"].unique().tolist())
    db_filter = st.multiselect(
        "Filter by Database",
        options=db_options,
        default=db_options
    )

with filter_col3:
    search = st.text_input("Search by Principal Name", "")

# ── Apply filters ─────────────────────────────────────────────────────────────
filtered = df[
    (df["risk_tier"].isin(tier_filter)) &
    (df["database"].isin(db_filter))
].copy()

if search:
    filtered = filtered[
        filtered["principal_name"].str.contains(search, case=False)
    ]

# ── Inventory table ───────────────────────────────────────────────────────────
display_cols = [
    "principal_name", "risk_tier", "score",
    "sql_role", "database", "environment",
    "direct_connect", "has_application_owner",
    "finding_count"
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
    st.write(f"**Role:** {selected['sql_role']}")
    st.write(f"**Database:** {selected['database']}")
    st.write(f"**Environment:** {selected['environment']}")
    st.write(f"**Direct Connect:** {selected['direct_connect']}")
    st.write(f"**Has Owner:** {selected['has_application_owner']}")
    st.write(f"**Justification on File:** {selected['justification_on_file']}")
    st.write(f"**Last Used:** {selected['last_used_days_ago']} days ago")
    st.write(f"**Notes:** {selected['notes']}")

with drill_col2:
    st.markdown("### Findings")
    findings_text = selected["findings"]
    if findings_text and findings_text != "None":
        for finding in findings_text.split(" | "):
            st.error(f"⚠️ {finding}")
    else:
        st.success("✅ No findings — this principal is compliant")

    st.markdown("### Recommended Action")
    st.info(f"📋 {selected['recommended_action']}")