# SP Compliance Portal - Streamlit frontend
# Three level navigation:
# Level 1 — Server instance summary
# Level 2 — Login and native permission grid per server
# Level 3 — Remediation pack with SIT/UAT/PROD change raising
#            and risk acceptance with audit trail

import streamlit as st
import plotly.express as px
import json
import uuid
import sys
from pathlib import Path
from datetime import datetime, date

# Add engine to path
sys.path.append(str(Path(__file__).parent))
from engine.bigquery_client import (
    get_server_summary,
    get_permissions_for_instance,
    get_classifications,
    get_findings_for_principal,
    get_permissions_for_principal,
    get_permissions_grouped,
    get_scan_summary,
    get_actions_for_permission,
    save_remediation_action,
    save_risk_acceptance,
)
from engine.remediation import generate_remediation_pack

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

TIER_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

# ── Session state initialisation ──────────────────────────────────────────────
for key, default in {
    "view_level":          1,
    "selected_instance":   None,
    "selected_permission": None,
    "navigate_to":         None,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

# ── Handle deferred navigation ────────────────────────────────────────────────
if st.session_state.navigate_to is not None:
    st.session_state.view_level  = st.session_state.navigate_to["level"]
    if "instance" in st.session_state.navigate_to:
        st.session_state.selected_instance = (
            st.session_state.navigate_to["instance"]
        )
    if "permission" in st.session_state.navigate_to:
        st.session_state.selected_permission = (
            st.session_state.navigate_to["permission"]
        )
    st.session_state.navigate_to = None

# ── Load summary data ─────────────────────────────────────────────────────────
@st.cache_data(ttl=300)
def load_scan_summary():
    return get_scan_summary()

@st.cache_data(ttl=300)
def load_server_summary():
    return get_server_summary()

@st.cache_data(ttl=300)
def load_instance_permissions(sql_instance: str):
    return get_permissions_for_instance(sql_instance)

summary    = load_scan_summary()
servers_df = load_server_summary()

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🔐 Service Principal Compliance Portal")
st.caption("Live data from BigQuery — sp-compliance.sp_compliance")
st.divider()

# ── Summary metrics row ───────────────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total SPs",  summary.get("total_principals", 0))
col2.metric("Critical",   summary.get("critical_count",   0))
col3.metric("High",       summary.get("high_count",       0))
col4.metric("Medium",     summary.get("medium_count",     0))
col5.metric("Low",        summary.get("low_count",        0))
st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# LEVEL 1 — SERVER INSTANCE SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
if st.session_state.view_level == 1:

    st.subheader("Server Instance Summary")
    st.caption(
        "One row per server — click View Details to inspect "
        "logins and permissions"
    )

    if servers_df.empty:
        st.warning("No data available — run the CSV loader first")
    else:
        for i, row in servers_df.iterrows():
            tier     = str(row.get("highest_risk_tier", "LOW"))
            icon     = TIER_ICONS.get(tier, "⚪")
            instance = str(row.get("sql_instance", ""))

            c1, c2, c3, c4, c5, c6, c7 = st.columns([3, 1, 1, 1, 1, 1, 1])
            c1.markdown(f"**{instance}**")
            c2.markdown(f"{icon} **{tier}**")
            c3.metric("Logins",   int(row.get("login_count",     0)))
            c4.metric("Findings", int(row.get("total_findings",  0)))
            c5.metric("Critical", int(row.get("critical_logins", 0)))
            c6.metric("High",     int(row.get("high_logins",     0)))

            with c7:
                if st.button("View Details", key=f"btn_view_{i}"):
                    st.session_state.navigate_to = {
                        "level":    2,
                        "instance": instance,
                    }
                    st.rerun()

            st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# LEVEL 2 — LOGIN AND PERMISSION GRID
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.view_level == 2:

    instance = st.session_state.selected_instance

    nav1, nav2 = st.columns([1, 5])
    with nav1:
        if st.button("◀ Back to Server Summary"):
            st.session_state.navigate_to = {"level": 1}
            st.rerun()

    st.subheader(f"📋 {instance}")
    st.caption(
        "One row per login per native permission — "
        "click Remediate to raise a change or accept risk"
    )

    perms_df = load_instance_permissions(instance)

    if perms_df.empty:
        st.warning("No permissions data found for this instance")
    else:
        f1, f2, f3 = st.columns(3)
        with f1:
            tier_opts   = sorted(
                perms_df["risk_tier"].dropna().unique().tolist()
            )
            tier_filter = st.multiselect(
                "Filter by Risk Tier",
                options=tier_opts,
                default=tier_opts
            )
        with f2:
            login_opts   = sorted(
                perms_df["principal_name"].dropna().unique().tolist()
            )
            login_filter = st.multiselect(
                "Filter by Login",
                options=login_opts,
                default=login_opts
            )
        with f3:
            perm_search = st.text_input("Search Permission", "")

        filtered = perms_df[
            (perms_df["risk_tier"].isin(tier_filter)) &
            (perms_df["principal_name"].isin(login_filter))
        ].copy()

        if perm_search:
            filtered = filtered[
                filtered["native_permission"].str.contains(
                    perm_search, case=False, na=False
                )
            ]

        filtered = filtered.sort_values(
            ["score", "principal_name", "native_permission"],
            ascending=[False, True, True]
        ).reset_index(drop=True)

        st.divider()

        hdr = st.columns([2, 2, 1, 1, 1, 1, 1])
        hdr[0].markdown("**Login**")
        hdr[1].markdown("**Permission**")
        hdr[2].markdown("**Role Mapping**")
        hdr[3].markdown("**Database**")
        hdr[4].markdown("**Risk**")
        hdr[5].markdown("**Enabled**")
        hdr[6].markdown("**Action**")
        st.divider()

        for idx, row in filtered.iterrows():
            tier = str(row.get("risk_tier", "LOW"))
            icon = TIER_ICONS.get(tier, "⚪")

            c1, c2, c3, c4, c5, c6, c7 = st.columns([2, 2, 1, 1, 1, 1, 1])
            c1.write(str(row.get("principal_name",    "")))
            c2.write(str(row.get("native_permission", "")))
            c3.write(str(row.get("role_mapping",      "")))
            c4.write(str(row.get("database_name",     "")))
            c5.write(f"{icon} {tier}")
            c6.write(str(row.get("login_enabled",     "")))

            with c7:
                if st.button("Remediate", key=f"btn_rem_{idx}"):
                    st.session_state.navigate_to = {
                        "level": 3,
                        "permission": {
                            "principal_id":      str(row["principal_id"]),
                            "principal_name":    str(row["principal_name"]),
                            "native_permission": str(row["native_permission"]),
                            "role_mapping":      str(row["role_mapping"]),
                            "database_name":     str(row["database_name"]),
                            "sql_instance":      str(row["sql_instance"]),
                            "risk_tier":         tier,
                            "score":             int(row["score"]),
                        }
                    }
                    st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
# LEVEL 3 — REMEDIATION PACK
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.view_level == 3:

    perm = st.session_state.selected_permission

    nav1, nav2, nav3 = st.columns([1, 1, 4])
    with nav1:
        if st.button("◀ Back to Permission Grid"):
            st.session_state.navigate_to = {
                "level":    2,
                "instance": perm["sql_instance"],
            }
            st.rerun()
    with nav2:
        if st.button("🏠 Home"):
            st.session_state.navigate_to = {"level": 1}
            st.rerun()

    st.subheader("🔧 Remediation Pack")

    tier = perm["risk_tier"]
    icon = TIER_ICONS.get(tier, "⚪")

    s1, s2, s3, s4 = st.columns(4)
    s1.markdown(f"**Login**\n\n{perm['principal_name']}")
    s2.markdown(f"**Permission**\n\n{perm['native_permission']}")
    s3.markdown(f"**Database**\n\n{perm['database_name']}")
    s4.markdown(f"**Risk**\n\n{icon} {tier}")

    st.divider()

    # ── Existing actions ──────────────────────────────────────────────────────
    existing = get_actions_for_permission(
        perm["principal_id"],
        perm["native_permission"],
        perm["database_name"],
    )

    if not existing.empty:
        st.markdown("#### Action History")
        st.dataframe(
            existing[[
                "actioned_at", "action_type", "status",
                "environment", "snow_cr_number",
                "risk_ref", "actioned_by", "notes"
            ]],
            use_container_width=True,
            hide_index=True,
        )
        st.divider()

    # ── Action tabs ───────────────────────────────────────────────────────────
    tab1, tab2 = st.tabs([
        "🔧 Raise Change Request",
        "⚠️ Accept Risk"
    ])

    with tab1:
        st.markdown("#### Raise a Change Request")
        st.caption(
            "Changes must progress sequentially: SIT → UAT → PROD. "
            "Maximum 5 days per stage."
        )

        env = st.selectbox(
            "Environment",
            options=["SIT", "UAT", "PROD"],
            index=0
        )

        snow_cr = st.text_input(
            "ServiceNow CR Number",
            placeholder="CHG0012345"
        )

        cr_notes = st.text_area(
            "Notes",
            placeholder=(
                "Describe the investigation outcome "
                "and reason for remediation"
            ),
            height=100
        )

        actioned_by = st.text_input(
            "Your Name / Email",
            placeholder="name@bank.com"
        )

        st.markdown("#### ServiceNow CR Template")

        snow_template = {
            "short_description": (
                f"Remove {perm['native_permission']} from "
                f"{perm['principal_name']} on "
                f"{perm['database_name']} — {env}"
            ),
            "description": (
                f"Login:        {perm['principal_name']}\n"
                f"Instance:     {perm['sql_instance']}\n"
                f"Database:     {perm['database_name']}\n"
                f"Permission:   {perm['native_permission']}\n"
                f"Role Mapping: {perm['role_mapping']}\n"
                f"Risk Tier:    {perm['risk_tier']}\n"
                f"Environment:  {env}\n\n"
                f"Notes: {cr_notes}"
            ),
            "category":         "Security",
            "subcategory":      "Access Management",
            "urgency":          "1 - High" if tier == "CRITICAL" else "2 - Medium",
            "impact":           "2 - Medium",
            "environment":      env,
            "assignment_group": "IAM Security Team",
            "test_plan": (
                f"Verify application function after removing "
                f"{perm['native_permission']} from "
                f"{perm['principal_name']}"
            ),
            "backout_plan": (
                f"Restore {perm['native_permission']} to "
                f"{perm['principal_name']} on "
                f"{perm['database_name']} if impact confirmed"
            ),
        }

        st.code(json.dumps(snow_template, indent=2), language="json")

        st.download_button(
            label=f"⬇️ Download {env} CR Template (JSON)",
            data=json.dumps(snow_template, indent=2),
            file_name=(
                f"CR_{env}_"
                f"{perm['principal_name'].replace(chr(92), '_')}_"
                f"{perm['native_permission']}.json"
            ),
            mime="application/json"
        )

        st.divider()

        if st.button(f"✅ Confirm — Save {env} Change to Audit Trail"):
            if not snow_cr:
                st.error("Please enter a ServiceNow CR number")
            elif not actioned_by:
                st.error("Please enter your name or email")
            else:
                findings_df = get_findings_for_principal(
                    perm["principal_id"]
                )
                finding_id = (
                    str(findings_df.iloc[0]["finding_id"])
                    if not findings_df.empty
                    else str(uuid.uuid4())
                )

                success = save_remediation_action(
                    finding_id        = finding_id,
                    principal_id      = perm["principal_id"],
                    principal_name    = perm["principal_name"],
                    native_permission = perm["native_permission"],
                    database_name     = perm["database_name"],
                    sql_instance      = perm["sql_instance"],
                    environment       = env,
                    snow_cr_number    = snow_cr,
                    notes             = cr_notes,
                    actioned_by       = actioned_by,
                )

                if success:
                    st.success(
                        f"✅ {env} change {snow_cr} saved to audit trail"
                    )
                    st.cache_data.clear()
                else:
                    st.error("Failed to save to audit trail — try again")

    with tab2:
        st.markdown("#### Accept Risk")
        st.caption(
            "Use when the permission is required and cannot be removed. "
            "A risk reference from the internal register is mandatory."
        )

        risk_ref = st.text_input(
            "Risk Register Reference",
            placeholder="RISK-2026-04821"
        )

        review_date = st.date_input(
            "Next Review Date",
            value=date(
                datetime.now().year,
                datetime.now().month,
                min(datetime.now().day, 28)
            ),
            min_value=date.today()
        )

        risk_notes = st.text_area(
            "Justification",
            placeholder=(
                "Explain why this permission is required "
                "and cannot be removed at this time"
            ),
            height=100
        )

        risk_actioned_by = st.text_input(
            "Your Name / Email",
            placeholder="name@bank.com",
            key="risk_actioned_by"
        )

        st.divider()

        if st.button("✅ Confirm — Save Risk Acceptance to Audit Trail"):
            if not risk_ref:
                st.error("Please enter a risk register reference")
            elif not risk_notes:
                st.error("Please enter a justification")
            elif not risk_actioned_by:
                st.error("Please enter your name or email")
            else:
                findings_df = get_findings_for_principal(
                    perm["principal_id"]
                )
                finding_id = (
                    str(findings_df.iloc[0]["finding_id"])
                    if not findings_df.empty
                    else ""
                )

                success = save_risk_acceptance(
                    finding_id        = finding_id,
                    principal_id      = perm["principal_id"],
                    principal_name    = perm["principal_name"],
                    native_permission = perm["native_permission"],
                    database_name     = perm["database_name"],
                    sql_instance      = perm["sql_instance"],
                    risk_ref          = risk_ref,
                    review_date       = str(review_date),
                    notes             = risk_notes,
                    actioned_by       = risk_actioned_by,
                )

                if success:
                    st.success(
                        f"✅ Risk acceptance {risk_ref} saved to audit trail"
                    )
                    st.cache_data.clear()
                else:
                    st.error("Failed to save to audit trail — try again")