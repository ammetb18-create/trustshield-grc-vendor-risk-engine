import streamlit as st
from risk_engine import analyze_vendors
from report_generator import generate_markdown_report

st.set_page_config(
    page_title="TrustShield GRC",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ TrustShield GRC")
st.subheader("Vendor Risk & Evidence Engine")

st.write(
    "A Python and Streamlit-based GRC tool that evaluates vendor cybersecurity risk, "
    "identifies missing compliance evidence, maps control gaps to security frameworks, "
    "and generates executive-style risk reports."
)

df = analyze_vendors()

total_vendors = len(df)
critical_vendors = len(df[df["Risk_Level"] == "Critical"])
high_vendors = len(df[df["Risk_Level"] == "High"])
missing_soc2 = df["Evidence_Gaps"].apply(lambda gaps: "Missing SOC 2" in gaps).sum()
missing_mfa = df["Evidence_Gaps"].apply(lambda gaps: "Missing MFA" in gaps).sum()

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Vendors Reviewed", total_vendors)
col2.metric("Critical Risk", critical_vendors)
col3.metric("High Risk", high_vendors)
col4.metric("Missing SOC 2", missing_soc2)
col5.metric("Missing MFA", missing_mfa)

st.divider()

st.header("Prioritized Vendor Risk Table")

display_df = df.copy()
display_df["Evidence_Gaps"] = display_df["Evidence_Gaps"].apply(lambda gaps: ", ".join(gaps))
display_df["Framework_Mapping"] = display_df["Framework_Mapping"].apply(lambda items: ", ".join(items))
display_df["Recommendations"] = display_df["Recommendations"].apply(lambda items: " | ".join(items))

st.dataframe(
    display_df[
        [
            "Vendor",
            "System",
            "Data_Type",
            "Business_Criticality",
            "Risk_Score",
            "Risk_Level",
            "Recommended_Priority",
            "Evidence_Gaps",
            "Framework_Mapping"
        ]
    ],
    use_container_width=True
)

st.header("Risk Score Overview")
chart_data = df[["Vendor", "Risk_Score"]].set_index("Vendor")
st.bar_chart(chart_data)

st.header("Vendor Detail Review")

selected_vendor = st.selectbox("Select a vendor to review:", df["Vendor"].tolist())
vendor_row = df[df["Vendor"] == selected_vendor].iloc[0]

left, right = st.columns(2)

with left:
    st.markdown("### Vendor Profile")
    st.write(f"**Vendor:** {vendor_row['Vendor']}")
    st.write(f"**System:** {vendor_row['System']}")
    st.write(f"**Data Type:** {vendor_row['Data_Type']}")
    st.write(f"**Business Criticality:** {vendor_row['Business_Criticality']}")
    st.write(f"**Risk Score:** {vendor_row['Risk_Score']}/100")
    st.write(f"**Risk Level:** {vendor_row['Risk_Level']}")

with right:
    st.markdown("### Evidence Gaps")
    if vendor_row["Evidence_Gaps"]:
        for gap in vendor_row["Evidence_Gaps"]:
            st.warning(gap)
    else:
        st.success("No major evidence gaps identified.")

st.markdown("### Framework Mapping")
if vendor_row["Framework_Mapping"]:
    for mapping in vendor_row["Framework_Mapping"]:
        st.info(mapping)
else:
    st.write("No major framework gaps mapped.")

st.markdown("### Recommended Actions")
if vendor_row["Recommendations"]:
    for recommendation in vendor_row["Recommendations"]:
        st.success(recommendation)
else:
    st.write("Continue routine monitoring.")

st.divider()

if st.button("Generate Executive Risk Report"):
    path = generate_markdown_report()
    st.success(f"Report generated successfully: {path}")

    with open(path, "r", encoding="utf-8") as report_file:
        st.download_button(
            label="Download Markdown Report",
            data=report_file.read(),
            file_name="vendor_risk_report.md",
            mime="text/markdown"
        )
