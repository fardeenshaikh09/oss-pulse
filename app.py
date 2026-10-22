import duckdb
import streamlit as st
import plotly.express as px

st.set_page_config(page_title="OSS-Pulse | Supply Chain Risk Lakehouse", layout="wide")
st.title("🛡️ OSS-Pulse: Open-Source Supply Chain & Burnout Lakehouse")
st.markdown("Automated Medallion pipeline tracking **Maintainer Bus Factor** and **CVE Remediation Velocity** across critical Python dependencies.")

@st.cache_data(ttl=600)
def load_gold_mart():
    con = duckdb.connect("data/oss_pulse.duckdb", read_only=True)
    df = con.execute("SELECT * FROM gold_dependency_risk").df()
    con.close()
    return df

df = load_gold_mart()
col1, col2, col3, col4 = st.columns(4)
col1.metric("Monitored Packages", len(df))
col2.metric("Total Tracked CVEs", int(df["total_cves"].sum()))
col3.metric("Max Bus-Factor Concentration", f"{df['bus_factor_concentration_pct'].max()}%")
col4.metric("High/Critical Risk Packages", int((df["risk_classification"] != "HEALTHY_SUPPLY_CHAIN").sum()))
st.divider()

left_col, right_col = st.columns([3, 2])
with left_col:
    st.subheader("Maintainer Concentration vs. Security Debt")
    fig = px.scatter(
        df, x="bus_factor_concentration_pct", y="total_cves",
        size="composite_risk_score", color="risk_classification",
        hover_name="package_name", text="package_name"
    )
    fig.update_traces(textposition="top center")
    st.plotly_chart(fig, use_container_width=True)
with right_col:
    st.subheader("Composite Risk Leaderboard")
    st.dataframe(df[["package_name", "composite_risk_score", "risk_classification", "bus_factor_concentration_pct", "total_cves"]], use_container_width=True, hide_index=True)
