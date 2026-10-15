import streamlit as st
import pandas as pd
import json
import os

st.set_page_config(page_title="Aegis Security Telemetry", page_icon="🛡️", layout="wide")
st.title("🛡️ Aegis: Zero-Trust Telemetry Dashboard")

# --- NUOVO: SIDEBAR AZIENDALE ---
with st.sidebar:
    st.markdown("## ⚙️ Control Panel")
    st.success("🟢 SYSTEM ONLINE")
    st.markdown("---")
    st.markdown("**Version:** 1.0.0-MVP")
    st.markdown("**Engine:** Zero-Trust Python Hook")
    st.markdown("**Environment:** `production`")
    st.markdown("---")
    st.caption("Aegis Security Gateway intercepting runtime OS calls.")
# ---------------------------------

LOG_FILE = "aegis_audit.jsonl"

def load_data():
    if not os.path.exists(LOG_FILE): return pd.DataFrame()
    data = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            try: data.append(json.loads(line.strip()))
            except json.JSONDecodeError: continue
    
    if not data: return pd.DataFrame()
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

df = load_data()

if df.empty:
    st.info("Nessun log rilevato. Esegui 'python test_agent.py' per generare dati.")
else:
    col1, col2, col3 = st.columns(3)
    total = len(df)
    blocked = len(df[df['action'] == 'BLOCKED'])
    col1.metric("Total Events Intercepted", total)
    col2.metric("Threats Neutralized", blocked, delta="-Secured", delta_color="inverse")
    col3.metric("Allowed Actions", total - blocked, delta="Normal")

    st.divider()
    
    col_chart, col_table = st.columns(2)
    with col_chart:
        st.subheader("Event Distribution")
        chart_data = df.groupby(['event_type', 'action']).size().unstack(fill_value=0)
        st.bar_chart(chart_data)
        
   # ... codice precedente (metriche e grafico a barre) ...
    
    with col_table:
        st.subheader("Top Targeted Assets (Blocked)")
        blocked_df = df[df['action'] == 'BLOCKED']
        if not blocked_df.empty:
            # TABELLA 1: Aggiunto hide_index=True
            st.dataframe(
                blocked_df['target'].value_counts().reset_index(name='Attempts'), 
                use_container_width=True, 
                hide_index=True
            )

    st.subheader("Raw Audit Trail")
    # TABELLA 2: Aggiunto hide_index=True
    st.dataframe(
        df.sort_values("timestamp", ascending=False), 
        use_container_width=True, 
        hide_index=True
    )
    
    if st.button("Refresh Telemetry"): st.rerun()