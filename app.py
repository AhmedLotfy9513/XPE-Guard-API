import streamlit as st
import requests
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="XPE-Guard", layout="wide")

st.sidebar.title("⚙️ Engine Configuration")
api_endpoint = st.sidebar.text_input("Backend API Endpoint URL", value="https://xxxx.ngrok-free.app/api/v1/scan")

st.title("🛡️ XPE-Guard: AI Malware Detection")
uploaded_file = st.file_uploader("Upload Target Payload (EXE, DLL)", type=['exe', 'dll'])

if uploaded_file and st.button("▶ Execute Forensic Triage", type="primary", use_container_width=True):
    with st.spinner("Analyzing..."):
        try:
            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/octet-stream")}
            response = requests.post(api_endpoint, files=files, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                st.success("Analysis Complete!")
                col1, col2 = st.columns(2)
                col1.metric("Verdict", "CRITICAL THREAT" if data["verdict"]["is_malicious"] else "BENIGN")
                col2.metric("Threat Score", f"{data['verdict']['threat_score']}%")
                
                st.markdown("### 🔬 Structural Anomaly Telemetry")
                df = pd.DataFrame(data["telemetry"]).T.reset_index()
                fig = px.bar(df, x="impact_coefficient", y="index", orientation='h', title="Feature Impact")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.error(f"Server Error: {response.status_code}")
        except Exception as e:
            st.error(f"Connection Failed: {e}")
