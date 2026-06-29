import streamlit as st
import requests
import pandas as pd
import plotly.express as px

# --- Page Configuration ---
st.set_page_config(page_title="XPE-Guard Enterprise", layout="wide", page_icon="🛡️")

# --- Corporate Styling ---
st.markdown("""
    <style>
    .title-text {font-size: 2.5rem; font-weight: 800; color: #1E293B; text-align: center; margin-bottom: 0px;}
    .subtitle-text {font-size: 1.2rem; color: #64748B; text-align: center; margin-bottom: 30px;}
    .metric-box {background-color: #F8FAFC; padding: 20px; border-radius: 10px; border: 1px solid #E2E8F0; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.05);}
    .danger-text {color: #DC2626; font-weight: bold; font-size: 1.5rem;}
    .safe-text {color: #059669; font-weight: bold; font-size: 1.5rem;}
    </style>
""", unsafe_allow_html=True)

# --- Dynamic Sidebar Configuration ---
st.sidebar.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=80)
st.sidebar.markdown("### ⚙️ Engine Configuration")

# THE MAGIC TRICK: Change API URL directly from the UI
default_api = "http://127.0.0.1:8000/api/v1/scan"
api_endpoint = st.sidebar.text_input("Backend API Endpoint URL", value=default_api, help="Update this URL when deploying to Cloud (e.g., Render or Ngrok URL).")

st.sidebar.markdown("---")
st.sidebar.markdown("### 📊 Display Options")
show_hashes = st.sidebar.checkbox("Show Cryptographic Hashes", value=True)
show_shap = st.sidebar.checkbox("Show SHAP Forensic Telemetry", value=True)

# --- Main UI ---
st.markdown('<div class="title-text">🛡️ XPE-Guard</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle-text">AI-Driven Static Malware Analysis & Threat Intelligence</div>', unsafe_allow_html=True)

uploaded_file = st.file_uploader("Drop Target Payload Here (EXE, DLL, SYS)", type=['exe', 'dll', 'sys'])

if uploaded_file and st.button("▶ Execute Forensic Triage", type="primary", use_container_width=True):
    with st.spinner("Analyzing structural properties and extracting deep features..."):
        try:
            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/octet-stream")}
            response = requests.post(api_endpoint, files=files, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # 1. Verdict Metrics
                col1, col2, col3 = st.columns(3)
                is_threat = data["verdict"]["is_malicious"]
                
                verdict_html = f'<div class="metric-box">Security Verdict<br><span class="{"danger-text" if is_threat else "safe-text"}">{"CRITICAL THREAT" if is_threat else "BENIGN PAYLOAD"}</span></div>'
                col1.markdown(verdict_html, unsafe_allow_html=True)
                
                score_html = f'<div class="metric-box">Threat Risk Score<br><span style="font-size: 1.5rem; font-weight: bold;">{data["verdict"]["threat_score"]}%</span></div>'
                col2.markdown(score_html, unsafe_allow_html=True)
                
                latency_html = f'<div class="metric-box">Engine Latency<br><span style="font-size: 1.5rem; font-weight: bold;">{data["performance"]["latency_seconds"]}s</span></div>'
                col3.markdown(latency_html, unsafe_allow_html=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # 2. Metadata Panel
                if show_hashes:
                    st.success(f"**MD5:** `{data['metadata']['md5']}`  |  **SHA-256:** `{data['metadata']['sha256']}`")
                
                # 3. Explainable AI (SHAP) Charts
                if show_shap:
                    st.markdown("### 🔬 Structural Anomaly Telemetry (XAI)")
                    df = pd.DataFrame(data["telemetry"]).T
                    df.reset_index(inplace=True)
                    df.rename(columns={'index': 'Structural Feature', 'impact_coefficient': 'Impact Coefficient', 'forensic_analysis': 'Forensic Analysis'}, inplace=True)
                    
                    # Plotly Graph
                    fig = px.bar(df, x="Impact Coefficient", y="Structural Feature", orientation='h', 
                                 color="Impact Coefficient", color_continuous_scale="RdBu",
                                 title="Feature Impact on Threat Verdict")
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # Datatable
                    st.dataframe(df[["Structural Feature", "Impact Coefficient", "Forensic Analysis"]], use_container_width=True)
                    
            else:
                st.error(f"❌ Server returned error code: {response.status_code}. Details: {response.text}")
                
        except requests.exceptions.RequestException as e:
            st.error("🚨 Connection Failed! Ensure the Backend API is running and the URL in the sidebar is correct.")
            st.warning(f"Technical Details: {e}")
