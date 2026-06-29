import streamlit as st
import requests
import pandas as pd
import plotly.express as px

# --- الإعدادات الأساسية للواجهة ---
st.set_page_config(page_title="XPE-Guard Enterprise", layout="wide", page_icon="🛡️")

# --- تنسيق احترافي ---
st.markdown("""
    <style>
    .title-text {font-size: 2.5rem; font-weight: 800; color: #1E293B; text-align: center;}
    .metric-box {background-color: #F8FAFC; padding: 20px; border-radius: 10px; border: 1px solid #E2E8F0; text-align: center;}
    </style>
""", unsafe_allow_html=True)

# --- القائمة الجانبية (المربع النصي لرابط الـ Ngrok) ---
st.sidebar.title("⚙️ Engine Configuration")
api_endpoint = st.sidebar.text_input("Backend API Endpoint URL", value="https://xxxx.ngrok-free.app/api/v1/scan")
show_hashes = st.sidebar.checkbox("Show Cryptographic Hashes", value=True)
show_shap = st.sidebar.checkbox("Show SHAP Forensic Telemetry", value=True)

# --- واجهة الفحص ---
st.markdown('<div class="title-text">🛡️ XPE-Guard</div>', unsafe_allow_html=True)
uploaded_file = st.file_uploader("Drop Target Payload (EXE, DLL, SYS)", type=['exe', 'dll', 'sys'])

# --- زر التنفيذ (المظبوط) ---
if uploaded_file is not None:
    if st.button("▶ Execute Forensic Triage", type="primary", use_container_width=True):
        with st.spinner("Analyzing structural properties..."):
            try:
                files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/octet-stream")}
                response = requests.post(api_endpoint, files=files, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # عرض النتائج
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Verdict", "CRITICAL THREAT" if data["verdict"]["is_malicious"] else "BENIGN")
                    col2.metric("Threat Score", f"{data['verdict']['threat_score']}%")
                    col3.metric("Latency", f"{data['performance']['latency_seconds']}s")
                    
                    if show_hashes:
                        st.success(f"MD5: `{data['metadata']['md5']}`")
                        
                    if show_shap:
                        df = pd.DataFrame(data["telemetry"]).T.reset_index()
                        fig = px.bar(df, x="impact_coefficient", y="index", orientation='h', title="Feature Impact")
                        st.plotly_chart(fig, use_container_width=True)
                else:
                    st.error("Error: Check if Backend is running and URL is correct.")
            except Exception as e:
                st.error(f"Connection Failed: {e}")
