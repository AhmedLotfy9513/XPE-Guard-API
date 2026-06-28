import streamlit as st
import requests
import pandas as pd
import plotly.express as px

# إعداد الصفحة لتكون واسعة
st.set_page_config(page_title="XPE-Guard", layout="wide")

# العنوان الرئيسي
st.markdown("<h1 style='text-align: center; color: #0F172A;'>🛡️ XPE-Guard: AI Malware Detection</h1>", unsafe_allow_html=True)

# رفع الملف
uploaded_file = st.file_uploader("Upload Target Payload (EXE, DLL, ZIP)", type=['exe', 'dll', 'zip'])

if uploaded_file and st.button("▶ Initialize Static Analysis", type="primary"):
    files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/octet-stream")}
    
    try:
        # الاتصال بالـ API
        response = requests.post("http://127.0.0.1:8000/api/v1/scan", files=files)
        
        if response.status_code == 200:
            data = response.json()
            
            # 1. عرض النتائج في 3 بطاقات (Metrics)
            col1, col2, col3 = st.columns(3)
            col1.metric("Security Verdict", "MALICIOUS" if data["analysis"]["is_malware"] else "BENIGN")
            col2.metric("Threat Risk Score", f"{data['analysis']['confidence']*100:.2f}%")
            col3.metric("Processing Latency", f"{data['metrics']['latency']} s")
            
            st.markdown("---")
            
            # 2. الرسم البياني للـ SHAP
            st.subheader("🔍 Forensic Intelligence (SHAP Analysis)")
            df = pd.DataFrame(data["explainability"]).T
            fig = px.bar(df, x="shap_value", y=df.index, orientation='h', title="Structural Anomaly Impact Metrics")
            st.plotly_chart(fig, use_container_width=True)
            
            # 3. جدول الملاحظات الجنائية
            st.subheader("Detailed Forensic Notes")
            st.table(df[["forensic_note"]])
            
        else:
            st.error("Engine Connection Error. Please ensure the API is running.")
            
    except Exception as e:
        st.error(f"System Error: {e}")