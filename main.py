import time
import hashlib
import math
import joblib
import numpy as np
import pandas as pd
import shap
import pefile
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="XPE-Guard Intelligence API", version="1.0")

# Allow cross-origin requests for cloud deployment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. Load the pre-trained XGBoost Model and SHAP Explainer
try:
    model = joblib.load("model.pkl")
    explainer = shap.TreeExplainer(model)
    expected_features = model.feature_names_in_ # Automatically detects the 55 features
except Exception as e:
    print(f"[!] Critical Error Loading Model: {e}")

def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0: entropy += - p_x * math.log(p_x, 2)
    return entropy

# 2. Dynamic Feature Extraction Engine
def extract_structural_telemetry(file_data: bytes, feature_list: list) -> pd.DataFrame:
    # Initialize all 55 required features to 0.0 to prevent shape mismatches
    extracted = {feat: 0.0 for feat in feature_list}
    
    try:
        pe = pefile.PE(data=file_data)
        
        # Map actual PE structure to common malware features (Fallback to 0 if not present)
        if 'SizeOfOptionalHeader' in extracted: extracted['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        if 'Characteristics' in extracted: extracted['Characteristics'] = pe.FILE_HEADER.Characteristics
        if 'MajorLinkerVersion' in extracted: extracted['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        if 'SizeOfInitializedData' in extracted: extracted['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        if 'SizeOfImage' in extracted: extracted['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        if 'CheckSum' in extracted: extracted['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        if 'SectionsMaxEntropy' in extracted:
            entropies = [calculate_entropy(section.get_data()) for section in pe.sections]
            extracted['SectionsMaxEntropy'] = max(entropies) if entropies else 0.0
        
        # Detect ASLR and DEP (Common Evasion Indicators)
        if 'DllCharacteristics' in extracted: extracted['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
            
    except Exception as e:
        print(f"[!] PE Parsing Warning: {e}") # Handle corrupted or non-PE files safely

    # Ensure output is strictly ordered as the model expects
    df = pd.DataFrame([extracted], columns=feature_list)
    df.fillna(0.0, inplace=True)
    return df

# 3. Humanized Forensic Descriptions
def generate_forensic_context(feature_name: str, impact_value: float) -> str:
    direction = "escalated" if impact_value > 0 else "mitigated"
    if "Entropy" in feature_name or "entropy" in feature_name:
        return f"Structural entropy variation {direction} the threat score (Indicator of packing/obfuscation)."
    elif "Size" in feature_name or "size" in feature_name:
        return f"Anomalous segment sizing {direction} the malicious probability."
    elif "Characteristics" in feature_name:
        return f"Suspicious PE header characteristics {direction} the verdict."
    else:
        return f"Telemetry metric '{feature_name}' {direction} the overall risk confidence."

@app.post("/api/v1/scan")
async def process_payload(file: UploadFile = File(...)):
    start_time = time.time()
    file_bytes = await file.read()
    
    # Cryptographic Hashing
    file_hashes = {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest()
    }
    
    # Feature Engineering
    features_df = extract_structural_telemetry(file_bytes, expected_features)
    
    # AI Verdict
    prediction = int(model.predict(features_df)[0])
    risk_probability = float(model.predict_proba(features_df)[0][prediction])
    
    # SHAP Explainability (Top 5 Impactful Features)
    shap_values = explainer.shap_values(features_df)[0]
    top_indices = np.argsort(np.abs(shap_values))[::-1][:5]
    
    forensic_report = {
        str(expected_features[i]): {
            "impact_coefficient": round(float(shap_values[i]), 4),
            "forensic_analysis": generate_forensic_context(str(expected_features[i]), float(shap_values[i]))
        } for i in top_indices
    }
    
    execution_time = round(time.time() - start_time, 3)
    
    return {
        "metadata": {"filename": file.filename, **file_hashes},
        "verdict": {
            "is_malicious": bool(prediction),
            "threat_score": round(risk_probability * 100, 2)
        },
        "telemetry": forensic_report,
        "performance": {"latency_seconds": execution_time}
    }
