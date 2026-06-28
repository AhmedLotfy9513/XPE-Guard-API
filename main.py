import time
import hashlib
import joblib
import numpy as np
import shap
import pefile
from fastapi import FastAPI, UploadFile, File
from pydantic import BaseModel

app = FastAPI(title="XPE-Guard Engine")

# Load model (تأكد أن ملف model.pkl موجود في نفس المجلد)
model = joblib.load("model.pkl")
explainer = shap.TreeExplainer(model)
feature_names = model.feature_names_in_

def get_forensic_note(feat_name: str, val: float) -> str:
    notes = {
        "ep_section_entropy": "High entropy detected in entry point; possible packing or obfuscation.",
        "has_aslr": "Memory randomization manipulation detected; typical evasion behavior.",
        "avg_string_length": "Abnormal string length; potential for encrypted payloads.",
        "has_anti_debug_imports": "Anti-debugging signatures found; indicates evasion attempt.",
        "num_resources": "Anomalous resource count; may contain hidden malicious data."
    }
    return notes.get(feat_name, f"Feature '{feat_name}' contribution: {'Malicious' if val > 0 else 'Benign'}")

@app.post("/api/v1/scan")
async def analyze(file: UploadFile = File(...)):
    start_time = time.time()
    content = await file.read()
    
    # Metadata
    metadata = {
        "md5": hashlib.md5(content).hexdigest(),
        "is_signed": hasattr(pefile.PE(data=content), 'DIRECTORY_ENTRY_SECURITY') if True else False
    }
    
    # Placeholder: Features (استبدلها بـ 55 خاصية الخاصة بك)
    features = np.array([0.0]*55).reshape(1, -1)
    
    # Prediction
    prediction = int(model.predict(features)[0])
    confidence = float(model.predict_proba(features)[0][prediction])
    
    # SHAP
    shap_vals = explainer.shap_values(features)[0]
    top_indices = np.argsort(np.abs(shap_vals))[::-1][:5]
    report = {str(feature_names[i]): {"shap_value": float(shap_vals[i]), "forensic_note": get_forensic_note(feature_names[i], shap_vals[i])} for i in top_indices}
    
    return {
        "file_info": {"name": file.filename, **metadata},
        "analysis": {"is_malware": bool(prediction), "confidence": confidence},
        "explainability": report,
        "metrics": {"latency": round(time.time() - start_time, 4)}
    }