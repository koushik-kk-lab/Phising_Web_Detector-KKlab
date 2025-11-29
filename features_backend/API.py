from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import numpy as np
import url_features  # ✅ replace featureExtraction with your actual file name

# -------------------------------------------------------
# Load pre-trained Random Forest model
# -------------------------------------------------------
with open("RandomForestModel.sav", "rb") as model_file:
    model = pickle.load(model_file)

# Initialize FastAPI app
app = FastAPI(
    title="Phishing URL Detection API",
    description="A machine learning-based API that classifies URLs as Legitimate or Phishing.",
    version="1.0"
)

# -------------------------------------------------------
# Define input schema
# -------------------------------------------------------
class URLRequest(BaseModel):
    url: str

# -------------------------------------------------------
# Prediction endpoint
# -------------------------------------------------------
@app.post("/predict")
async def predict_url(request: URLRequest):
    """
    Accepts a URL, extracts its features, and returns prediction results.
    """
    url = request.url
    print(f"Received URL: {url}")

    # ✅ Call the correct function from your url_extract module
    # Example: if your function name is getAttributess, keep it.
    # If it’s get_features or extract_features, change accordingly.
    features = url_features.getAttributess(url)

    if not isinstance(features, np.ndarray):
        features = np.array(features).reshape(1, -1)

    prediction_label = int(model.predict(features)[0])

    response = {
        "url": url,
        "features": features.tolist()[0] if features.ndim > 1 else features.tolist(),
        "decision_source": "model: RandomForest",
        "prediction": "benign" if prediction_label == 0 else "phishing",
        "prediction_label": prediction_label
    }

    return response
