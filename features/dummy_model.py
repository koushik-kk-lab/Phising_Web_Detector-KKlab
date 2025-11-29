# scripts/create_dummy_model.py
# Creates a models/phish_rf.pkl dummy classifier (scikit-learn) so your Flask app can load it.

import os
from pathlib import Path
import joblib
import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

OUT_DIR = Path(__file__).resolve().parents[1] / 'models'
OUT_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = OUT_DIR / 'phish_rf.pkl'

# Synthetic dataset that matches the 7 features returned by get_features
X = np.array([
    [50, 2, 2, 0, 0, 0, 0],    # benign-like
    [120, 10, 5, 0, 1, 1, 3],  # suspicious
    [40, 0, 1, 0, 0, 0, 0],    # benign
    [200, 20, 6, 1, 1, 1, 5],  # phishing-like
])
y = np.array([0, 1, 0, 1])  # 0 = benign, 1 = phishing

pipe = Pipeline([
    ('scaler', StandardScaler()),
    ('clf', DummyClassifier(strategy='stratified', random_state=42))
])

pipe.fit(X, y)
joblib.dump(pipe, MODEL_PATH)
print(f"Saved dummy model to {MODEL_PATH}")
