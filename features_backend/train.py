import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.exceptions import UndefinedMetricWarning
import warnings

# suppress warnings for tiny datasets
warnings.filterwarnings("ignore", category=UndefinedMetricWarning)

# import your feature extractor
import sys
import pathlib
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from features.url_features import get_features  # adjust if needed

# paths
ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODEL_DIR / "phish_rf.pkl"
CSV_PATH = DATA_DIR / "urls.csv"

# create tiny sample dataset if missing
if not CSV_PATH.exists():
    DATA_DIR.mkdir(exist_ok=True)
    sample = [
        ("http://example.com", 0),
        ("https://www.google.com", 0),
        ("http://192.168.0.1/login", 1),
        ("http://secure-login.bank.example.com@malicious.com", 1),
        ("http://free-gift.example.info/win", 1),
    ]
    df_sample = pd.DataFrame(sample, columns=["url", "label"])
    df_sample.to_csv(CSV_PATH, index=False)
    print("Created sample dataset at", CSV_PATH)

# load dataset
df = pd.read_csv(CSV_PATH)
X = [get_features(u) for u in df["url"].astype(str).tolist()]
X = pd.DataFrame(X)
y = df["label"]

# handle tiny datasets safely
n_classes = len(y.unique())
min_test_samples = n_classes
test_size = max(min_test_samples / len(df), 0.2)

# stratify only if dataset is large enough
stratify_param = y if len(df) >= n_classes else None

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=test_size, random_state=42, stratify=stratify_param
)

# train model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# evaluation
if len(y_test) < 5:
    print("\n⚠️ Tiny dataset detected (<5 test samples). Metrics may be misleading.")
    print("y_test:", list(y_test))
    print("y_pred:", list(clf.predict(X_test)))
else:
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1] if hasattr(clf, "predict_proba") else None
    print(classification_report(y_test, y_pred))
    if y_proba is not None:
        print("AUC:", roc_auc_score(y_test, y_proba))

# save model
joblib.dump(clf, MODEL_PATH)
print("\nSaved model to", MODEL_PATH)
