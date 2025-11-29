# app.py
# Flask app for phishing URL detection (dev mode)
# Supports GET (query param) and POST (form or JSON).
# Uses deterministic rules for dev testing and falls back to ML model if available.

import pathlib
import joblib
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from features.url_features import get_features

app = Flask(__name__)

BASE_DIR = pathlib.Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / 'models' / 'phish_rf.pkl'

# Deterministic dev rules
SAFE_DOMAINS = {
    'google.com', 'www.google.com',
    'youtube.com', 'www.youtube.com',
    'github.com', 'www.github.com',
    'example.com', 'www.example.com',
}

SUSPICIOUS_KEYWORDS = {
    'login', 'verify', 'update', 'secure', 'bank', 'account', 'confirm', 'pay', 'ebay', 'paypal'
}

# Try to load an ML model (optional). If missing, the app still works via rules.
try:
    model = joblib.load(MODEL_PATH)
    print(f"Loaded model from {MODEL_PATH}")
except Exception as e:
    model = None
    print(f"⚠️ Model not found or failed to load: {e}")

def domain_from_url(url: str):
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    return host.lower()

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Phishing URL Detector</title>
        <meta name="viewport" content="width=device-width,initial-scale=1" />
        <style>
            :root{
                --bg1: #667eea;
                --bg2: #764ba2;
                --card: rgba(255,255,255,0.06);
                --accent: #ff6b6b;
                --accent-2: #4ade80;
                --glass: rgba(255,255,255,0.06);
                --muted: rgba(255,255,255,0.85);
            }
            html,body{height:100%;margin:0;font-family:Inter,Segoe UI,Roboto,system-ui,-apple-system; }
            body{
                background: linear-gradient(135deg,var(--bg1),var(--bg2));
                display:flex;
                align-items:center;
                justify-content:center;
                padding:24px;
                color:var(--muted);
            }
            .card{
                width:420px;
                max-width:95%;
                background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.02));
                border-radius:14px;
                padding:28px;
                box-shadow: 0 12px 40px rgba(0,0,0,0.35);
                border: 1px solid rgba(255,255,255,0.06);
            }
            h1{margin:0 0 14px 0;font-size:20px;color:#fff;text-align:center}
            p.lead{margin:0 0 20px 0;text-align:center;opacity:0.95}
            form{display:flex;flex-direction:column;align-items:center;gap:12px}
            input[type="text"]{
                width:100%;
                padding:12px 14px;
                border-radius:10px;
                border: none;
                outline: none;
                font-size:14px;
                background: rgba(255,255,255,0.03);
                color: #fff;
                box-shadow: inset 0 1px 0 rgba(255,255,255,0.02);
            }
            .row{
                display:flex;
                gap:12px;
                width:100%;
            }
            button.primary{
                flex:1;
                padding:10px 14px;
                border-radius:10px;
                border:none;
                background: linear-gradient(90deg,var(--accent),#ff4757);
                color:#fff;
                font-weight:600;
                cursor:pointer;
            }
            button.secondary{
                padding:10px 14px;
                border-radius:10px;
                border:1px solid rgba(255,255,255,0.06);
                background:transparent;
                color:#fff;
                cursor:pointer;
            }
            .foot{margin-top:16px;font-size:13px;text-align:center;opacity:0.9}
            pre.output{
                white-space:pre-wrap;
                word-break:break-word;
                background: rgba(0,0,0,0.28);
                padding:12px;border-radius:8px;margin-top:12px;color:#fff;
            }
            .badge-safe{display:inline-block;padding:6px 10px;border-radius:999px;background:var(--accent-2);color:#062713;font-weight:700}
            .badge-phish{display:inline-block;padding:6px 10px;border-radius:999px;background:#ff6b6b;color:#fff;font-weight:700}
            @media (max-width:480px){
                .card{padding:18px}
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Phishing URL Detector</h1>
            <p class="lead">Paste a URL below and click <strong>Predict</strong>. API: POST /predict JSON {"url":"..."} or GET /predict?url=...</p>
            <form action="/predict" method="post" id="detectForm">
                <input type="text" name="url" id="urlInput" placeholder="https://example.com/login" required autocomplete="off" />
                <div class="row">
                    <button class="primary" type="submit">Predict</button>
                    <button class="secondary" type="button" id="exampleBtn">Try Example</button>
                </div>
            </form>
            <div id="resultArea" style="display:none">
                <div id="resultBadge" style="margin-top:12px;text-align:center"></div>
                <pre id="resultJson" class="output"></pre>
            </div>
            <div class="foot">
                Examples: <code>/predict?url=https://www.youtube.com</code> — <code>POST {{'url':'https://...'}}</code>
            </div>
        </div>

        <script>
            const form = document.getElementById('detectForm');
            const urlInput = document.getElementById('urlInput');
            const resultArea = document.getElementById('resultArea');
            const resultJson = document.getElementById('resultJson');
            const resultBadge = document.getElementById('resultBadge');
            document.getElementById('exampleBtn').addEventListener('click', () => {
                urlInput.value = 'https://secure-login-paypal.com/verify';
            });

            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const url = urlInput.value.trim();
                if(!url) return;
                try {
                    const res = await fetch('/predict', {
                        method: 'POST',
                        headers: {'Content-Type':'application/json'},
                        body: JSON.stringify({url})
                    });
                    const data = await res.json();
                    resultArea.style.display = 'block';
                    resultJson.textContent = JSON.stringify(data, null, 2);
                    if(data.prediction_label === 1){
                        resultBadge.innerHTML = '<span class="badge-phish">PHISHING</span>';
                    } else {
                        resultBadge.innerHTML = '<span class="badge-safe">BENIGN</span>';
                    }
                    window.scrollTo({top: document.body.scrollHeight, behavior:'smooth'});
                } catch (err){
                    resultArea.style.display = 'block';
                    resultJson.textContent = 'Error: ' + err;
                    resultBadge.innerHTML = '';
                }
            });
        </script>
    </body>
    </html>
    '''

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    # Accept GET (?url=...) or POST (form or JSON)
    if request.method == 'GET':
        url = request.args.get('url')
    else:
        if request.is_json:
            data = request.get_json()
            url = data.get('url') if isinstance(data, dict) else None
        else:
            url = request.form.get('url') or request.values.get('url')

    if not url:
        return jsonify({'error': 'no url provided'}), 400

    url = url.strip()
    feats = get_features(url)
    domain = domain_from_url(url)

    # heuristics first, then safe whitelist
    if any(k in url.lower() for k in SUSPICIOUS_KEYWORDS) or feats[3] == 1 or feats[4] == 1 or feats[6] > 0:
        pred_label = 1
        decision_source = 'rule: suspicious_heuristic'
    elif domain in SAFE_DOMAINS:
        pred_label = 0
        decision_source = 'rule: safe_domain'
    elif model is not None:
        pred_label = int(model.predict([feats])[0])
        decision_source = 'model'
    else:
        pred_label = 0
        decision_source = 'fallback: dev_mode_no_model'

    result = 'phishing' if pred_label == 1 else 'benign'

    # Try to grab probabilities if model used
    prob = None
    if model is not None and decision_source == 'model':
        try:
            prob = model.predict_proba([feats])[0].tolist()
        except Exception:
            prob = None

    response = {
        'url': url,
        'prediction': result,
        'prediction_label': int(pred_label),
        'probabilities': prob,
        'features': feats,
        'decision_source': decision_source,
    }

    # For browser GETs return an HTML preformatted box for quick reading
    if request.method == 'GET' and not request.is_json:
        return f"<pre>{response}</pre>"

    return jsonify(response)

if __name__ == '__main__':
    # Change host='0.0.0.0' if you want to expose to other machines/containers
    app.run(debug=True, host='127.0.0.1', port=5000)
