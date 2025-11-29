# features/url_features.py
# Minimal realistic feature extractor for a URL so your model receives a fixed-length vector.

from urllib.parse import urlparse
import re

FEATURE_NAMES = [
    'length',           # total length of URL
    'num_digits',       # number of digits in URL
    'num_dots',         # number of dots in hostname
    'has_ip',           # whether hostname is an IP address
    'has_at',           # '@' in URL
    'has_dash',         # '-' in hostname
    'suspicious_words', # count of known suspicious keywords
]

SUSPICIOUS_WORDS = [
    'login', 'verify', 'update', 'secure', 'bank', 'account', 'ebay', 'paypal', 'confirm', 'pay'
]

def get_features(url: str):
    """
    Return a list of numeric features for the provided URL.
    Deterministic and small so it's stable for dev/testing.
    """
    if not isinstance(url, str):
        url = str(url or '')

    parsed = urlparse(url)
    # If the user passed something like 'example.com' (no scheme), parsed.netloc may be empty.
    host = parsed.netloc or parsed.path
    full = url

    length = len(full)
    num_digits = sum(c.isdigit() for c in full)
    num_dots = host.count('.')
    has_ip = 1 if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', host) else 0
    has_at = 1 if '@' in full else 0
    has_dash = 1 if '-' in host else 0
    lower = full.lower()
    suspicious_words = sum(1 for w in SUSPICIOUS_WORDS if w in lower)

    return [
        length,
        num_digits,
        num_dots,
        has_ip,
        has_at,
        has_dash,
        suspicious_words,
    ]
