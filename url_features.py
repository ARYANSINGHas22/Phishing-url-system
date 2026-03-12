"""
URL Feature Extraction Module
Contains feature extraction functions and security-related constants for phishing detection.
"""

import re
import urllib.parse

# ─────────────────────────────────────────────────
# Constants  (used in app.py for rule-based detection)
# ─────────────────────────────────────────────────

# Common brands that phishers impersonate
BRANDS = [
    "amazon", "apple", "google", "microsoft", "paypal", "facebook",
    "twitter", "instagram", "linkedin", "netflix", "spotify", "adobe",
    "dropbox", "github", "slack", "stripe", "bank", "chase", "wells",
    "fargo", "boa", "citibank", "hsbc", "barclays", "aol", "outlook",
    "gmail", "yahoo", "login", "account", "verify", "confirm", "update",
    "confirm-identity", "activate", "secure-update"
]

# Keywords commonly found in phishing URLs
PHISHING_KEYWORDS = [
    "verify", "confirm", "update", "secure", "login", "signin", "account",
    "password", "credit", "card", "bank", "urgent", "action", "required",
    "validate", "activate", "suspended", "limited", "restricted", "claim",
    "alert", "warning", "unusual", "activity", "manage", "billing"
]

# Suspicious free/cheap TLDs often used in phishing
SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "top", "download", "click", "stream",
    "zip", "men", "lol", "review", "xyz", "date", "webcam", "trade"
]


# ─────────────────────────────────────────────────
# Feature Extraction  (for ML model)
# ─────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Extract numerical and categorical features from a URL for ML model.
    This is a feature extraction interface for training/prediction.
    
    Returns:
        dict: Dictionary of extracted features
    """
    features = {}
    
    # Normalize URL
    u = url.lower().strip()
    if not u.startswith(('http://', 'https://')):
        u = 'http://' + u
    
    parsed = urllib.parse.urlparse(u)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    domain = re.sub(r'^www\.', '', hostname)
    
    # Basic features
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    features['has_https'] = 1 if u.startswith('https') else 0
    features['has_at_symbol'] = 1 if '@' in u else 0
    features['has_hyphen'] = 1 if '-' in domain else 0
    features['has_ip'] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0
    features['dot_count'] = u.count('.')
    features['hyphen_count'] = u.count('-')
    
    # Subdomain features
    labels = domain.split('.')
    features['subdomain_count'] = max(0, len(labels) - 2)
    
    # TLD features
    tld = labels[-1] if labels else ''
    features['has_suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0
    
    # Keyword features
    features['phishing_keyword_count'] = sum(1 for kw in PHISHING_KEYWORDS if kw in u)
    features['brand_count'] = sum(1 for brand in BRANDS if brand in u)
    
    # Special character features
    features['has_punycode'] = 1 if 'xn--' in hostname else 0
    features['has_percent_encoding'] = 1 if re.search(r'%[0-9a-f]{2}', u) else 0
    features['has_double_slash_path'] = 1 if '//' in path else 0
    
    # Port feature
    features['has_nonstandard_port'] = 1 if parsed.port and parsed.port not in (80, 443) else 0
    
    return features
