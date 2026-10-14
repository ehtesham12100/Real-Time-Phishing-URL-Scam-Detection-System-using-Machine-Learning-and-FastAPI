import math
import re
from urllib.parse import urlparse

# -------------------------------------------------------------
# String Analysis Helpers
# -------------------------------------------------------------

def calculate_shannon_entropy(text: str) -> float:
    """Calculates character randomness to spot auto-generated fake domains."""
    if not text:
        return 0.0
    length = len(text)
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates edit distance to detect fake brand names like 'paypa1'."""
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    return dp[m][n]

# Commonly targeted brands
PROTECTED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", 
    "netflix", "facebook", "instagram", "chase", "wellsfargo", 
    "bankofamerica", "binance", "coinbase", "dropbox", "twitter",
    "whatsapp", "linkedin", "adobe", "yahoo", "github"
]

# Suspicious domain extensions often used for cheap spam
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "club", "tk", "ml", "ga", "cf", "gq", 
    "work", "icu", "click", "rest", "fit", "surf", "monster"
}

# Common keywords used in phishing traps
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking", 
    "confirm", "wallet", "password", "security", "free", "bonus",
    "signin", "authenticate", "suspend", "unlock", "alert", "recover"
]

HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', 
    '8': 'b', '@': 'a', '$': 's'
}

# -------------------------------------------------------------
# Feature Extraction
# -------------------------------------------------------------

def extract_url_features(url: str) -> dict:
    """Extracts structural and lexical features from the URL."""
    raw_url = url.strip()
    if not re.match(r'^[a-zA-Z]+://', raw_url):
        raw_url = "http://" + raw_url
    
    parsed = urlparse(raw_url)
    hostname = (parsed.netloc or "").lower()
    if ":" in hostname:
        hostname = hostname.split(":")[0]
    
    path = parsed.path or ""
    query = parsed.query or ""
    full_clean = raw_url.lower()

    url_length = len(raw_url)
    hostname_length = len(hostname)
    path_length = len(path)
    
    # Check if host is direct IP address
    has_ip = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname) else 0

    # Subdomains
    dot_count = hostname.count(".")
    subdomains_count = max(0, dot_count - 1) if not has_ip else 0

    # Special characters
    count_hyphens = raw_url.count("-")
    count_at = raw_url.count("@")
    count_double_slash_redirect = 1 if "//" in (path + query) else 0
    count_question = raw_url.count("?")
    count_equal = raw_url.count("=")
    count_percent = raw_url.count("%")

    domain_entropy = calculate_shannon_entropy(hostname)

    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_clean]
    keyword_count = len(matched_keywords)

    tld = hostname.split(".")[-1] if "." in hostname else ""
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    lookalike_count = sum(1 for ch in hostname if ch in HOMOGLYPH_MAP)

    # Check for brand typosquatting (edit distance <= 2)
    brand_spoofed = None
    typosquat_flag = 0
    clean_host_alpha = re.sub(r'[^a-z0-9]', ' ', hostname).split()
    for token in clean_host_alpha:
        for brand in PROTECTED_BRANDS:
            if token == brand:
                continue
            dist = levenshtein_distance(token, brand)
            if dist == 1 or (len(brand) > 5 and dist == 2):
                brand_spoofed = f"{brand} (written as '{token}')"
                typosquat_flag = 1
                break
        if typosquat_flag:
            break

    path_depth = len([p for p in path.split("/") if p])

    return {
        "url": raw_url,
        "hostname": hostname,
        "tld": tld,
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "has_ip": has_ip,
        "subdomains_count": subdomains_count,
        "count_hyphens": count_hyphens,
        "count_at": count_at,
        "count_double_slash_redirect": count_double_slash_redirect,
        "count_question": count_question,
        "count_equal": count_equal,
        "count_percent": count_percent,
        "domain_entropy": domain_entropy,
        "keyword_count": keyword_count,
        "matched_keywords": matched_keywords,
        "is_suspicious_tld": is_suspicious_tld,
        "lookalike_count": lookalike_count,
        "typosquat_flag": typosquat_flag,
        "brand_spoofed": brand_spoofed,
        "path_depth": path_depth
    }

# -------------------------------------------------------------
# Scoring Model
# -------------------------------------------------------------

# Weights for indicators based on phishing datasets
WEIGHTS = {
    "has_ip": 2.8,
    "count_at": 2.2,
    "count_double_slash_redirect": 2.0,
    "typosquat_flag": 2.6,
    "is_suspicious_tld": 1.7,
    "high_subdomains": 1.5,
    "excessive_hyphens": 1.4,
    "suspicious_keywords": 0.8,
    "high_entropy": 1.3,
    "excessive_url_length": 1.2,
    "lookalike_chars": 0.9,
    "deep_path": 0.7
}

MODEL_BIAS = -2.4  # Negative baseline: typical legitimate links have low probability

def predict_phishing(url: str) -> dict:
    """Evaluates features and calculates risk score."""
    feats = extract_url_features(url)
    
    score_sum = MODEL_BIAS
    reasons = []

    # IP in host
    if feats["has_ip"]:
        score_sum += WEIGHTS["has_ip"]
        reasons.append({
            "feature": "Direct IP Address",
            "impact": "High Risk",
            "description": f"URL uses raw IP ({feats['hostname']}) instead of a standard domain name."
        })

    # @ Symbol
    if feats["count_at"] > 0:
        score_sum += WEIGHTS["count_at"] * feats["count_at"]
        reasons.append({
            "feature": "@ Symbol Masking",
            "impact": "High Risk",
            "description": "Browsers use text after '@' as the actual destination, masking the real link."
        })

    # Double slash
    if feats["count_double_slash_redirect"]:
        score_sum += WEIGHTS["count_double_slash_redirect"]
        reasons.append({
            "feature": "Redirect Pattern (//)",
            "impact": "High Risk",
            "description": "Found '//' inside the path, which can redirect you to an external site."
        })

    # Brand typosquatting
    if feats["typosquat_flag"]:
        score_sum += WEIGHTS["typosquat_flag"]
        reasons.append({
            "feature": "Brand Lookalike",
            "impact": "High Risk",
            "description": f"Domain appears to mimic a known brand: {feats['brand_spoofed']}."
        })

    # Risky TLD
    if feats["is_suspicious_tld"]:
        score_sum += WEIGHTS["is_suspicious_tld"]
        reasons.append({
            "feature": f"Suspicious Extension (.{feats['tld']})",
            "impact": "Medium Risk",
            "description": f"The extension '.{feats['tld']}' is frequently used in temporary spam sites."
        })

    # Subdomains
    if feats["subdomains_count"] >= 3:
        score_sum += WEIGHTS["high_subdomains"] * (feats["subdomains_count"] - 2)
        reasons.append({
            "feature": "Too Many Subdomains",
            "impact": "Medium Risk",
            "description": f"Found {feats['subdomains_count']} subdomain levels used to confuse users."
        })

    # Hyphens
    if feats["count_hyphens"] >= 2:
        score_sum += min(2.5, WEIGHTS["excessive_hyphens"] * (feats["count_hyphens"] - 1) * 0.5)
        reasons.append({
            "feature": "Multiple Hyphens",
            "impact": "Medium Risk",
            "description": f"Domain uses {feats['count_hyphens']} hyphens (e.g. 'paypal-security-update')."
        })

    # Keywords
    if feats["keyword_count"] > 0:
        score_sum += min(2.4, WEIGHTS["suspicious_keywords"] * feats["keyword_count"])
        reasons.append({
            "feature": "Sensitive Keywords",
            "impact": "Medium Risk",
            "description": f"Found action keywords: {', '.join(feats['matched_keywords'])}."
        })

    # Entropy
    if feats["domain_entropy"] >= 3.6:
        score_sum += WEIGHTS["high_entropy"]
        reasons.append({
            "feature": "Random Character Text",
            "impact": "Medium Risk",
            "description": f"Domain character randomness is high ({feats['domain_entropy']} bits), typical for bot-generated links."
        })
    elif feats["domain_entropy"] < 2.5:
        score_sum -= 0.5

    # Long URL
    if feats["url_length"] > 75:
        score_sum += min(1.8, WEIGHTS["excessive_url_length"] * ((feats["url_length"] - 75) / 50))
        reasons.append({
            "feature": "Unusually Long Link",
            "impact": "Low Risk",
            "description": f"URL length is {feats['url_length']} characters (most normal URLs are under 60)."
        })

    # Lookalike characters
    if feats["lookalike_count"] > 0 and not feats["has_ip"]:
        score_sum += min(1.8, WEIGHTS["lookalike_chars"] * feats["lookalike_count"])
        reasons.append({
            "feature": "Character Substitutions",
            "impact": "Low Risk",
            "description": "Found characters like 0 or 1 replacing letters like 'o' or 'l'."
        })

    # Path depth
    if feats["path_depth"] >= 4:
        score_sum += WEIGHTS["deep_path"]
        reasons.append({
            "feature": "Deep Directory Nesting",
            "impact": "Low Risk",
            "description": f"Link is nested {feats['path_depth']} folders deep."
        })

    # Sigmoid function for probability
    clipped = max(-10.0, min(10.0, score_sum))
    probability = 1.0 / (1.0 + math.exp(-clipped))
    risk_score = round(probability * 100, 1)

    # Human-friendly verdict
    if risk_score >= 70.0:
        verdict = "PHISHING LINK (High Risk)"
        verdict_level = "danger"
        recommendation = "Do not click or enter passwords. High signs of credential theft or brand spoofing."
    elif risk_score >= 40.0:
        verdict = "SUSPICIOUS LINK (Caution)"
        verdict_level = "warning"
        recommendation = "Be cautious. This link has patterns commonly found on untrusted websites."
    else:
        verdict = "SAFE LINK"
        verdict_level = "safe"
        recommendation = "This link appears normal and shows standard domain structure."

    if not reasons:
        reasons.append({
            "feature": "Clean Link",
            "impact": "Safe",
            "description": "Standard domain name, reasonable length, and no known brand spoofing patterns."
        })

    return {
        "url": feats["url"],
        "hostname": feats["hostname"],
        "risk_score": risk_score,
        "probability": round(probability, 4),
        "verdict": verdict,
        "verdict_level": verdict_level,
        "recommendation": recommendation,
        "logit_score": round(score_sum, 2),
        "contributions": reasons,
        "features": feats
    }

# -------------------------------------------------------------
# Message & Email Scanner
# -------------------------------------------------------------

URGENT_PHRASES = [
    "account suspended", "urgent action required", "immediately", "within 24 hours",
    "unauthorized login", "security alert", "verify your identity", "reset password",
    "won a prize", "lottery", "claim your reward", "tax refund", "wire transfer",
    "final notice", "billing problem", "unusual activity", "click the link below"
]

def analyze_phishing_text(text: str) -> dict:
    """Scans email or SMS text for pressure tactics and embedded links."""
    clean_text = text.lower()
    matched_urgency = [phrase for phrase in URGENT_PHRASES if phrase in clean_text]
    urls_found = re.findall(r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-z]{2,}/[^\s]*)', text)
    
    urgency_score = len(matched_urgency) * 20
    has_money = bool(re.search(r'(\$|€|£|₹|\b(usd|inr|cash|dollars|gift card|crypto|bitcoin)\b)', clean_text))
    if has_money:
        urgency_score += 15

    total_risk = min(100, urgency_score + (15 if len(urls_found) > 0 else 0))
    
    if total_risk >= 65:
        verdict = "Likely Scam / Phishing"
        verdict_level = "danger"
    elif total_risk >= 35:
        verdict = "Suspicious Message"
        verdict_level = "warning"
    else:
        verdict = "Normal Message"
        verdict_level = "safe"

    return {
        "text_preview": text[:120] + ("..." if len(text) > 120 else ""),
        "risk_score": total_risk,
        "verdict": verdict,
        "verdict_level": verdict_level,
        "matched_urgency_phrases": matched_urgency,
        "embedded_urls": urls_found,
        "has_financial_lure": has_money
    }
