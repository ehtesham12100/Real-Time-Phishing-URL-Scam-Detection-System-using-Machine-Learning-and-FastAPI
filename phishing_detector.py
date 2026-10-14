import sys
import os

# Set output encoding to UTF-8 if supported
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Add local path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_classifier import predict_phishing
from threat_intel import check_google_safe_browsing
from database import save_scan

def main():
    print("-" * 55)
    print("        Phishing Detection Tool (CLI)")
    print("-" * 55)
    
    try:
        url = input("Enter a website URL to check: ").strip()
    except (EOFError, KeyboardInterrupt):
        return

    if not url:
        print("Please enter a valid URL.")
        return

    print("\nScanning URL...")
    
    # Analyze the URL features
    result = predict_phishing(url)
    
    # Check Google Safe Browsing
    google_res = check_google_safe_browsing(url)
    
    # Save scan to database
    try:
        save_scan(
            url=result["url"],
            hostname=result["hostname"],
            risk_score=result["risk_score"],
            verdict=result["verdict"],
            verdict_level=result["verdict_level"],
            domain_entropy=result["features"].get("domain_entropy", 0.0),
            typosquat_flag=result["features"].get("typosquat_flag", 0),
            google_flagged=1 if google_res.get("flagged") else 0
        )
    except Exception:
        pass

    # Print clean results
    print("\nResults:")
    print(f"  URL        : {result['url']}")
    print(f"  Domain     : {result['hostname']}")
    print(f"  Risk Score : {result['risk_score']}%")
    print(f"  Verdict    : {result['verdict']}")
    print(f"  Advice     : {result['recommendation']}")
    
    feats = result["features"]
    print("\nKey Checks:")
    if feats["typosquat_flag"]:
        print(f"  - Looks like fake brand : {feats['brand_spoofed']}")
    if feats["has_ip"]:
        print(f"  - Uses IP address directly : Yes")
    if feats["is_suspicious_tld"]:
        print(f"  - Cheap/Risky extension    : .{feats['tld']}")
    if google_res.get("flagged"):
        print(f"  - Google Threat List       : Flagged ({google_res.get('threat_type')})")
    else:
        print(f"  - Google Threat List       : Clean")

    print("\nDetails:")
    for item in result["contributions"]:
        print(f"  * {item['feature']}: {item['description']}")
    
    print("-" * 55)
    print("Tip: Run 'python run.py' to use the web browser interface.\n")

if __name__ == "__main__":
    main()
