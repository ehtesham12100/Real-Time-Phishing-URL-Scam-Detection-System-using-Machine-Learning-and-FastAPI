import os
import io
import csv
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from pydantic import BaseModel
from typing import List, Optional

from ai_classifier import (
    predict_phishing, 
    analyze_phishing_text, 
    WEIGHTS, 
    MODEL_BIAS, 
    PROTECTED_BRANDS, 
    SUSPICIOUS_TLDS
)
from threat_intel import check_google_safe_browsing, check_dns_resolution
from database import (
    init_db, 
    save_scan, 
    get_recent_scans, 
    get_analytics_stats, 
    clear_scan_history
)

# Initialize FastAPI application
app = FastAPI(
    title="Phishing Detection Tool",
    description="URL and Message Phishing Detection API with SQLite Logging",
    version="1.0.0"
)

# Ensure DB initialized
init_db()

from pathlib import Path

# Directories (robust for local & Vercel serverless)
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

if not TEMPLATES_DIR.exists():
    alt_templates = BASE_DIR.parent / "templates"
    if alt_templates.exists():
        TEMPLATES_DIR = alt_templates
        STATIC_DIR = BASE_DIR.parent / "static"

try:
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Request Models
class URLScanRequest(BaseModel):
    url: str
    check_live_threat: Optional[bool] = True

class TextScanRequest(BaseModel):
    text: str

class BatchScanRequest(BaseModel):
    urls: List[str]

# Middleware to handle Vercel serverless path rewrites
@app.middleware("http")
async def vercel_path_normalizer(request: Request, call_next):
    path = request.scope.get("path", "")
    if path in ("/api/index.py", "/api/index", "/api/index/", "/api", "/api/"):
        request.scope["path"] = "/"
    return await call_next(request)

# ----------------- ROUTES -----------------

@app.get("/", response_class=HTMLResponse)
@app.get("/api", response_class=HTMLResponse)
@app.get("/api/index", response_class=HTMLResponse)
@app.get("/api/index.py", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Serves the main Cyber Threat SOC Dashboard."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/scan")
async def scan_single_url(req: URLScanRequest):
    """
    Scans a single URL using explainable ML, queries threat intel,
    and logs the audit record into SQLite database.
    """
    clean_url = req.url.strip()
    if not clean_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    # 1. AI / ML Classification
    ai_result = predict_phishing(clean_url)
    hostname = ai_result["hostname"]

    # 2. DNS Resolution Check
    dns_info = check_dns_resolution(hostname)

    # 3. Threat Intel (Google Safe Browsing)
    safe_browsing_info = {"status": "SKIPPED", "flagged": False, "details": "Real-time threat check bypassed."}
    if req.check_live_threat:
        safe_browsing_info = check_google_safe_browsing(clean_url)
        if safe_browsing_info.get("flagged"):
            ai_result["risk_score"] = max(ai_result["risk_score"], 95.0)
            ai_result["verdict"] = "MALICIOUS (PHISHING / MALWARE)"
            ai_result["verdict_level"] = "danger"
            ai_result["contributions"].insert(0, {
                "feature": "Google Safe Browsing Match",
                "impact": "+ Critical",
                "description": safe_browsing_info["details"]
            })

    # 4. Save into SQLite Database Audit Log
    scan_id = save_scan(
        url=clean_url,
        hostname=hostname,
        risk_score=ai_result["risk_score"],
        verdict=ai_result["verdict"],
        verdict_level=ai_result["verdict_level"],
        domain_entropy=ai_result["features"].get("domain_entropy", 0.0),
        typosquat_flag=ai_result["features"].get("typosquat_flag", 0),
        google_flagged=1 if safe_browsing_info.get("flagged") else 0
    )

    return {
        "status": "success",
        "scan_id": scan_id,
        "analysis": ai_result,
        "dns": dns_info,
        "threat_intel": safe_browsing_info
    }

@app.post("/api/scan-text")
async def scan_message_text(req: TextScanRequest):
    """NLP text analyzer for phishing emails or SMS scams (Smishing)."""
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    
    result = analyze_phishing_text(req.text)
    return {"status": "success", "analysis": result}

@app.post("/api/batch-scan")
async def scan_batch(req: BatchScanRequest):
    """Batch scans a list of URLs and persists them to SQLite."""
    if not req.urls:
        raise HTTPException(status_code=400, detail="URLs list cannot be empty")
    
    results = []
    for url in req.urls[:50]:
        clean = url.strip()
        if clean:
            pred = predict_phishing(clean)
            save_scan(
                url=clean,
                hostname=pred["hostname"],
                risk_score=pred["risk_score"],
                verdict=pred["verdict"],
                verdict_level=pred["verdict_level"],
                domain_entropy=pred["features"].get("domain_entropy", 0.0),
                typosquat_flag=pred["features"].get("typosquat_flag", 0),
                google_flagged=0
            )
            results.append({
                "url": clean,
                "risk_score": pred["risk_score"],
                "verdict": pred["verdict"],
                "verdict_level": pred["verdict_level"]
            })
    
    return {"status": "success", "count": len(results), "results": results}

@app.get("/api/history")
async def get_history(limit: int = 25):
    """Fetches recent scan history logs from SQLite."""
    scans = get_recent_scans(limit=limit)
    return {"status": "success", "scans": scans}

@app.get("/api/analytics")
async def get_analytics():
    """Fetches aggregate threat telemetry statistics."""
    stats = get_analytics_stats()
    return {"status": "success", "analytics": stats}

@app.post("/api/clear-history")
async def clear_history():
    """Clears the scan audit history table in SQLite."""
    clear_scan_history()
    return {"status": "success", "message": "Scan history cleared successfully"}

@app.get("/api/export-csv")
async def export_audit_csv():
    """Exports SQLite scan logs as a downloadable CSV report."""
    scans = get_recent_scans(limit=1000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "URL", "Hostname", "Risk Score (%)", "Verdict", "Entropy (bits)", "Typosquatting"])
    
    for s in scans:
        writer.writerow([
            s.get("id"),
            s.get("timestamp"),
            s.get("url"),
            s.get("hostname"),
            s.get("risk_score"),
            s.get("verdict"),
            s.get("domain_entropy"),
            "Yes" if s.get("typosquat_flag") else "No"
        ])
    
    csv_content = output.getvalue()
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishguard_threat_audit.csv"}
    )

@app.get("/api/model-info")
async def get_model_information():
    """Returns AI model weights, formulas, and architecture for faculty explanation."""
    return {
        "model_type": "Explainable Logistic Probability Classifier (Supervised ML)",
        "database": "SQLite 3 Relational Audit Database",
        "decision_function": "P(Phishing) = 1 / (1 + exp(-(w^T * x + b)))",
        "bias_b": MODEL_BIAS,
        "weights": WEIGHTS,
        "protected_brands_count": len(PROTECTED_BRANDS),
        "suspicious_tlds_count": len(SUSPICIOUS_TLDS)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
