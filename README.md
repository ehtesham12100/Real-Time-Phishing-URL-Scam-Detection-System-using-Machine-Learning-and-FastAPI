# PhishGuard AI — Phishing Detection Platform

An AI-powered cybersecurity platform that detects phishing URLs, email/SMS scam messages, and zero-day malicious domains using explainable machine learning, threat intelligence, and a modern web dashboard.

---

## 🛠️ Tools & Technologies Used (Point Explanation)

- **Python 3.11**  
  Core programming language used for feature extraction, machine learning probability calculations, NLP text heuristics, and backend orchestration.

- **FastAPI**  
  Modern, high-performance asynchronous web framework used to build REST API endpoints (`/api/scan`, `/api/scan-text`, `/api/batch-scan`, `/api/history`) and serve the web dashboard. Provides automatic interactive OpenAPI/Swagger documentation at `/docs`.

- **Uvicorn**  
  Lightning-fast ASGI (Asynchronous Server Gateway Interface) web server used to run the FastAPI application with asynchronous concurrency.

- **SQLite 3 (`sqlite3`)**  
  Serverless, self-contained relational database built into Python. Used to store persistent security audit logs in `phishguard.db`, track scan history, and power real-time threat telemetry counters with zero external server dependencies.

- **Tailwind CSS**  
  Utility-first CSS framework used via CDN to create a modern, responsive, dark-mode Cyber Security Operations Center (SOC) dashboard.

- **Font Awesome**  
  Iconography library providing cybersecurity indicators, threat meters, and status badges across the UI.

- **Shannon Entropy Algorithm (`math.log2`)**  
  Information-theory algorithm that calculates character distribution randomness:
  $$H(X) = -\sum P(c) \log_2 P(c)$$
  Used to detect algorithmic domain generation (DGA) and randomized obfuscation patterns frequently used in disposable phishing domains.

- **Levenshtein Distance Algorithm**  
  Dynamic programming string-matching algorithm used to detect Brand Typosquatting (e.g., catching `paypa1` or `micros0ft` spoofing protected corporate brands).

- **Google Safe Browsing API v4**  
  External live threat intelligence feed used to verify URLs against Google's global database of confirmed malware and social engineering attacks.

- **Pydantic**  
  Data validation and schema library used by FastAPI to enforce strict data types on all incoming API request payloads.

- **Jinja2**  
  Fast template rendering engine used by FastAPI to serve the dashboard HTML.

- **Socket & DNS Resolver (`socket`)**  
  Network utility used to verify active DNS A-record resolution for scanned hostnames.

---

## 🚀 How to Run the Project

### Option 1: Web Dashboard (Recommended)
Run the launcher script from the project folder:
```powershell
python run.py
```
- Dashboard UI will automatically open at: **http://127.0.0.1:8000**
- Interactive Swagger API Documentation: **http://127.0.0.1:8000/docs**

### Option 2: Command-Line Interface (CLI Mode)
To scan directly in the terminal:
```powershell
python phishing_detector.py
```

---

## 📁 Project Structure

- **`run.py`**: One-click startup script that starts the Uvicorn server and automatically opens the browser.
- **`main.py`**: FastAPI backend application with REST routes, database calls, and template rendering.
- **`ai_classifier.py`**: 15-feature extraction engine, Shannon entropy, Levenshtein typosquatting detector, and logistic machine learning classifier.
- **`threat_intel.py`**: Google Safe Browsing API integration and DNS resolution checker.
- **`database.py`**: SQLite database manager for audit logs, telemetry stats, and CSV export.
- **`phishing_detector.py`**: Standalone terminal CLI scanner.
- **`templates/index.html`**: Cyber SOC dashboard web interface.
- **`static/style.css`**: Dashboard styles, badge themes, and animations.
- **`static/app.js`**: Frontend JavaScript for real-time API communication and dynamic telemetry updates.
- **`phishguard.db`**: Local SQLite database storing all scan records (created automatically).
