import sqlite3
import os
from datetime import datetime

def get_db_path() -> str:
    """
    Returns appropriate database path.
    On Vercel / AWS Lambda serverless environments, the root directory is read-only.
    The /tmp directory is the only writable location.
    """
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return "/tmp/phishguard.db"
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    # If directory is not writable, fall back to /tmp or tempfile
    if not os.access(base_dir, os.W_OK):
        import tempfile
        return os.path.join(tempfile.gettempdir(), "phishguard.db")
    
    return os.path.join(base_dir, "phishguard.db")

DB_PATH = get_db_path()

def get_connection():
    """Returns a SQLite database connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the SQLite database and creates the scan_history table if not exists."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                hostname TEXT,
                risk_score REAL NOT NULL,
                verdict TEXT NOT NULL,
                verdict_level TEXT NOT NULL,
                domain_entropy REAL,
                typosquat_flag INTEGER DEFAULT 0,
                google_flagged INTEGER DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Warning: Database init issue ({e}). Continuing in stateless mode.")

def save_scan(url: str, hostname: str, risk_score: float, verdict: str, 
              verdict_level: str, domain_entropy: float = 0.0, 
              typosquat_flag: int = 0, google_flagged: int = 0) -> int:
    """Saves a scanned URL record into the database."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history (
                url, hostname, risk_score, verdict, verdict_level, 
                domain_entropy, typosquat_flag, google_flagged, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            url, hostname, risk_score, verdict, verdict_level, 
            domain_entropy, typosquat_flag, google_flagged, 
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        scan_id = cursor.lastrowid
        conn.close()
        return scan_id or 1
    except Exception as e:
        print(f"[!] Warning: Could not save scan to database: {e}")
        return 1

def get_recent_scans(limit: int = 25):
    """Retrieves the most recent scans ordered by timestamp descending."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, url, hostname, risk_score, verdict, verdict_level, 
                   domain_entropy, typosquat_flag, google_flagged, timestamp 
            FROM scan_history 
            ORDER BY id DESC 
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception:
        return []

def get_analytics_stats():
    """Computes real-time threat telemetry statistics for dashboard counters."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) AS total FROM scan_history")
        total = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS safe FROM scan_history WHERE verdict_level = 'safe'")
        safe = cursor.fetchone()["safe"]

        cursor.execute("SELECT COUNT(*) AS warning FROM scan_history WHERE verdict_level = 'warning'")
        warning = cursor.fetchone()["warning"]

        cursor.execute("SELECT COUNT(*) AS danger FROM scan_history WHERE verdict_level = 'danger'")
        danger = cursor.fetchone()["danger"]

        conn.close()

        threat_rate = round(((danger + warning) / total * 100), 1) if total > 0 else 0.0

        return {
            "total_scans": total,
            "safe_count": safe,
            "suspicious_count": warning,
            "phishing_count": danger,
            "threat_rate": threat_rate
        }
    except Exception:
        return {
            "total_scans": 0,
            "safe_count": 0,
            "suspicious_count": 0,
            "phishing_count": 0,
            "threat_rate": 0.0
        }

def clear_scan_history():
    """Clears all audit logs from the database."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history")
        conn.commit()
        conn.close()
    except Exception:
        pass

# Auto-initialize database on import
init_db()
