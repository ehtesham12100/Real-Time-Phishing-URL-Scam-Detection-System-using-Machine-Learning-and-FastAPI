import sys
import uvicorn
import webbrowser
import threading
import time

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

def open_browser():
    time.sleep(1.2)
    print("Opening browser at http://127.0.0.1:8000 ...")
    webbrowser.open("http://127.0.0.1:8000")

if __name__ == "__main__":
    print("-" * 50)
    print("  Starting Phishing Detection Web Application")
    print("  URL: http://127.0.0.1:8000")
    print("  Press Ctrl + C in this terminal to stop.")
    print("-" * 50)

    # Automatically open web browser
    threading.Thread(target=open_browser, daemon=True).start()

    # Run the server
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
