import subprocess
import sys
import time
import os

def run_app():
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")

    print("=" * 60)
    print("Starting LogPulse Security Log Analyzer")
    print("=" * 60)

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "backend.main:app",
        "--host",
        host,
        "--port",
        str(port),
        "--reload"
    ]

    print(f"\n>> Launching LogPulse on http://{host}:{port} ...")
    proc = subprocess.Popen(cmd, cwd=os.path.dirname(os.path.abspath(__file__)))

    time.sleep(2)
    print("=" * 60)
    print(">> App is live at: http://127.0.0.1:8000")
    print(">> Interactive API Docs: http://127.0.0.1:8000/docs")
    print("=" * 60)
    print("Press CTRL+C to stop.")

    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\nStopping server...")
        proc.terminate()
        print("Shutdown complete.")

if __name__ == "__main__":
    run_app()
