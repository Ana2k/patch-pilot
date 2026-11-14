"""Deploy PatchPilot itself into a long-lived, public Daytona sandbox and print the live URL.

    .venv/bin/python deploy_daytona.py

PatchPilot then runs *in* Daytona and creates a fresh child sandbox for every scan.
"""
import os
import time
from pathlib import Path

from dotenv import dotenv_values
from daytona import CreateSandboxFromSnapshotParams, Daytona, DaytonaConfig, FileUpload, SessionExecuteRequest

ROOT = Path(__file__).parent
SHIP = ["agent.py", "security.py", "scanners.py", "server.py", "requirements.txt", "static", "demo_repo", "cases"]
ENV_KEYS = ["DAYTONA_API_KEY", "NOSANA_API_KEY", "TAVILY_API_KEY", "NOSANA_MODEL",
            "NOSANA_DEPLOYMENT_URL", "NOSANA_DEPLOYMENT_MODEL", "MAX_STEPS"]

env = {k: v for k, v in dotenv_values(ROOT / ".env").items() if k in ENV_KEYS and v}
d = Daytona(DaytonaConfig(api_key=env["DAYTONA_API_KEY"]))
sb = d.create(CreateSandboxFromSnapshotParams(language="python", public=True, auto_stop_interval=0,
                                              labels={"app": "patchpilot-live"}, env_vars=env), timeout=120)
app = f"{sb.get_work_dir().rstrip('/')}/patchpilot"
files = []
for item in SHIP:
    p = ROOT / item
    for f in ([p] if p.is_file() else [x for x in p.rglob("*") if x.is_file() and "__pycache__" not in x.parts]):
        files.append(FileUpload(source=f.read_bytes(), destination=f"{app}/{f.relative_to(ROOT)}"))
sb.fs.create_folder(app, "755")
sb.fs.upload_files(files)
print(f"sandbox {sb.id} · uploaded {len(files)} files")
r = sb.process.exec("python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt 2>&1 | tail -3", cwd=app, timeout=600)
print("install:", r.exit_code, r.result[-300:])
sb.process.create_session("web")
sb.process.execute_session_command("web", SessionExecuteRequest(
    command=f"cd {app} && .venv/bin/uvicorn server:app --host 0.0.0.0 --port 8000 > server.log 2>&1", run_async=True))
time.sleep(6)
print("health:", sb.process.exec("curl -s localhost:8000/api/health", timeout=30).result)
link = sb.get_preview_link(8000)
print("LIVE URL:", link.url)
(ROOT / "LIVE_URL.txt").write_text(f"{link.url}\nsandbox={sb.id}\n")
