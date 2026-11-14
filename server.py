"""PatchPilot web server: starts agent runs in background threads and streams their events (SSE)."""
import asyncio
import json
import threading
import time
import uuid
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env", override=True)

from fastapi import FastAPI  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from agent import PatchPilot  # noqa: E402

app = FastAPI(title="PatchPilot")
RUNS: dict[str, list[dict]] = {}
STATIC = Path(__file__).parent / "static"


class RunReq(BaseModel):
    repo_url: str | None = None


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.post("/api/run")
def start(req: RunReq):
    active = sum(1 for evs in RUNS.values() if evs and evs[-1].get("type") != "done")
    if active >= int(__import__("os").getenv("MAX_CONCURRENT_RUNS", "2")):
        return JSONResponse({"error": "PatchPilot is busy with other scans. Try again in a minute, or open a saved case study."}, 429)
    rid = uuid.uuid4().hex[:8]
    RUNS[rid] = []

    def emit(ev: dict):
        ev["t"] = round(time.time(), 2)
        RUNS[rid].append(ev)
        print(f"[{rid}] {ev.get('type')}: {str(ev)[:160]}", flush=True)
        if ev["type"] == "done":
            save_case(rid, req.repo_url, RUNS[rid], ev.get("seconds"))

    threading.Thread(target=PatchPilot(emit, req.repo_url).run, daemon=True).start()
    return {"run_id": rid}


CASES = Path(__file__).parent / "cases"


def save_case(rid, repo, evs, seconds):
    """Persist every finished run as a case study (report + key stats)."""
    last = {}
    for e in evs:
        last[e["type"]] = e
    rep = last.get("report")
    if not rep:
        return
    c = rep["counts"]
    scan = next((e for e in evs if e["type"] == "scan" and e.get("phase") == "before"), {})
    case = {"id": rid, "repo": repo or "demo: invoice-mailer",
            "title": (repo or "invoice-mailer").rstrip("/").split("/")[-1], "ecosystem": rep.get("ecosystem"),
            "stats": {"seconds": seconds, "deps_vulns": scan.get("total", 0), "packages": scan.get("packages"),
                      "code_findings": len(last.get("review", {}).get("findings", [])), "critical": c["critical"],
                      "patch": c["patch"], "monitor": c["monitor"], "kev": last.get("intel", {}).get("kev_count", 0),
                      "patched": bool(last.get("result", {}).get("verified")), "cost_usd": last.get("usage", {}).get("cost_usd")},
            "report": {k: v for k, v in rep.items() if k not in ("type", "t")},
            "recon_summary": last.get("recon", {}).get("summary", ""),
            "intel": {k: last.get("intel", {}).get(k) for k in ("summary", "items", "chatter")},
            "compute": last.get("compute", {}).get("sandbox")}
    CASES.mkdir(exist_ok=True)
    (CASES / f"{case['title']}.json").write_text(json.dumps(case, indent=1))


@app.get("/api/cases")
def cases():
    if not CASES.exists():
        return []
    order = ["CodeAF", "DVWA", "NodeGoat", "generative-ai-for-beginners", "invoice-mailer"]  # demo last
    files = sorted(CASES.glob("*.json"), key=lambda p: (order.index(p.stem) if p.stem in order else len(order) - 0.5))
    return [json.loads(p.read_text()) for p in files]


@app.get("/api/stream/{rid}")
async def stream(rid: str):
    if rid not in RUNS:
        return JSONResponse({"error": "unknown run"}, 404)

    async def gen():
        i = 0
        while True:
            evs = RUNS[rid]
            while i < len(evs):
                yield f"data: {json.dumps(evs[i])}\n\n"
                if evs[i]["type"] == "done":
                    return
                i += 1
            await asyncio.sleep(0.3)

    return StreamingResponse(gen(), media_type="text/event-stream")


_compute_cache: dict = {}


@app.get("/api/compute")
def compute():
    """What's powering PatchPilot, read live from the partners' APIs."""
    import os
    import httpx
    from agent import make_llm
    if not _compute_cache.get("nosana") or time.time() - _compute_cache.get("_t", 0) > 60:
        try:
            _, model, provider, info = make_llm()
            p = info.get("pricing") or {}
            _compute_cache["nosana"] = {"provider": provider, "model": model, "name": info.get("name", model),
                                        "context_length": info.get("context_length"), "max_output_tokens": info.get("max_output_tokens"),
                                        "price_in_per_m": round(float(p.get("prompt", 0)) * 1e6, 3),
                                        "price_out_per_m": round(float(p.get("completion", 0)) * 1e6, 3),
                                        "hourly_usd": info.get("hourly_usd")}
        except Exception as ex:
            _compute_cache["nosana"] = {"error": str(ex)}
        _compute_cache["_t"] = time.time()
        _compute_cache["daytona"] = {"note": "Fresh sandbox per run · sizes reported live from the Daytona API when a run starts"}
    out = {k: v for k, v in _compute_cache.items() if not k.startswith("_")}
    try:  # live remaining Nosana credits (USD)
        b = httpx.get("https://api.nosana.com/api/credits/balance", timeout=10,
                      headers={"Authorization": f"Bearer {os.getenv('NOSANA_API_KEY')}"}).json()
        out["nosana_credits"] = {"assigned": b["assignedCredits"], "reserved": b["reservedCredits"],
                                 "spent": b["settledCredits"],
                                 "available": round(b["assignedCredits"] - b["reservedCredits"] - b["settledCredits"], 3)}
    except Exception as ex:
        out["nosana_credits"] = {"error": str(ex)[:80]}
    return out


@app.get("/api/health")
def health():
    import os
    return {k: bool(os.getenv(k)) for k in ("DAYTONA_API_KEY", "NOSANA_API_KEY", "TAVILY_API_KEY")}
