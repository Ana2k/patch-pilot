"""
PatchPilot agent: find vulnerable dependencies, patch them, and PROVE the fix in a sandbox.

The anatomy of an agent (read this file top to bottom, it's the lesson):

  1. ENVIRONMENT  -> a Daytona sandbox: a disposable Linux machine where untrusted code runs.
  2. PERCEPTION   -> deterministic tools give the agent facts (OSV scan, pytest output).
  3. KNOWLEDGE    -> Tavily web search gives it fresh information its model weights don't have.
  4. BRAIN        -> an open LLM served on Nosana's decentralized GPUs decides the next action.
  5. LOOP         -> think -> act (tool call) -> observe (tool result) -> repeat until done.
  6. VERIFICATION -> we never trust the model's claim; we re-scan and re-test ourselves.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

import httpx
from daytona import CreateSandboxFromSnapshotParams, Daytona, DaytonaConfig, FileUpload
from openai import OpenAI
from tavily import TavilyClient

from scanners import detect, inventory
from security import build_report, code_review, recon, threat_intel

Emit = Callable[[dict], None]
ROOT = Path(__file__).parent
DEMO_REPO = ROOT / "demo_repo"
MAX_STEPS = int(os.getenv("MAX_STEPS", "20"))


# --------------------------------------------------------------------------- LLM (Nosana)
class OllamaNative:
    """OpenAI-SDK-shaped adapter over Ollama's native /api/chat on our Nosana GPU.
    Why: Ollama's OpenAI endpoint silently truncates prompts to its default context (~2K tokens);
    the native API lets us set num_ctx per request."""

    def __init__(self, base: str, num_ctx: int = 24576):
        from types import SimpleNamespace as NS
        self.base, self.num_ctx, self.NS = base, num_ctx, NS
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, model, messages, temperature=0.1, max_tokens=4000, tools=None, tool_choice=None,
                response_format=None, **_):
        NS = self.NS
        msgs = []
        for m in messages:
            m = dict(m)
            if m.get("tool_calls"):
                m["tool_calls"] = [{"function": {"name": t["function"]["name"],
                                                 "arguments": json.loads(t["function"]["arguments"] or "{}")}}
                                   for t in m["tool_calls"]]
            m.pop("tool_call_id", None)
            msgs.append(m)
        body = {"model": model, "messages": msgs, "stream": False, "think": False,
                "options": {"num_ctx": self.num_ctx, "temperature": temperature, "num_predict": max_tokens}}
        if tools:
            body["tools"] = tools
        if response_format:
            body["format"] = "json"
        r = httpx.post(f"{self.base}/api/chat", json=body, timeout=300)
        if r.status_code >= 500:
            raise RuntimeError(f"{r.status_code} unavailable: {r.text[:120]}")
        r.raise_for_status()
        d = r.json()
        msg = d.get("message", {})
        tcs = [NS(id=f"call_{i}_{int(time.time()*1000)}", type="function",
                  function=NS(name=t["function"]["name"], arguments=json.dumps(t["function"].get("arguments", {}))))
               for i, t in enumerate(msg.get("tool_calls") or [])]
        return NS(choices=[NS(message=NS(content=msg.get("content", ""), tool_calls=tcs or None))],
                  usage=NS(prompt_tokens=d.get("prompt_eval_count", 0), completion_tokens=d.get("eval_count", 0)))


def make_llm() -> tuple[OpenAI, str, str, dict]:
    """Nosana exposes an OpenAI-compatible API, so the standard OpenAI SDK just works."""
    key = os.getenv("NOSANA_API_KEY", "").strip()
    dep = os.getenv("NOSANA_DEPLOYMENT_URL", "").strip().rstrip("/")
    if key:
        # Route 1: Nosana's shared, per-token inference gateway (if a GPU node is serving the model right now)
        client = OpenAI(base_url="https://inference.nosana.com/v1", api_key=key, timeout=180)
        try:
            models = {m.id: m.model_dump() for m in client.models.list().data}
        except Exception:
            models = {}
        model = os.getenv("NOSANA_MODEL", "").strip()
        if model in models and models[model].get("available", True):
            return client, model, "Nosana gateway", models[model]
        # Route 2: our own dedicated Nosana GPU deployment (Ollama, OpenAI-compatible, billed per hour)
        if dep:
            dclient = OllamaNative(dep)
            dmodel = os.getenv("NOSANA_DEPLOYMENT_MODEL", "qwen3.5:9b")
            return dclient, dmodel, f"Nosana GPU ({os.getenv('NOSANA_DEPLOYMENT_GPU', 'RTX 3080')})", {
                "name": f"{dmodel} on dedicated Nosana GPU", "context_length": dclient.num_ctx, "pricing": {},
                "hourly_usd": float(os.getenv("NOSANA_DEPLOYMENT_PRICE", "0.10"))}
        avail = [i for i, m in models.items() if m.get("available") and "embed" not in i]
        if avail:
            return client, avail[0], "Nosana gateway", models[avail[0]]
        raise RuntimeError("No Nosana model is serving right now and no NOSANA_DEPLOYMENT_URL is set")
    client = OpenAI(base_url=os.getenv("FALLBACK_BASE_URL") or None, api_key=os.getenv("FALLBACK_API_KEY"))
    return client, os.getenv("FALLBACK_MODEL", "gpt-4o-mini"), "Fallback", {}


# --------------------------------------------------------------------------- Scanner (OSV)
def _ver(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", v)[:4])


def osv_scan(packages: dict[str, str], ecosystem: str = "PyPI") -> list[dict]:
    """Ask the OSV.dev vulnerability database about every installed package."""
    findings = []
    with httpx.Client(timeout=30) as c:
        def q(item):
            name, ver = item
            r = c.post("https://api.osv.dev/v1/query",
                       json={"package": {"name": name, "ecosystem": ecosystem}, "version": ver})
            return name, ver, r.json().get("vulns", [])
        with ThreadPoolExecutor(8) as ex:
            results = list(ex.map(q, packages.items()))
    for name, ver, vulns in results:
        if not vulns:
            continue
        seen, advisories, fixed = set(), [], []
        for v in vulns:
            ids = {v["id"], *v.get("aliases", [])}
            if ids & seen:
                continue
            seen |= ids
            cve = next((a for a in sorted(ids) if a.startswith("CVE-")), v["id"])
            advisories.append({"id": cve, "summary": (v.get("summary") or v.get("details", ""))[:140]})
            for aff in v.get("affected", []):
                for rng in aff.get("ranges", []):
                    for ev in rng.get("events", []):
                        if "fixed" in ev:
                            fixed.append(ev["fixed"])
        safe = max(fixed, key=_ver) if fixed else None
        findings.append({"package": name, "version": ver, "count": len(advisories),
                         "advisories": advisories, "fixed_in": safe})
    return sorted(findings, key=lambda f: -f["count"])


# --------------------------------------------------------------------------- The agent
SYSTEM = """You are PatchPilot, an autonomous security engineer working inside an isolated Linux sandbox.
The repository is at {repo}. A Python venv is at {repo}/.venv (use .venv/bin/pip and .venv/bin/python).

GOAL: upgrade every vulnerable dependency to a safe version, keep the test suite passing, change as little code as possible.

Vulnerable packages and the minimum safe version (from the OSV database):
{vulns}

Research notes from the web (Tavily):
{research}

You cannot talk to a human. You act ONLY by calling exactly one tool per turn
(run, read_file, write_file, web_search, finish). Always fill the "thought" argument with one short sentence of reasoning.

Recommended plan: 1) write_file requirements.txt with safe versions (use >= the safe version, a current stable release is fine; remove pins that block it)
2) run ".venv/bin/pip install -q -r requirements.txt" 3) run ".venv/bin/python -m pytest -q"
4) if tests fail, read the failing file, web_search the error, fix the code, re-run tests 5) finish only when tests pass."""


def _tool(name, desc, **props):
    """OpenAI function-calling schema. Every tool also requires a 'thought' so we can show the reasoning."""
    props = {"thought": {"type": "string", "description": "One sentence: why this action now"}, **props}
    return {"type": "function", "function": {"name": name, "description": desc, "parameters": {
        "type": "object", "properties": props, "required": list(props)}}}


TOOLS = [
    _tool("run", "Run a shell command inside the sandbox, in the repo directory. Returns exit code + output.",
          cmd={"type": "string"}),
    _tool("read_file", "Read a file from the repo.", path={"type": "string", "description": "path relative to repo"}),
    _tool("write_file", "Overwrite a file in the repo with full new content.",
          path={"type": "string"}, content={"type": "string"}),
    _tool("web_search", "Search the live web (Tavily) for docs, changelogs, error messages.", query={"type": "string"}),
    _tool("finish", "Call ONLY when tests pass after the upgrade.",
          summary={"type": "string", "description": "Markdown bullet list of what changed and why"}),
]


class PatchPilot:
    def __init__(self, emit: Emit, repo_url: str | None = None, keep_sandbox: bool = False):
        self.emit, self.repo_url, self.keep = emit, (repo_url or "").strip() or None, keep_sandbox
        self.sandbox = None
        self.repo = ""
        self.sources: list[dict] = []
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0, "cost_usd": 0.0}
        self.tav_calls = 0
        self.lock = threading.Lock()

    # ---- metered access to the partners --------------------------------------
    def chat(self, messages, max_tokens=4000, json_mode=False, tools=None, label="", raw=False):
        """Every LLM call goes through here so we can meter tokens & cost (Nosana bills per token)."""
        kw = {"model": self.model, "messages": messages, "temperature": 0.1, "max_tokens": max_tokens}
        if tools:
            kw.update(tools=tools, tool_choice="auto")
        if json_mode:
            kw["response_format"] = {"type": "json_object"}
            if isinstance(self.llm, OpenAI):  # reasoning model: skip the long hidden "thinking" for structured output
                kw["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}
        for attempt in range(8):  # decentralized GPUs: a node can drop; back off and retry
            try:
                r = self.llm.chat.completions.create(**kw)
                break
            except Exception as ex:
                if attempt == 7 or not any(s in str(ex) for s in ("503", "502", "504", "unavailable")):
                    raise
                wait = min(4 * (attempt + 1), 15)
                self.emit({"type": "log", "message": f"Nosana node busy/rotating ({str(ex)[:60]}…). Retrying in {wait}s"})
                time.sleep(wait)
        p = self.model_info.get("pricing") or {}
        with self.lock:
            u = r.usage
            if u:
                self.usage["prompt_tokens"] += u.prompt_tokens or 0
                self.usage["completion_tokens"] += u.completion_tokens or 0
                self.usage["cost_usd"] += (u.prompt_tokens or 0) * float(p.get("prompt", 0)) + \
                    (u.completion_tokens or 0) * float(p.get("completion", 0))
            if self.model_info.get("hourly_usd"):  # dedicated GPU: billed by time, not tokens
                self.usage["cost_usd"] = (time.time() - self.t0) / 3600 * self.model_info["hourly_usd"]
                self.usage["billing"] = f"${self.model_info['hourly_usd']}/h GPU time"
            self.usage["calls"] += 1
            self.emit({"type": "usage", "provider": self.provider, "model": self.model, **self.usage})
        if raw:
            return r
        return re.sub(r"<think>.*?</think>", "", r.choices[0].message.content or "", flags=re.S).strip()

    def tavily(self, method: str, **kw) -> dict:
        with self.lock:
            self.tav_calls += 1
            self.emit({"type": "tavily", "calls": self.tav_calls})
        return getattr(self.tav, method)(**kw)

    # ---- helpers ---------------------------------------------------------
    def stage(self, key: str, status: str, detail: str = ""):
        self.emit({"type": "stage", "key": key, "status": status, "detail": detail})

    def sh(self, cmd: str, timeout: int = 240, show: bool = True) -> tuple[int, str]:
        """Run a shell command INSIDE the sandbox (never on our machine)."""
        if show:
            self.emit({"type": "cmd", "cmd": cmd})
        r = self.sandbox.process.exec(cmd, cwd=self.repo, timeout=timeout)
        out = (r.result or "").strip()
        if show:
            self.emit({"type": "cmd_out", "exit": r.exit_code, "out": out[-4000:]})
        return r.exit_code, out

    def freeze(self) -> dict[str, str]:
        _, out = self.sh(".venv/bin/pip freeze --all", show=False)
        pk = {}
        for line in out.splitlines():
            if "==" in line:
                n, v = line.split("==", 1)
                if n.lower() not in {"pip", "setuptools", "wheel"}:
                    pk[n.lower()] = v.strip()
        return pk

    def snapshot(self, budget: int = 9000, exts: str = "py|txt|toml|cfg|ini") -> str:
        """Give the model the small source files up front, so it doesn't waste steps exploring."""
        _, out = self.sh(f"git ls-files | grep -E '\\.({exts})$' | head -40", show=False)
        parts, used = [], 0
        for path in out.split():
            try:
                body = self.sandbox.fs.download_file(f"{self.repo}/{path}").decode(errors="replace")
            except Exception:
                continue
            if used + len(body) > budget:
                parts.append(f"--- {path} (not shown, read_file if needed)")
                continue
            used += len(body)
            parts.append(f"--- {path}\n{body}")
        return "\n".join(parts)

    def tests(self) -> dict:
        code, out = self.sh(".venv/bin/python -m pytest -q 2>&1 | tail -25")
        m = re.search(r"(\d+) passed", out)
        f = re.search(r"(\d+) failed", out)
        e = re.search(r"(\d+) error", out)
        return {"ok": bool(m) and not f and not e, "passed": int(m.group(1)) if m else 0,
                "failed": (int(f.group(1)) if f else 0) + (int(e.group(1)) if e else 0), "tail": out[-1500:]}

    # ---- pipeline --------------------------------------------------------
    def run(self):
        t0 = self.t0 = time.time()
        try:
            self._run()
        except Exception as ex:  # surface every failure in the UI
            self.emit({"type": "error", "message": f"{type(ex).__name__}: {ex}", "trace": traceback.format_exc()[-2000:]})
        finally:
            if self.sandbox is not None and not self.keep:
                try:
                    self.sandbox.delete()
                    self.emit({"type": "log", "message": "Sandbox deleted. Nothing touched your machine."})
                except Exception:
                    pass
            self.emit({"type": "done", "seconds": round(time.time() - t0, 1)})

    def _run(self):
        self.llm, self.model, self.provider, self.model_info = make_llm()
        self.tav = TavilyClient(api_key=os.environ["TAVILY_API_KEY"])
        self.emit({"type": "meta", "model": self.model, "provider": self.provider})

        # ① SANDBOX (Daytona) ----------------------------------------------------
        self.stage("sandbox", "running", "Creating an isolated Daytona sandbox…")
        t = time.time()
        daytona = Daytona(DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"]))
        self.sandbox = daytona.create(CreateSandboxFromSnapshotParams(
            language="python", labels={"app": "patchpilot"}, auto_stop_interval=15))
        boot = time.time() - t
        sb = self.sandbox
        self.emit({"type": "compute", "sandbox": {
            "id": sb.id, "cpu": getattr(sb, "cpu", None), "memory_gb": getattr(sb, "memory", None),
            "disk_gb": getattr(sb, "disk", None), "gpu": getattr(sb, "gpu", None) or 0,
            "target": getattr(sb, "target", None), "boot_s": round(boot, 2)}})
        self.repo = f"{sb.get_work_dir().rstrip('/')}/repo"
        if self.repo_url:
            self.emit({"type": "cmd", "cmd": f"git clone --depth 1 {self.repo_url}"})
            self.sandbox.git.clone(self.repo_url, self.repo, depth=1)
        else:
            files = [FileUpload(source=p.read_bytes(), destination=f"{self.repo}/{p.relative_to(DEMO_REPO)}")
                     for p in DEMO_REPO.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
            self.sandbox.fs.create_folder(self.repo, "755")
            self.sandbox.fs.upload_files(files)
            self.emit({"type": "log", "message": f"Uploaded demo repo invoice-mailer ({len(files)} files)"})
        self.sh("git init -q 2>/dev/null; git config user.email pp@local; git config user.name PatchPilot; "
                "git add -A >/dev/null && git commit -qm baseline --allow-empty; git ls-files | wc -l | xargs echo files:")
        self.stage("sandbox", "done", f"Sandbox {sb.id[:8]} ready in {boot:.1f}s · repo loaded")

        # ② RECON (Tavily → DeepWiki) -------------------------------------------
        self.stage("recon", "running", "Reading DeepWiki docs via Tavily…")
        recon_txt = recon(self, self.tav)
        self.stage("recon", "done", "Architecture & attack surface mapped")

        # ③ HUNT: inventory + OSV, then Threat-Intel ‖ Code-Review sub-agents -----
        _, ls = self.sh("ls -1A", show=False)
        marker, eco, label, patchable = detect(set(ls.split()))
        if label == "unknown":  # no manifest: infer the stack from the source files themselves
            _, ext = self.sh("git ls-files | sed -n 's/.*\\.\\([a-z]*\\)$/\\1/p' | sort | uniq -c | sort -rn | head -5", show=False)
            langs = {"php": ("Packagist", "PHP"), "py": ("PyPI", "Python"), "go": ("Go", "Go"), "js": ("npm", "Node.js"), "ts": ("npm", "Node.js")}
            for tok in ext.split()[1::2]:
                if tok in langs:
                    eco, label = langs[tok]
                    break
        self.stage("hunt", "running", f"Stack: {label}. Inventorying dependencies…")
        before_tests = None
        if patchable:
            self.sh("python3 -m venv .venv && .venv/bin/pip install -q --upgrade pip && "
                    ".venv/bin/pip install -q -r requirements.txt pytest 2>&1 | tail -5", timeout=400)
            before_tests = self.tests()
            pkgs = self.freeze()
        else:
            try:
                pkgs = inventory(self, marker) if marker else {}
            except Exception as ex:
                pkgs = {}
                self.emit({"type": "log", "message": f"Could not parse {marker}: {ex}"})
        before = osv_scan(pkgs, eco or "PyPI") if pkgs else []
        total_before = sum(f["count"] for f in before)
        self.emit({"type": "scan", "phase": "before", "ecosystem": label, "findings": before, "total": total_before,
                   "tests": before_tests, "packages": len(pkgs)})
        self.stage("hunt", "running", f"{len(pkgs)} deps · {total_before} advisories → sub-agents hunting in parallel")
        with ThreadPoolExecutor(3) as ex:
            f_intel = ex.submit(threat_intel, self, before)
            f_review = ex.submit(code_review, self, label)
            f_notes = ex.submit(self.research, before) if (patchable and before) else None
            intel, review = f_intel.result(), f_review.result()
            notes = f_notes.result() if f_notes else ""
        self.stage("hunt", "done", f"{total_before} dependency advisories · {len(review['findings'])} code findings")

        # ④ FIX (Nosana agent loop) — only where we can prove the fix ------------
        result = None
        if not (patchable and before):
            why = "no vulnerable dependencies" if patchable else f"{label}: report-only (auto-fix ships for Python first)"
            self.stage("fix", "skipped", why)
            self.stage("prove", "running", "Compiling the evidence report…")
            rep = build_report(self, label, before, intel, review)
            self.emit({"type": "result", "verified": False, "mode": "report-only", "before": total_before, "after": total_before,
                       "summary": "", "sources": self.sources[:12], "usage": self.usage, "tavily_calls": self.tav_calls,
                       "pr": self.pr_text(before, before, {"passed": 0, "failed": 0}, "Report only.", intel, review)})
            self.stage("prove", "done", rep["verdict"][:90])
            return
        self.stage("fix", "running", f"Fixer agent on {self.provider} · {self.model}")
        vuln_txt = "\n".join(f"- {f['package']}=={f['version']} -> needs >= {f['fixed_in']} ({f['count']} advisories)" for f in before)
        intel_txt = intel["summary"] + "\n" + "\n".join(
            f"- {i['cve']} ({i['package']}): EPSS {i['epss']*100:.1f}%{' KEV-EXPLOITED' if i['kev'] else ''}" for i in intel["items"][:6])
        messages = [{"role": "system", "content": SYSTEM.format(repo=self.repo, vulns=vuln_txt,
                     research=notes + "\n\nThreat intel (prioritise these):\n" + intel_txt + "\n\nRepo recon:\n" + recon_txt[:1500])},
                    {"role": "user", "content": "Start. Baseline tests pass on the old versions. Repository snapshot:\n" + self.snapshot()}]
        summary, step = "", 0
        for step in range(1, MAX_STEPS + 1):
            act, assistant_msg = self.think(messages)                    # THINK
            messages.append(assistant_msg)
            self.emit({"type": "thought", "step": step, "thought": act["args"].pop("thought", ""),
                       "action": act["action"], "args": act["args"]})
            obs = self.act(act)                                           # ACT
            if act["action"] == "finish":
                summary = act["args"].get("summary", "")
                break
            self.emit({"type": "observation", "step": step, "text": obs[-1800:]})
            if act.get("id"):                                             # OBSERVE
                messages.append({"role": "tool", "tool_call_id": act["id"], "content": obs[-3500:]})
            else:
                messages.append({"role": "user", "content": f"OBSERVATION:\n{obs[-3500:]}"})
        self.stage("fix", "done", f"Fixer finished in {step} steps")
        if not summary:
            _, d = self.sh("git --no-pager diff", show=False)
            summary = self.chat([{"role": "user", "content": "Summarise this security patch as 3-5 markdown bullets:\n" + d[:6000]}],
                                max_tokens=1500, label="summary")

        # ⑤ PROVE (Daytona re-test + re-scan) -----------------------------------
        self.stage("prove", "running", "Re-installing, re-scanning & re-testing independently…")
        self.sh(".venv/bin/pip install -q -r requirements.txt 2>&1 | tail -3")
        after_tests = self.tests()
        after = osv_scan(self.freeze(), "PyPI")
        total_after = sum(f["count"] for f in after)
        _, diff = self.sh("git --no-pager diff --stat; echo ---; git --no-pager diff", show=False)
        self.emit({"type": "scan", "phase": "after", "ecosystem": label, "findings": after, "total": total_after, "tests": after_tests})
        verified = after_tests["ok"] and total_after < total_before
        result = {"verified": verified, "mode": "patched", "before": total_before, "after": total_after,
                  "tests_before": before_tests, "tests_after": after_tests, "diff": diff[:12000],
                  "summary": summary, "sources": self.sources[:12], "model": self.model, "provider": self.provider,
                  "review_count": len(review.get("findings", [])), "kev_count": intel.get("kev_count", 0),
                  "usage": self.usage, "tavily_calls": self.tav_calls,
                  "pr": self.pr_text(before, after, after_tests, summary, intel, review)}
        self.emit({"type": "result", **result})
        build_report(self, label, before, intel, review, result)
        self.stage("prove", "done" if verified else "warn",
                   f"{total_before} → {total_after} advisories · tests {after_tests['passed']} passed, {after_tests['failed']} failed")

    def research(self, before) -> str:
        notes = []
        for f in before[:4]:
            q = f"{f['package']} upgrade from {f['version']} to {f['fixed_in']} breaking changes migration"
            res = self.tavily("search", query=q, max_results=3, include_answer=True)
            src = [{"title": r["title"], "url": r["url"]} for r in res.get("results", [])]
            with self.lock:
                self.sources += src
            notes.append(f"- {f['package']}: {res.get('answer') or ''}"[:600])
            self.emit({"type": "research", "query": q, "answer": res.get("answer"), "sources": src})
        return "\n".join(notes)

    # ---- brain -------------------------------------------------------------
    def think(self, messages) -> tuple[dict, dict]:
        """One LLM call -> one tool call. This is the entire 'brain' of the agent."""
        nudge = []
        for _ in range(3):
            r = self.chat(messages + nudge, max_tokens=6000, tools=TOOLS, raw=True, label="fixer")
            m = r.choices[0].message
            if m.tool_calls:
                tc = m.tool_calls[0]
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = parse_json(tc.function.arguments) or {}
                msg = {"role": "assistant", "content": m.content or "", "tool_calls": [
                    {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments}}]}
                return {"id": tc.id, "action": tc.function.name, "args": args}, msg
            legacy = parse_json(m.content or "")
            if legacy and legacy.get("action"):
                args = legacy.get("args") or {}
                args["thought"] = legacy.get("thought", "")
                return {"action": legacy["action"], "args": args}, {"role": "assistant", "content": m.content}
            nudge = [{"role": "assistant", "content": m.content or ""},
                     {"role": "user", "content": "You must act by calling one of the tools now."}]
        return {"action": "finish", "args": {"summary": "Agent could not decide on an action."}}, {"role": "assistant", "content": "giving up"}

    # ---- hands -------------------------------------------------------------
    def act(self, act: dict) -> str:
        a, args = act.get("action"), act.get("args") or {}
        try:
            if a == "run":
                code, out = self.sh(args["cmd"])
                return f"exit_code={code}\n{out}"
            if a == "read_file":
                return self.sandbox.fs.download_file(f"{self.repo}/{args['path'].lstrip('/')}").decode()[:6000]
            if a == "write_file":
                self.sandbox.fs.upload_file(args["content"].encode(), f"{self.repo}/{args['path'].lstrip('/')}")
                self.emit({"type": "file", "path": args["path"], "content": args["content"][:3000]})
                return f"Wrote {args['path']} ({len(args['content'])} chars)"
            if a == "web_search":
                res = self.tavily("search", query=args["query"], max_results=3, include_answer=True)
                src = [{"title": r["title"], "url": r["url"]} for r in res.get("results", [])]
                self.sources += src
                self.emit({"type": "research", "query": args["query"], "answer": res.get("answer"), "sources": src})
                return (res.get("answer") or "") + "\n" + "\n".join(f"* {r['title']}: {r['content'][:300]}" for r in res.get("results", []))
            if a == "finish":
                return "done"
            return f"Unknown tool {a}. Use run/read_file/write_file/web_search/finish."
        except Exception as ex:
            return f"Tool error: {type(ex).__name__}: {ex}"

    def pr_text(self, before, after, tests, summary, intel=None, review=None) -> str:
        rows = "\n".join(f"| {f['package']} | {f['version']} | {f['count']} |" for f in before)
        txt = (f"## 🛡️ PatchPilot: dependency security fixes\n\n"
               f"**Verified in an isolated Daytona sandbox:** {sum(f['count'] for f in before)} → "
               f"{sum(f['count'] for f in after)} known advisories · tests: {tests['passed']} passed, {tests['failed']} failed\n\n"
               f"| Package | Was | Advisories |\n|---|---|---|\n{rows}\n\n### What changed\n{summary}\n")
        if intel and intel.get("items"):
            txt += "\n### Threat intel\n" + intel["summary"] + "\n" + "\n".join(
                f"- {i['cve']} ({i['package']}): EPSS {i['epss']*100:.1f}%" + (" · **CISA KEV: exploited in the wild**" if i["kev"] else "")
                for i in intel["items"][:5]) + "\n"
        if review and review.get("findings"):
            txt += "\n### Code review (not auto-fixed, needs human decision)\n" + "\n".join(
                f"- **{f.get('severity')}** `{f.get('file')}:{f.get('line')}` {f.get('title')}" for f in review["findings"][:8]) + "\n"
        return txt


def parse_json(txt: str) -> dict | None:
    txt = re.sub(r"<think>.*?</think>", "", txt, flags=re.S).strip()
    txt = re.sub(r"^```(?:json)?|```$", "", txt.strip(), flags=re.M).strip()
    start = txt.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(txt)):
            ch = txt[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(txt[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = txt.find("{", start + 1)
    return None
