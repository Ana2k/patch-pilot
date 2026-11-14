# Submission (paste into https://tinyurl.com/20261114submission)

**Project:** PatchPilot, an AI security engineer that proves its fixes

**One-liner:** Paste a GitHub repo. PatchPilot opens it in a Daytona sandbox, reads its DeepWiki docs via Tavily, hunts vulnerabilities
with two parallel sub-agents, auto-patches what it safely can with an open model on Nosana GPUs, and proves the fix by re-running
the tests. The output is a plain-English report: 🔴 Critical / 🟠 Needs a patch / 🔵 Monitor.

**Problem:** Known CVEs in dependencies and classic injection bugs (PHP, Node, Go, Python) cause most breaches. Teams don't know what is
*actually* exploitable, upgrades break code, and AI review tools comment without executing anything.

**What's innovative**
- **Proof, not opinions:** fixes are verified by re-install, re-scan and re-test inside the sandbox (demo: 20 → 0 advisories, tests 3/3).
- **Predictive triage:** every CVE is ranked by FIRST EPSS (probability of exploitation in the next 30 days) and CISA KEV (exploited in the wild),
  plus live security news via Tavily, so it catches what will hurt *before* it's headline news.
- **Understands before it acts:** a recon sub-agent reads the repo's DeepWiki page via Tavily extract.
- **Non-techie report:** each issue says what an attacker could do in everyday words, plus the exact fix; download as .md or PDF.

**Real runs (case studies on the site):** demo Python app (auto-patched, 20 → 0) · Agent-Field/CodeAF (Go, 110 modules, 22 advisories) ·
digininja/DVWA (PHP: command injection, SQLi, file inclusion, weak hashing) · OWASP/NodeGoat (804 npm packages, 177 advisories, `eval` RCE).

**Partner tech (code-level)**
- **Daytona:** `create`, `process.exec`, `git.clone`, `fs.upload_files/download_file`, `delete`. One throwaway sandbox per scan (~1 s boot), 4 in parallel.
- **Nosana:** OpenAI-compatible inference gateway (Qwen 3.8 27B, tool calling) **plus** our own GPU deployment (Qwen 3.5 9B on an RTX 3080,
  $0.10/h) with automatic failover; live credit balance from api.nosana.com. A full scan costs about $0.003–0.013.
- **Tavily:** `extract` (DeepWiki recon), `search` with `include_answer` (fix research), `topic="news"` + forum domains (threat intel).

Repo: <add GitHub link> · Demo: `uvicorn server:app` then open localhost:8000
