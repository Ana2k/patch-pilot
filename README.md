<div align="center">

# 🛡️ PatchPilot
**The AI security engineer that proves its fixes.**

Paste a GitHub repo → find what's exploitable → fix it → prove the fix → plain-English report.

![Daytona](https://img.shields.io/badge/sandbox-Daytona-0b1f3a) ![Nosana](https://img.shields.io/badge/LLM-Nosana-00a3a1) ![Tavily](https://img.shields.io/badge/search-Tavily-4f46e5) ![Python](https://img.shields.io/badge/python-3.12-blue)

Built at **Tokyo AgentForge 2026** with **Daytona · Nosana · Tavily**

**[📑 Pitch deck (PDF)](docs/PatchPilot-deck.pdf)** · **[📊 Results](#-results-on-real-repos)** · **[🚀 Run it](#-run-it)**

<img src="docs/app-landing.png" width="85%" alt="PatchPilot landing page"/>

</div>

## 💡 The problem
Most breaches start with a **known** bug. Teams don't patch because they can't tell what's actually exploitable, and upgrades break code. AI review bots *comment*; **PatchPilot executes** every fix and proves it.

## 📊 Results on real repos
| Repository | Stack | Verdict | Key finding | Time |
|:--|:--:|:--:|:--|:--:|
| [Agent-Field/CodeAF](https://github.com/Agent-Field/CodeAF) | Go | 🟠 | 22 known vulns across 110 modules (`x/net`, `x/crypto`, `x/image`) | 81 s |
| [digininja/DVWA](https://github.com/digininja/DVWA) | PHP | 🔴 | 9 critical: command injection, SQL injection, file inclusion, all with fixes | 61 s |
| [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | Node | 🔴 | `eval()` remote code execution + 177 known vulns | 91 s |
| [microsoft/generative-ai-for-beginners](https://github.com/microsoft/generative-ai-for-beginners) | Python | 🟢 | Clean: 66 deps, no known vulns | 106 s |
| `demo_repo` | Python | ✅ | **Auto-patched 20 → 0**, fixed the Jinja2 break, tests 3/3 | ~110 s |

<p align="center">Cost per scan: <b>$0.002–0.013</b> · Full reports in <a href="cases/"><code>cases/</code></a></p>

| 🔴 DVWA (PHP) | 🟠 CodeAF (Go) |
|:--:|:--:|
| <img src="docs/app-report.png" width="100%"/> | <img src="docs/report-CodeAF.png" width="100%"/> |
| 🔴 **NodeGoat (Node)** | 🟢 **Microsoft repo** |
| <img src="docs/report-NodeGoat.png" width="100%"/> | <img src="docs/report-generative-ai-for-beginners.png" width="100%"/> |

## ⚙️ How it works
| Step | What happens | Powered by |
|:--:|:--|:--|
| ① Sandbox | Disposable VM (boots ~1 s); untrusted code never touches your laptop | **Daytona** |
| ② Recon | Reads the repo's architecture and attack surface first | **Tavily** → DeepWiki |
| ③ Hunt | Two parallel sub-agents: Threat Intel (OSV · EPSS · CISA KEV · news) + Code Review | OSV · FIRST · CISA · **Tavily** |
| ④ Fix | Agent loop: think → run a tool in the sandbox → observe → repeat | **Nosana** (Qwen) |
| ⑤ Prove | Re-install, re-scan, re-test → diff, PR text, report | **Daytona** |

## 🤝 Partner tech (code-level)
- **Daytona:** `create` · `process.exec` · `git.clone` · `fs` · `delete`; 4 repos scanned in 4 sandboxes at once.
- **Nosana:** OpenAI-compatible gateway (Qwen 3.8 27B, tool calling) **+** our own RTX 3080 GPU (Qwen 3.5 9B, $0.10/h) with auto-failover and live credit tracking.
- **Tavily:** `extract` (DeepWiki recon) · `search` with answers (fix research) · news/forum search (threat intel).

| Daytona sandboxes | Nosana GPU | Tavily usage |
|:--:|:--:|:--:|
| <img src="docs/daytona-sandboxes.jpg" width="100%"/> | <img src="docs/nosana-gpu-deployment.jpg" width="100%"/> | <img src="docs/tavily-usage.jpg" width="100%"/> |

## 🛡️ Why trust it
- **Isolated:** every command the AI chooses runs in a throwaway Daytona VM that is deleted after each scan.
- **Verified:** the Prove step ignores the agent's claims and re-scans and re-tests independently.
- **Transparent:** you watch every thought, tool call and sandbox command live; reports cite their sources.

## 🧭 Limitations & roadmap
- Auto-fix ships for Python today; PHP/Node/Go are report-only (with fixes suggested).
- Next: **AgentField CodeAF** as the in-sandbox fixer (`codeaf do`, pointed at Nosana), a GitHub App that opens verified PRs, and a CI gate.

## 🚀 Run it live
```bash
git clone https://github.com/Ana2k/patch-pilot && cd patch-pilot
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env        # DAYTONA_API_KEY, NOSANA_API_KEY, TAVILY_API_KEY
.venv/bin/uvicorn server:app --port 8000
```
Open `http://localhost:8000`, paste any public repo (or leave it empty for the demo) and click **Run security test**. You'll watch the 5 stages light up, the agent's thoughts, and the sandbox terminal live; the report lands in ~1–2 min.
Saved reports open instantly: `/#case=CodeAF` · `/#case=DVWA` · `/#case=NodeGoat`.

<sub>`agent.py` orchestrator + fixer · `security.py` sub-agents + report · `scanners.py` PHP/Go/JS/Python checks · `server.py` API · `static/` site · `demo_repo/` fake secrets only. Scanned code runs only inside Daytona.</sub>
