# PatchPilot: Tokyo AgentForge 2026 submission

| Field | Answer |
|:--|:--|
| **Project** | PatchPilot: the AI security engineer that proves its fixes |
| **Repo** | https://github.com/Ana2k/patch-pilot |
| **Deck** | [`docs/PatchPilot-deck.pdf`](docs/PatchPilot-deck.pdf) (9 slides) |
| **Partners** | Daytona · Nosana · Tavily (+ DeepWiki, OSV.dev, FIRST EPSS, CISA KEV) |

**What it does:** PatchPilot scans any GitHub repo inside an isolated Daytona sandbox. Its agents read the docs via Tavily, rank vulnerabilities by real-world exploit risk and review the code for injection bugs, then a Nosana-powered agent patches what it can. It proves each fix by re-running the tests and delivers a plain-English Critical / Patch / Monitor report.

## The agents
| Agent | Job |
|:--|:--|
| **Recon** | Reads the repo's DeepWiki docs (Tavily extract) to map what the app does and where attackers get in |
| **Threat Intel** | Checks every library against OSV; ranks by EPSS exploit odds and CISA's known-exploited list; reads security news |
| **Code Reviewer** | Hunts injection, `eval`, unsafe deserialisation and hard-coded secrets (PHP/Go/JS/Python); explains each in plain words with a fix |
| **Fixer** | Upgrades vulnerable libraries in the sandbox; reads errors, searches, edits code until tests pass (Nosana Qwen) |
| **Prove** *(check step)* | Ignores the Fixer's claim, re-scans and re-tests itself, then writes the report |

## Results
| Repo | Verdict | Finding | Time |
|:--|:--:|:--|:--:|
| Agent-Field/CodeAF (Go) | 🟠 | 22 known vulns across 110 modules | 81 s |
| digininja/DVWA (PHP) | 🔴 | 9 critical: command injection, SQLi, file inclusion | 61 s |
| OWASP/NodeGoat (Node) | 🔴 | `eval()` RCE + 177 known vulns | 91 s |
| microsoft/generative-ai-for-beginners | 🟢 | Clean | 106 s |
| demo_repo (Python) | ✅ | Auto-patched 20 → 0, tests 3/3 | ~110 s |

**Next:** CodeAF (AgentField) as the in-sandbox fixer · a GitHub App that opens verified PRs · auto-fix for PHP/Node/Go · a CI gate.
