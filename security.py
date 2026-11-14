"""
PatchPilot security sub-agents. Each one is a specialist with its own tools and its own output.
The orchestrator (agent.py) runs Threat-Intel and Code-Review IN PARALLEL, then hands both reports to the Fixer.

  Recon        - understand the repo before touching it (DeepWiki page, fetched with Tavily extract; README fallback)
  Threat-Intel - "sniff" which known vulns are about to hurt you:
                   FIRST EPSS  = probability a CVE is exploited in the next 30 days
                   CISA KEV    = CVEs confirmed exploited in the wild
                   Tavily news = what security forums / news are saying right now
  Code-Review  - bandit SAST runs INSIDE the sandbox, then the Nosana LLM triages it and hunts for logic
                 flaws bandit can't see (injection, SSTI, secrets, unsafe deserialisation, SSRF...).
"""
from __future__ import annotations

import json
import re

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FORUMS = ["github.com", "reddit.com", "news.ycombinator.com", "seclists.org", "thehackernews.com",
          "bleepingcomputer.com", "securityweek.com", "snyk.io", "nvd.nist.gov", "cisa.gov"]
_kev_cache: dict | None = None


def _kev() -> dict:
    global _kev_cache
    if _kev_cache is None:
        try:
            data = httpx.get(KEV_URL, timeout=30).json()
            _kev_cache = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        except Exception:
            _kev_cache = {}
    return _kev_cache


def recon(pp, tav) -> str:
    """Recon sub-agent: read DeepWiki's generated docs for a GitHub repo (via Tavily extract)."""
    pp.emit({"type": "subagent", "name": "Recon", "status": "start", "detail": "Reading DeepWiki + README"})
    src, url, text = "readme", "", ""
    m = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)", pp.repo_url or "")
    if m:
        url = f"https://deepwiki.com/{m.group(1)}/{m.group(2).removesuffix('.git')}"
        try:
            res = pp.tavily("extract", urls=[url]).get("results", [])
            if res and len(res[0].get("raw_content", "")) > 300:
                src, text = "deepwiki", res[0]["raw_content"]
        except Exception:
            pass
    if not text:
        _, text = pp.sh("cat README* 2>/dev/null | head -80", show=False)
    summary = pp.chat(messages=[{"role": "user", "content":
        "You are a security architect. From this project documentation, write 4 short markdown bullets: what the "
        "project does, its tech stack, where untrusted input enters (attack surface), and the riskiest component.\n\n"
        + text[:7000]}], max_tokens=1200, label="recon")
    pp.emit({"type": "recon", "source": src, "url": url, "summary": summary})
    pp.emit({"type": "subagent", "name": "Recon", "status": "done", "detail": f"source: {src}"})
    return summary


def threat_intel(pp, findings: list[dict]) -> dict:
    """Threat-Intel sub-agent: rank CVEs by real-world exploit likelihood and scan the security chatter."""
    pp.emit({"type": "subagent", "name": "Threat Intel", "status": "start", "detail": "EPSS · CISA KEV · security news"})
    pp.stage("hunt", "running", "Threat Intel: EPSS exploit odds · CISA KEV · security news")
    cves = {}
    for f in findings:
        for a in f["advisories"]:
            if a["id"].startswith("CVE-"):
                cves[a["id"]] = f["package"]
    items = []
    if cves:
        try:
            r = httpx.get("https://api.first.org/data/v1/epss", params={"cve": ",".join(list(cves)[:100])}, timeout=20)
            epss = {d["cve"]: d for d in r.json().get("data", [])}
        except Exception:
            epss = {}
        kev = _kev()
        for cve, pkg in cves.items():
            e, k = epss.get(cve, {}), kev.get(cve)
            items.append({"cve": cve, "package": pkg, "epss": float(e.get("epss", 0) or 0),
                          "percentile": float(e.get("percentile", 0) or 0), "kev": bool(k),
                          "kev_date": k.get("dateAdded") if k else None, "kev_name": k.get("vulnerabilityName") if k else None})
    items.sort(key=lambda i: (not i["kev"], -i["epss"]))
    chatter = []
    pkgs = [f["package"] for f in findings[:3]]
    for q, kw in [] if not pkgs else [(f"{' '.join(pkgs)} vulnerability exploit", {"topic": "news", "days": 180}),
                  (f"{' '.join(pkgs)} CVE proof of concept exploit", {"include_domains": FORUMS})]:
        try:
            res = pp.tavily("search", query=q, max_results=4, **kw)
            chatter += [{"title": x["title"], "url": x["url"], "snippet": x.get("content", "")[:220],
                         "date": x.get("published_date")} for x in res.get("results", [])]
        except Exception:
            pass
    kev_n = sum(i["kev"] for i in items)
    top = items[0] if items else None
    summary = (f"{len(items)} CVEs scored. " + (f"{kev_n} are on CISA's Known Exploited list. " if kev_n else "None are on CISA KEV. ")
               + (f"Highest exploit likelihood: {top['cve']} in {top['package']} ({top['epss']*100:.1f}% in 30 days, "
                  f"riskier than {top['percentile']*100:.0f}% of all CVEs)." if top else ""))
    out = {"items": items[:25], "chatter": chatter[:8], "summary": summary, "kev_count": kev_n}
    pp.emit({"type": "intel", **out})
    pp.emit({"type": "subagent", "name": "Threat Intel", "status": "done", "detail": summary[:90]})
    return out




REVIEW_PROMPT = """You are an elite application-security reviewer (CodeRabbit-grade, pentester mindset).
Stack: {label}. Below are raw hits from SAST tools (bandit, pattern hunter) with code context.
For PHP pay special attention to: eval/assert, system/exec/shell_exec/passthru/backticks, include/require of user input (LFI/RFI),
unserialize (object injection), SQL built from $_GET/$_POST, echo of user input (XSS), md5/sha1 passwords, file uploads,
php-cgi argument injection (CVE-2024-4577 class), type juggling (== on hashes).
Keep only real, exploitable issues (max 10), merge duplicates; be concise, and write for a NON-TECHNICAL reader too.
Return ONLY JSON: {{"findings":[{{"severity":"CRITICAL|HIGH|MEDIUM|LOW","file":"path","line":N,"rule":"CWE-xx",
"title":"short","explanation":"technical why, 1 sentence","plain":"what an attacker could do, in everyday words",
"fix":"concrete replacement code"}}],"summary":"one sentence overall risk"}}

HITS:
{hits}"""


def code_review(pp, label: str) -> dict:
    """Code-Review sub-agent: semgrep + bandit + pattern hunter IN the sandbox, then Nosana LLM triage."""
    from scanners import FIXES, bandit, pattern_hunt
    pp.emit({"type": "subagent", "name": "Code Reviewer", "status": "start", "detail": "pattern hunter · bandit → LLM triage"})
    hits = pattern_hunt(pp)
    tools = ["pattern-hunter"]
    if label == "Python":
        hits += bandit(pp)
        tools.append("bandit")
    seen, uniq = set(), []
    for h in hits:
        k = (h["file"], h["line"])
        if k not in seen:
            seen.add(k)
            uniq.append(h)
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    uniq.sort(key=lambda h: rank.get(h["severity"].upper(), 4))
    pp.emit({"type": "log", "message": f"Code Reviewer: {len(uniq)} raw hits from {', '.join(tools)} → triage on Nosana"})
    data = {"findings": [], "summary": "No risky code patterns found."}
    if uniq:
        try:
            txt = pp.chat([{"role": "user", "content": REVIEW_PROMPT.format(label=label, hits=json.dumps(uniq[:25], indent=1)[:8000])}],
                          max_tokens=6000, json_mode=True, label="review")
            data = json.loads(txt[txt.find("{"):txt.rfind("}") + 1])
        except Exception:
            data = {"findings": [{"severity": h["severity"].upper(), "file": h["file"], "line": h["line"], "rule": h["rule"],
                                  "title": h["title"], "explanation": h.get("code", ""), "plain": h.get("plain", "Flagged by " + h["tool"]),
                                  "fix": FIXES.get(h["rule"], "")} for h in uniq[:12]], "summary": "Raw scanner results (LLM triage unavailable)."}
    data["findings"] = sorted(data.get("findings", []), key=lambda f: rank.get(str(f.get("severity")).upper(), 4))
    data["tools"] = tools
    pp.emit({"type": "review", **data})
    pp.emit({"type": "subagent", "name": "Code Reviewer", "status": "done", "detail": f"{len(data['findings'])} findings"})
    return data


def build_report(pp, label, before, intel, review, result=None) -> dict:
    """Turn everything into a plain-English, bucketed report: Critical / Needs a patch / Monitor."""
    items = []
    intel_by_pkg: dict[str, dict] = {}
    for i in intel.get("items", []):
        p = intel_by_pkg.setdefault(i["package"], {"epss": 0, "kev": False, "cve": i["cve"]})
        if i["epss"] > p["epss"]:
            p.update(epss=i["epss"], cve=i["cve"])
        p["kev"] = p["kev"] or i["kev"]
    patched = bool(result and result.get("verified"))
    for f in before:
        t = intel_by_pkg.get(f["package"], {})
        bucket = "critical" if t.get("kev") or t.get("epss", 0) >= 0.10 else "patch"
        if patched:
            bucket = "monitor"
        items.append({"bucket": bucket, "kind": "dependency", "severity": "CRITICAL" if bucket == "critical" else "HIGH",
                      "title": f"{f['package']} {f['version']} has {f['count']} known vulnerabilities",
                      "where": f"{f['package']}@{f['version']}",
                      "plain": ("Already upgraded and re-tested by PatchPilot. " if patched else "") +
                               f"This library has publicly documented security holes. "
                               f"Upgrade to {f['fixed_in'] or 'the latest version'} or newer.",
                      "fix": f"upgrade {f['package']} to >= {f['fixed_in']}", "cve": t.get("cve"),
                      "epss": t.get("epss"), "kev": t.get("kev", False)})
    crit_rx = re.compile(r"CWE-(77|78|89|94|95|98|502)\b|command injection|sql injection|remote code|\bRCE\b|code execution|"
                         r"file inclusion|deserial", re.I)
    for c in review.get("findings", []):
        sev = str(c.get("severity", "LOW")).upper()
        if sev == "HIGH" and crit_rx.search(f"{c.get('rule', '')} {c.get('title', '')}"):
            sev = "CRITICAL"  # attacker-controlled code/command/query execution is always "fix now"
            c["severity"] = sev
        items.append({"bucket": "critical" if sev == "CRITICAL" else "patch" if sev in ("HIGH", "MEDIUM") else "monitor",
                      "kind": "code", "severity": sev, "title": c.get("title", ""), "where": f"{c.get('file')}:{c.get('line')}",
                      "plain": c.get("plain") or c.get("explanation", ""), "fix": c.get("fix", ""), "rule": c.get("rule")})
    order = {"critical": 0, "patch": 1, "monitor": 2}
    items.sort(key=lambda i: order[i["bucket"]])
    counts = {b: sum(i["bucket"] == b for i in items) for b in order}
    if counts["critical"]:
        verdict = f"🔴 Not safe to ship: {counts['critical']} critical issue(s) need fixing now."
    elif counts["patch"]:
        verdict = f"🟠 Ship with caution: {counts['patch']} issue(s) need a patch soon."
    else:
        verdict = "🟢 No urgent issues found" + (" (dependency fixes applied and proven by re-running the tests)." if patched else ".")
    plain = pp.chat([{"role": "user", "content":
        "Explain this security report to a non-technical founder in 3 short sentences (no jargon, no markdown):\n"
        + json.dumps({"counts": counts, "top": [{k: i[k] for k in ('title', 'plain')} for i in items[:6]],
                      "patched": patched, "stack": label})}], max_tokens=600, label="report")
    rep = {"verdict": verdict, "plain_summary": plain, "repo": pp.repo_url or "demo: invoice-mailer",
           "ecosystem": label, "counts": counts, "items": items[:60]}
    pp.emit({"type": "report", **rep})
    return rep
