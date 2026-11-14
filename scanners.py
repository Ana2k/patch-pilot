"""
Language-agnostic hunting: dependency inventory (lockfiles -> OSV) and SAST (semgrep + bandit + a fast pattern hunter).
Everything executes INSIDE the Daytona sandbox; only the parsed results come back.
"""
from __future__ import annotations

import json
import re
import shlex

ECOSYSTEMS = [  # (marker file, OSV ecosystem, label, patchable by the Fixer)
    ("requirements.txt", "PyPI", "Python", True),
    ("composer.lock", "Packagist", "PHP", False),
    ("composer.json", "Packagist", "PHP", False),
    ("go.mod", "Go", "Go", False),
    ("package-lock.json", "npm", "Node.js", False),
    ("package.json", "npm", "Node.js", False),
    ("pyproject.toml", "PyPI", "Python", False),
]

# Fast, explainable pattern hunter. Each rule: (id, severity, regex, title, plain-English meaning)
PATTERNS = [
    # PHP: the classic remote-code-execution and injection sinks
    ("php-eval", "CRITICAL", r"\b(eval|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "eval() on user input",
     "Anyone can send code to this page and the server will run it."),
    ("php-cmd", "CRITICAL", r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)|`[^`]*\$_(GET|POST|REQUEST)",
     "OS command built from user input", "An attacker can run any command on the server through this input."),
    ("php-include", "CRITICAL", r"\b(include|require)(_once)?\s*\(?[^;]*\$_(GET|POST|REQUEST|COOKIE)",
     "File include from user input (LFI/RFI)", "An attacker can make the server load and run files of their choosing."),
    # PHP taint-style: user input flows through a variable into a dangerous sink (DVWA-style code)
    ("php-cmd-concat", "CRITICAL", r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^;]*['\"]\s*\.\s*\$[A-Za-z_]",
     "OS command built by string concatenation (command injection)", "If that variable comes from a user, they can run any command on the server."),
    ("php-sqli-var", "CRITICAL", r"(SELECT|INSERT|UPDATE|DELETE)[^;\n]*(['\"]\s*\.\s*\$[A-Za-z_]|'\$[A-Za-z_]+')",
     "SQL query built from a variable (SQL injection)", "An attacker can read, change or delete the database."),
    ("php-include-var", "CRITICAL", r"\b(include|require)(_once)?\s*\(?\s*\$[A-Za-z_]",
     "File include from a variable (LFI/RFI)", "An attacker may make the server load and run arbitrary files."),
    ("php-upload", "HIGH", r"move_uploaded_file\s*\(", "File upload handler",
     "Uploads without strict type checks let attackers plant a web shell."),
    ("php-unserialize", "HIGH", r"\bunserialize\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)",
     "unserialize() on user input", "Crafted data can trigger hidden code paths (object injection)."),
    ("php-sqli", "HIGH", r"(mysqli?_query|->query|pg_query)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)|(SELECT|INSERT|UPDATE|DELETE)[^;\n]*['\"]\s*\.\s*\$_(GET|POST|REQUEST)",
     "SQL query built from user input", "An attacker can read or change the database (SQL injection)."),
    ("php-xss", "MEDIUM", r"\becho\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)", "User input echoed into the page (XSS)",
     "Attackers can inject scripts that run in your users' browsers."),
    ("php-weak-hash", "MEDIUM", r"\bmd5\s*\(\s*\$(pass|password|pwd)", "Passwords hashed with MD5",
     "Stolen password hashes can be cracked in seconds."),
    # Python
    ("py-shell", "HIGH", r"subprocess\.(call|run|Popen|check_output)\([^)]*shell\s*=\s*True", "Shell command with shell=True",
     "If any part of the command comes from users, they can run their own commands."),
    ("py-pickle", "HIGH", r"pickle\.loads?\(", "pickle deserialisation", "Loading untrusted pickle data lets an attacker run code."),
    ("py-yaml", "HIGH", r"yaml\.load\([^)]*\)$", "yaml.load without SafeLoader", "Untrusted YAML can execute code."),
    ("tls-off", "MEDIUM", r"verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|rejectUnauthorized\s*:\s*false",
     "TLS certificate checks disabled", "Traffic can be intercepted and altered (man-in-the-middle)."),
    # Go / JS
    ("go-cmd", "HIGH", r"exec\.Command\(\s*\"(sh|bash)\"\s*,\s*\"-c\"", "Shell invoked via sh -c",
     "Shell strings are easy to inject into if any part is user-controlled."),
    ("go-sqli", "HIGH", r"(Query|Exec)(Context)?\([^)]*fmt\.Sprintf", "SQL built with fmt.Sprintf", "Possible SQL injection."),
    ("js-eval", "HIGH", r"\beval\(|new Function\(|child_process\.exec\(", "Dynamic code / shell execution in JS",
     "If input reaches here, attackers can run code."),
    # Secrets (any language)
    ("secret", "HIGH", r"(sk_live_[0-9A-Za-z]{10,}|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{30,}|xox[bap]-[0-9A-Za-z-]{10,}|-----BEGIN (RSA |EC )?PRIVATE KEY-----)",
     "Hard-coded secret / API key", "A real credential is in the code; anyone with the repo can use it."),
]
FIXES = {
    "php-eval": "Never eval user input. Remove eval() and map allowed actions explicitly.",
    "php-cmd": "Avoid the shell; if unavoidable use escapeshellarg($input) and an allow-list.",
    "php-cmd-concat": "$ip = filter_var($_REQUEST['ip'], FILTER_VALIDATE_IP); if ($ip) { shell_exec('ping -c 4 ' . escapeshellarg($ip)); }",
    "php-include": "Use a fixed allow-list: $pages=['home'=>'home.php']; include $pages[$_GET['p']] ?? 'home.php';",
    "php-include-var": "Only include files from a hard-coded allow-list, never a path built from input.",
    "php-sqli": "$st = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $st->execute([$id]);",
    "php-sqli-var": "$st = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $st->execute([$id]);",
    "php-unserialize": "Use json_decode() instead of unserialize() for untrusted data.",
    "php-upload": "Check MIME + extension allow-list, rename the file, store outside the web root.",
    "php-xss": "echo htmlspecialchars($value, ENT_QUOTES, 'UTF-8');",
    "php-weak-hash": "$hash = password_hash($password, PASSWORD_DEFAULT); password_verify($input, $hash);",
    "py-shell": "subprocess.run(['gzip', '-k', filename], check=True)  # no shell=True",
    "py-pickle": "Use json.loads() for untrusted data instead of pickle.",
    "py-yaml": "yaml.safe_load(data)",
    "tls-off": "Remove verify=False / InsecureSkipVerify; trust the proper CA bundle instead.",
    "go-cmd": "exec.Command(\"ping\", \"-c\", \"4\", host)  // pass args, no sh -c",
    "go-sqli": "db.Query(\"SELECT * FROM t WHERE id = $1\", id)",
    "js-eval": "Remove eval(); parse data with JSON.parse() and use explicit handlers.",
    "secret": "Revoke the key now, move it to an environment variable or secret manager.",
}
CODE_EXT = r"\.(php|py|go|js|ts|jsx|tsx|rb|java|inc)$"


def detect(files: set[str]) -> tuple[str | None, str, str, bool]:
    for marker, eco, label, patchable in ECOSYSTEMS:
        if marker in files:
            return marker, eco, label, patchable
    return None, "", "unknown", False


def inventory(pp, marker: str) -> dict[str, str]:
    """Parse the lockfile inside the sandbox -> {package: version}."""
    raw = pp.sandbox.fs.download_file(f"{pp.repo}/{marker}").decode(errors="replace")
    pk: dict[str, str] = {}
    if marker == "go.mod":
        for m in re.finditer(r"^\s*(?:require\s+)?([\w.\-/]+\.[\w.\-/]+)\s+v([\w.\-+]+)", raw, re.M):
            pk[m.group(1)] = m.group(2).split("+")[0]
    elif marker == "composer.lock":
        d = json.loads(raw)
        for p in d.get("packages", []) + d.get("packages-dev", []):
            pk[p["name"]] = p["version"].lstrip("v")
    elif marker == "package-lock.json":
        d = json.loads(raw)
        for k, v in (d.get("packages") or {}).items():
            if k.startswith("node_modules/") and v.get("version"):
                pk[k.split("node_modules/")[-1]] = v["version"]
    elif marker in ("composer.json", "package.json"):
        d = json.loads(raw)
        for sec in ("require", "dependencies"):
            for n, v in (d.get(sec) or {}).items():
                m = re.search(r"(\d+\.\d+(\.\d+)?)", v)
                if m and ("/" in n or marker == "package.json"):
                    pk[n] = m.group(1)
    return pk


def pattern_hunt(pp) -> list[dict]:
    """grep-based hunter: milliseconds, explainable, works for every language."""
    out = []
    for rid, sev, rx, title, plain in PATTERNS:
        _, res = pp.sh(f"git ls-files | grep -E '{CODE_EXT}' | grep -vE '(^|/)(vendor|node_modules|tests?|\\.venv)/' "
                       f"| head -3000 | xargs -r grep -nEI -m3 -e {shlex.quote(rx)} 2>/dev/null | head -12", show=False)
        for line in res.splitlines():
            m = re.match(r"^(.+?):(\d+):(.*)$", line)
            if m:
                out.append({"tool": "pattern", "rule": rid, "severity": sev, "file": m.group(1), "line": int(m.group(2)),
                            "title": title, "plain": plain, "code": m.group(3).strip()[:200]})
    return out


def semgrep(pp, label: str) -> list[dict]:
    cfg = "--config p/security-audit --config p/secrets" + (" --config p/php" if label == "PHP" else "") + \
          (" --config p/golang" if label == "Go" else "")
    _, raw = pp.sh("(test -x /tmp/sec/bin/semgrep || (python3 -m venv /tmp/sec && /tmp/sec/bin/pip install -q semgrep)) >/dev/null 2>&1; "
                   f"timeout 150 /tmp/sec/bin/semgrep scan {cfg} --json --quiet --metrics=off --timeout 10 "
                   "--exclude vendor --exclude node_modules --exclude .venv --exclude tests . 2>/dev/null", timeout=320)
    try:
        d = json.loads(raw[raw.find("{"):])
    except Exception:
        return []
    sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    return [{"tool": "semgrep", "rule": r["check_id"].split(".")[-1], "severity": sev.get(r["extra"].get("severity"), "LOW"),
             "file": r["path"], "line": r["start"]["line"], "title": r["extra"].get("message", "")[:160],
             "code": (r["extra"].get("lines") or "")[:200]} for r in d.get("results", [])][:60]


def bandit(pp) -> list[dict]:
    _, raw = pp.sh("(test -x /tmp/sec/bin/bandit || (python3 -m venv /tmp/sec; /tmp/sec/bin/pip install -q bandit)) >/dev/null 2>&1; "
                   "/tmp/sec/bin/bandit -r . -x ./.venv,./tests,./vendor -f json -q 2>/dev/null", timeout=300)
    try:
        b = json.loads(raw[raw.find("{"):])
    except Exception:
        return []
    return [{"tool": "bandit", "rule": r["test_id"], "severity": r["issue_severity"], "file": r["filename"].lstrip("./"),
             "line": r["line_number"], "title": r["issue_text"], "code": r.get("code", "")[:200]} for r in b.get("results", [])][:40]
