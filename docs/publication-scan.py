"""Scan the whole git history for material that must not be published.

Complements gitleaks rather than repeating it: these are the classes gitleaks
has no rule for, plus the disclosure categories that are judgement calls rather
than secrets — private addresses, tailnet names, personal contact details.

Deliberately over-triggers. Every hit is triaged by hand, and the triage for the
2026-09-09 run is recorded in docs/publication-audit.md. A scanner that reports
nothing is indistinguishable from one that is not looking, so the intended
output is a handful of false positives with a known explanation, not silence.

    git log --all -p > /tmp/kt-witness-allhist.txt
    python3 docs/publication-scan.py
"""
import re, collections

text = open('/tmp/kt-witness-allhist.txt', errors='replace').read()

PATTERNS = {
    # --- key material that would be catastrophic ---
    "PEM private key":        r"BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY",
    "note/sigsum secret":     r"PRIVATE\+KEY\+",
    "ssh private":            r"ssh-rsa AAAA[A-Za-z0-9+/]{200,}|BEGIN OPENSSH",
    "witness secret key":     r"(?i)(secret[_-]?key|signing[_-]?key|skey|seed)\s*[:=]\s*[\"'][A-Za-z0-9+/=]{32,}",
    # --- service credentials ---
    "tailscale authkey":      r"tskey-[a-z]+-[A-Za-z0-9]{10,}",
    "cloudflare tunnel":      r"TunnelSecret|AccountTag|\"tunnel_secret\"",
    "cloudflare api token":   r"(?i)cf[_-]?api[_-]?token\s*[:=]\s*\S{20,}",
    "github token":           r"gh[pousr]_[A-Za-z0-9]{16,}",
    "aws key":                r"AKIA[0-9A-Z]{16}",
    "slack/discord webhook":  r"hooks\.slack\.com/services/\S+|discord\.com/api/webhooks/\S+",
    "generic bearer":         r"(?i)authorization:\s*bearer\s+\S{20,}",
    "password assignment":    r"(?i)(password|passwd|passphrase)\s*[:=]\s*[\"'][^\"'{}$]{6,}",
    "influx/grafana token":   r"(?i)(influx|grafana)[_-]?(token|password|api[_-]?key)\s*[:=]\s*[\"'][^\"'{}$]{8,}",
    # --- personal / infrastructure disclosure (judgement, not secrets) ---
    "public IPv4":            r"\b(?!10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|169\.254\.|22[4-9]\.|23\d\.|255\.)"
                              r"(?:\d{1,3}\.){3}\d{1,3}\b",
    "private IPv4":           r"\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.)?\d{1,3}\.?\d{0,3}\b",
    "tailnet name":           r"[a-z0-9-]+\.ts\.net",
    "phone number":           r"\+1[- ]?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}",
    "home-ish address":       r"(?i)\b\d{1,5} [A-Z][a-z]+ (?:St|Street|Ave|Avenue|Rd|Road|Ln|Lane|Dr|Drive)\b",
    "email (non-noreply)":    r"[A-Za-z0-9._%+-]+@(?!users\.noreply|noreply|example\.)[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
}

counts = collections.Counter()
samples = collections.defaultdict(set)
for name, pat in PATTERNS.items():
    for m in re.finditer(pat, text):
        s = m.group(0).strip()
        counts[name] += 1
        if len(samples[name]) < 12:
            samples[name].add(s[:90])

for name in PATTERNS:
    n = counts[name]
    flag = "  " if n == 0 else "!!"
    print(f"{flag} {n:>6}  {name}")
    for s in sorted(samples[name]):
        print(f"            {s}")
