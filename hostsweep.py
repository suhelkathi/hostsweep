#!/usr/bin/env python3
"""
HostSweep - a Host header injection scanner.

Detection is confirmation-based to minimise false positives. Each candidate
header is injected with a unique canary value; a finding is only recorded when
that exact canary is reflected back in the response. The tool also extracts the
EXACT reflected value and classifies whether the attacker still controls the
resulting host, so that cases like `evil.com` -> `fr.evil.com` (still yours) are
separated from `evil.com` -> `evil.com.trusted.com` (not yours, not exploitable).

Scan strategy (two passes):
  1. Triage  - all candidate headers are sent in one request, each with a
               distinct canary; whichever canary reflects identifies the header.
  2. Confirm - each header that reflected is re-tested in isolation to rule out
               multi-header interference before it is reported.

Output streams live: each target prints as soon as it finishes, with a progress
counter. Use -v for a per-header live trace.

Author: Suhel Kathi (suhelkathi)
License: MIT
"""

import argparse
import asyncio
import csv
import json
import re
import secrets
import sys
from dataclasses import dataclass, asdict, field
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

try:
    import httpx
except ImportError:
    sys.exit("[!] Missing dependency. Run:  pip install httpx")

ATTACKER_ROOT = "canary-hostsweep.com"   # anything ending in this = attacker-controlled


# ----------------------------- colours --------------------------------------
class C:
    RED = "\033[91m"; YEL = "\033[93m"; GRN = "\033[92m"
    CYN = "\033[96m"; GRY = "\033[90m"; BLD = "\033[1m"; RST = "\033[0m"

    @classmethod
    def strip(cls):
        for k in ("RED", "YEL", "GRN", "CYN", "GRY", "BLD", "RST"):
            setattr(cls, k, "")


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YEL,
             "LOW": C.CYN, "INFO": C.GRY}

CANDIDATE_HEADERS = [
    ("X-Forwarded-Host",     lambda c: c),
    ("X-Forwarded-Server",   lambda c: c),
    ("X-Host",               lambda c: c),
    ("X-HTTP-Host-Override", lambda c: c),
    ("X-Original-Host",      lambda c: c),
    ("X-Original-URL",       lambda c: c),
    ("X-Rewrite-URL",        lambda c: c),
    ("Forwarded",            lambda c: f"host={c}"),
    ("X-Forwarded-For",      lambda c: c),
]
HEADER_FMT = dict(CANDIDATE_HEADERS)


# ----------------------------- data model -----------------------------------
@dataclass
class Finding:
    url: str
    header: str
    canary: str
    reflected_value: str    # the EXACT host string that came back
    control: str            # exact | prefixed | wrapped
    location: str
    severity: str
    detail: str


@dataclass
class Target:
    url: str
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    error: Optional[str] = None


# ------------------------- reflection analysis ------------------------------
def new_canary(tag: str) -> str:
    return f"hs-{secrets.token_hex(4)}-{tag}.{ATTACKER_ROOT}"


def _token_around(text: str, canary: str) -> str:
    """Pull the full host-like token that contains the canary."""
    m = re.search(r'([A-Za-z0-9._%-]*' + re.escape(canary) + r'[A-Za-z0-9._%-]*)',
                  text)
    return m.group(1) if m else canary


def _control(token: str, canary: str) -> str:
    """exact = value returned unchanged; prefixed = subdomain added but still
    under the attacker root; wrapped = something appended after the attacker
    root, so the effective host is NOT attacker-controlled."""
    t = token.strip().rstrip("/").rstrip(".").lower()
    if not t.endswith(ATTACKER_ROOT):
        return "wrapped"
    return "exact" if t == canary.lower() else "prefixed"


def _safe_text(resp) -> str:
    try:
        return resp.text or ""
    except Exception:            # noqa: BLE001 - decoding can fail
        try:
            return resp.content.decode("utf-8", "ignore")
        except Exception:        # noqa: BLE001
            return ""


def find_reflections(resp, canary: str):
    """Return list of (context, token, control)."""
    out = []
    loc = resp.headers.get("location", "") or ""
    if canary in loc:
        tok = _token_around(loc, canary)
        out.append(("Location header (redirect)", tok, _control(tok, canary)))

    try:
        cookies = resp.headers.get_list("set-cookie")
    except Exception:            # noqa: BLE001
        sc = resp.headers.get("set-cookie", "")
        cookies = [sc] if sc else []
    for sc in cookies:
        if sc and canary in sc:
            tok = _token_around(sc, canary)
            out.append(("Set-Cookie", tok, _control(tok, canary)))
            break

    body = _safe_text(resp)
    if canary in body:
        tok = _token_around(body, canary)
        ctrl = _control(tok, canary)
        if re.search(r'(?:href|src|action|content)\s*=\s*["\']?[^"\'>]*'
                     + re.escape(canary), body, re.I):
            out.append(("HTML attribute (href/src/action)", tok, ctrl))
        else:
            out.append(("response body", tok, ctrl))
    return out


def score(header: str, context: str, control: str, value: str):
    if control == "wrapped":
        return ("INFO",
                f"'{header}' was reflected as '{value}', but a suffix was "
                f"appended so the effective host is NOT attacker-controlled. "
                f"Most likely not exploitable; noted for completeness.")

    ctrl_note = ("returned unchanged - full attacker control" if control == "exact"
                 else f"attacker-controlled subdomain (server prefixed it to "
                      f"'{value}', but it still resolves to your domain)")

    if "Location" in context:
        return ("HIGH",
                f"'{header}' is reflected into the redirect target as '{value}' "
                f"({ctrl_note}). Enables open redirect and, where the value "
                f"feeds password-reset or verification links, reset-poisoning. "
                f"Trigger the reset flow manually to confirm impact.")
    if "Set-Cookie" in context:
        return ("HIGH",
                f"'{header}' influences the cookie domain as '{value}' "
                f"({ctrl_note}); can lead to cookie scoping or fixation.")
    if "attribute" in context:
        return ("MEDIUM",
                f"'{header}' is reflected into an HTML attribute as '{value}' "
                f"({ctrl_note}); may load attacker-controlled content.")
    return ("MEDIUM",
            f"'{header}' is reflected into the response body as '{value}' "
            f"({ctrl_note}). Confirm it reaches a security-relevant sink.")


# ------------------------------ core scan -----------------------------------
async def scan_target(client, url, base_headers, do_cache, verbose, log) -> Target:
    t = Target(url=url)
    short = url if len(url) <= 48 else url[:45] + "..."

    try:
        base = await client.request("GET", url, headers=base_headers)
    except Exception as e:                           # noqa: BLE001
        t.error = f"{type(e).__name__}: {e}"
        return t
    base_status, base_len = base.status_code, len(_safe_text(base))
    if verbose:
        log(f"{C.GRY}[.]{C.RST} {short}  baseline {base_status}, {base_len}B")

    # ---- pass 1: triage ----
    triage_headers = dict(base_headers)
    canary_map = {}
    for hname, fmt in CANDIDATE_HEADERS:
        can = new_canary(hname.replace("-", "").lower()[:8])
        canary_map[hname] = can
        triage_headers[hname] = fmt(can)
    try:
        tri = await client.request("GET", url, headers=triage_headers)
    except Exception as e:                           # noqa: BLE001
        t.error = f"triage failed: {type(e).__name__}: {e}"
        return t

    candidates = [h for h, can in canary_map.items() if find_reflections(tri, can)]
    if verbose:
        log(f"{C.GRY}[.]{C.RST} {short}  triage flagged: "
            f"{', '.join(candidates) or 'none'}")

    # ---- pass 2: confirm each candidate in isolation ----
    for hname in candidates:
        fmt = HEADER_FMT[hname]
        can = new_canary(hname.replace("-", "").lower()[:8])
        hdrs = dict(base_headers); hdrs[hname] = fmt(can)
        try:
            r = await client.request("GET", url, headers=hdrs)
        except Exception:                            # noqa: BLE001
            continue
        refs = find_reflections(r, can)
        if not refs:
            continue
        context, token, control = refs[0]
        sev, detail = score(hname, context, control, token)
        t.findings.append(Finding(url=url, header=hname, canary=can,
                                  reflected_value=token, control=control,
                                  location=context, severity=sev, detail=detail))
        if verbose:
            col = SEV_COLOR[sev]
            log(f"  {col}[{sev}]{C.RST} {short}  {hname} -> {context} "
                f"as '{token}'")

    # ---- behavioural signal: spoofed Host (robust, never crashes) ----
    host_canary = new_canary("host")
    try:
        hb = await client.request("GET", url,
                                  headers={**base_headers, "Host": host_canary})
    except Exception as e:                           # noqa: BLE001
        t.notes.append(f"Spoofed Host request failed ({type(e).__name__}); the "
                       f"server may strictly validate Host. Worth a manual look.")
    else:
        refs = find_reflections(hb, host_canary)
        if refs:
            context, token, control = refs[0]
            sev, detail = score("Host", context, control, token)
            t.findings.append(Finding(url=url, header="Host", canary=host_canary,
                                      reflected_value=token, control=control,
                                      location=context, severity=sev, detail=detail))
        else:
            try:
                changed = (hb.status_code != base_status or
                           abs(len(_safe_text(hb)) - base_len) > 40)
            except Exception:                        # noqa: BLE001
                changed = False
            if changed:
                t.notes.append(
                    f"Response changed when Host was spoofed "
                    f"(status {base_status}->{hb.status_code}, "
                    f"len {base_len}->{len(_safe_text(hb))}). No reflection "
                    f"seen; review manually for routing/SSRF behaviour.")

    # ---- optional cache poisoning ----
    if do_cache:
        try:
            await cache_poison_check(client, url, base_headers, t)
        except Exception:                            # noqa: BLE001
            pass

    # de-dupe
    seen, uniq = set(), []
    for f in sorted(t.findings, key=lambda x: SEV_ORDER[x.severity]):
        key = (f.header, f.location)
        if key not in seen:
            seen.add(key); uniq.append(f)
    t.findings = uniq
    return t


async def cache_poison_check(client, url, base_headers, t: Target):
    buster = secrets.token_hex(3)
    parts = urlsplit(url)
    q = (parts.query + "&" if parts.query else "") + f"cb={buster}"
    poison_url = urlunsplit((parts.scheme, parts.netloc, parts.path, q,
                             parts.fragment))
    can = new_canary("cache")
    await client.request("GET", poison_url,
                         headers={**base_headers, "X-Forwarded-Host": can})
    clean = await client.request("GET", poison_url, headers=base_headers)
    refs = find_reflections(clean, can)
    if refs:
        _, token, _ = refs[0]
        t.findings.append(Finding(
            url=url, header="X-Forwarded-Host", canary=can,
            reflected_value=token, control=_control(token, can),
            location="cached response", severity="CRITICAL",
            detail=f"A poisoned Host value ('{token}') was cached and served to "
                   f"a subsequent clean request. Web cache poisoning affecting "
                   f"other users."))


# ------------------------------- runner -------------------------------------
def build_headers(args):
    headers = {"User-Agent": args.user_agent}
    for h in args.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    cookies = {}
    if args.cookie:
        for part in args.cookie.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
    return headers, cookies


async def run(urls, args, printer):
    headers, cookies = build_headers(args)
    limits = httpx.Limits(max_connections=args.concurrency)

    def log(msg):
        print(msg, flush=True)

    async with httpx.AsyncClient(
            verify=not args.insecure, follow_redirects=False,
            timeout=args.timeout, limits=limits, cookies=cookies,
            proxy=args.proxy or None) as client:
        sem = asyncio.Semaphore(args.concurrency)

        async def bound(u):
            async with sem:
                return await scan_target(client, u, headers, args.cache,
                                         args.verbose, log)

        tasks = [asyncio.ensure_future(bound(u)) for u in urls]
        total = len(tasks)
        results = []
        done = 0
        for fut in asyncio.as_completed(tasks):
            t = await fut
            done += 1
            printer(t, done, total)      # live: print each target as it finishes
            results.append(t)
        return results


# ------------------------------- output -------------------------------------
def print_target(t, done, total, only_vuln):
    prefix = f"{C.GRY}[{done}/{total}]{C.RST}"
    rows = t.findings
    if only_vuln:
        rows = [f for f in rows if f.severity not in ("INFO", "LOW")]
    if t.error and not rows:
        print(f"{prefix} {C.GRY}[err ]{C.RST} {t.url}  ({t.error})", flush=True)
        return
    if not rows and not (t.notes and not only_vuln):
        print(f"{prefix} {C.GRN}[ ok ]{C.RST} {t.url}", flush=True)
        return
    print(f"\n{prefix} {C.BLD}{t.url}{C.RST}", flush=True)
    for f in rows:
        col = SEV_COLOR[f.severity]
        tag = {"exact": "exact", "prefixed": "prefixed",
               "wrapped": "wrapped/not-controlled"}.get(f.control, f.control)
        print(f"  {col}{f.severity:<8}{C.RST} {f.header:<20} "
              f"-> {f.location}", flush=True)
        print(f"           reflected value: {C.CYN}{f.reflected_value}{C.RST} "
              f"[{tag}]", flush=True)
        print(f"           {C.GRY}{f.detail}{C.RST}", flush=True)
    if not only_vuln:
        for n in t.notes:
            print(f"  {C.GRY}NOTE     {n}{C.RST}", flush=True)


def print_summary(targets):
    n = sum(1 for t in targets for f in t.findings
            if f.severity in ("CRITICAL", "HIGH", "MEDIUM"))
    print(f"\n{C.BLD}{n}{C.RST} actionable finding(s) across "
          f"{len(targets)} target(s).", flush=True)


def write_json(targets, path):
    out = [{"url": t.url, "error": t.error, "notes": t.notes,
            "findings": [asdict(f) for f in t.findings]} for t in targets]
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)


def write_csv(targets, path):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "severity", "header", "location", "reflected_value",
                    "control", "detail"])
        for t in targets:
            for f in t.findings:
                w.writerow([f.url, f.severity, f.header, f.location,
                            f.reflected_value, f.control, f.detail])


# ------------------------------- CLI ----------------------------------------
def main():
    ap = argparse.ArgumentParser(
        prog="hostsweep",
        description="Host header injection scanner (confirmation-based).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url", help="single target URL")
    g.add_argument("-l", "--list", help="file with one URL per line")
    ap.add_argument("-c", "--cookie", help="Cookie header for authenticated tests")
    ap.add_argument("-H", "--header", action="append",
                    help="extra request header 'K: V' (repeatable)")
    ap.add_argument("-t", "--concurrency", type=int, default=15)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--cache", action="store_true",
                    help="also run the web cache poisoning check")
    ap.add_argument("--proxy", help="e.g. http://127.0.0.1:8080 for Burp")
    ap.add_argument("-k", "--insecure", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="live per-header trace while scanning")
    ap.add_argument("--user-agent", default="HostSweep/1.1")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--csv", dest="csv_out")
    ap.add_argument("--only-vuln", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.strip()
        for k in SEV_COLOR:
            SEV_COLOR[k] = ""

    if args.url:
        urls = [args.url]
    else:
        with open(args.list) as fh:
            urls = [ln.strip() for ln in fh if ln.strip()
                    and not ln.startswith("#")]
    urls = [u if u.startswith("http") else "https://" + u for u in urls]

    print(f"{C.GRY}[>]{C.RST} scanning {len(urls)} target(s) with "
          f"{len(CANDIDATE_HEADERS)} candidate headers...\n", flush=True)

    def printer(t, done, total):
        print_target(t, done, total, args.only_vuln)

    targets = asyncio.run(run(urls, args, printer))
    print_summary(targets)

    if args.json_out:
        write_json(targets, args.json_out)
        print(f"{C.GRY}JSON -> {args.json_out}{C.RST}", flush=True)
    if args.csv_out:
        write_csv(targets, args.csv_out)
        print(f"{C.GRY}CSV  -> {args.csv_out}{C.RST}", flush=True)

    for t in targets:
        if any(f.severity in ("CRITICAL", "HIGH") for f in t.findings):
            sys.exit(2)


if __name__ == "__main__":
    main()
