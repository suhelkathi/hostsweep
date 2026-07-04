#!/usr/bin/env python3
"""
HostSweep - a Host header injection scanner.

Detection is confirmation-based to minimise false positives. Each candidate
header is injected with a unique canary value; a finding is only recorded when
that exact canary is reflected back in the response (redirect target, body, or
Set-Cookie). Reflections are reported separately from behavioural changes so
that lower-confidence signals never inflate the primary results.

Scan strategy (two passes):
  1. Triage  - all candidate headers are sent in a single request, each with a
               distinct canary. Whichever canary is reflected identifies which
               header the server trusts, at the cost of one request.
  2. Confirm - each header that reflected in triage is re-tested in isolation to
               rule out multi-header interference before it is reported.

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
from urllib.parse import urlparse, urlsplit, urlunsplit

try:
    import httpx
except ImportError:
    sys.exit("[!] Missing dependency. Run:  pip install httpx")


# ----------------------------- colours --------------------------------------
class C:
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"
    GRY = "\033[90m"
    BLD = "\033[1m"
    RST = "\033[0m"

    @classmethod
    def strip(cls):
        for k in ("RED", "YEL", "GRN", "CYN", "GRY", "BLD", "RST"):
            setattr(cls, k, "")


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YEL,
             "LOW": C.CYN, "INFO": C.GRY}

# Candidate headers. Value is a formatter that wraps the canary appropriately.
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


# ----------------------------- data model -----------------------------------
@dataclass
class Finding:
    url: str
    header: str            # the request header that was trusted
    canary: str
    location: str          # where the canary was reflected
    severity: str
    detail: str


@dataclass
class Target:
    url: str
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)   # behavioural, lower confidence
    error: Optional[str] = None


# ------------------------- reflection analysis ------------------------------
def new_canary(tag: str) -> str:
    return f"hs-{secrets.token_hex(4)}-{tag}.canary-hostsweep.com"


def where_reflected(resp, canary: str):
    """Return a list of contexts in which `canary` appears, or []."""
    hits = []
    loc = resp.headers.get("location", "")
    if canary in loc:
        hits.append("Location header (redirect)")

    for sc in resp.headers.get_list("set-cookie") if hasattr(
            resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]:
        if sc and canary in sc:
            hits.append("Set-Cookie")
            break

    body = resp.text or ""
    if canary in body:
        # try to classify the context in the body
        if re.search(r'(?:href|src|action|content)\s*=\s*["\']?[^"\'>]*'
                     + re.escape(canary), body, re.I):
            hits.append("HTML attribute (href/src/action)")
        elif re.search(r'<link[^>]+' + re.escape(canary), body, re.I):
            hits.append("<link> tag")
        else:
            hits.append("response body")
    return hits


def score(header: str, context: str) -> (str, str):
    """Severity + explanation for a confirmed reflection."""
    if "Location" in context:
        return ("HIGH",
                f"'{header}' is reflected into the redirect target. This can "
                f"enable open redirect and, where the value feeds password "
                f"reset or verification links, reset-poisoning. Verify the "
                f"reset flow manually to confirm impact.")
    if "Set-Cookie" in context:
        return ("HIGH",
                f"'{header}' influences the cookie domain/scope, which can lead "
                f"to cookie scoping or fixation issues.")
    if "attribute" in context or "<link>" in context:
        return ("MEDIUM",
                f"'{header}' is reflected into an HTML attribute. If it feeds a "
                f"script/link source, it may load attacker-controlled content.")
    return ("MEDIUM",
            f"'{header}' is reflected into the response body. Confirm whether "
            f"the value reaches a security-relevant sink.")


# ------------------------------ core scan -----------------------------------
async def request(client, method, url, extra_headers):
    return await client.request(method, url, headers=extra_headers)


async def scan_target(client, url, base_headers, do_cache, sem) -> Target:
    t = Target(url=url)
    async with sem:
        # ---- baseline (no injected headers) ----
        try:
            base = await request(client, "GET", url, base_headers)
        except Exception as e:                       # noqa: BLE001
            t.error = f"{type(e).__name__}: {e}"
            return t
        base_status, base_len = base.status_code, len(base.text or "")

        # ---- pass 1: triage, all headers with distinct canaries ----
        triage_headers = dict(base_headers)
        canary_map = {}
        for hname, fmt in CANDIDATE_HEADERS:
            can = new_canary(hname.replace("-", "").lower()[:8])
            canary_map[hname] = can
            triage_headers[hname] = fmt(can)
        try:
            tri = await request(client, "GET", url, triage_headers)
        except Exception as e:                       # noqa: BLE001
            t.error = f"{type(e).__name__}: {e}"
            return t

        candidates = []
        for hname, can in canary_map.items():
            if where_reflected(tri, can):
                candidates.append(hname)

        # ---- pass 2: confirm each candidate in isolation ----
        for hname in candidates:
            fmt = dict(CANDIDATE_HEADERS)[hname]
            can = new_canary(hname.replace("-", "").lower()[:8])
            hdrs = dict(base_headers)
            hdrs[hname] = fmt(can)
            try:
                r = await request(client, "GET", url, hdrs)
            except Exception:                        # noqa: BLE001
                continue
            contexts = where_reflected(r, can)
            if not contexts:
                continue  # triage hit was interference; drop it
            ctx = contexts[0]
            sev, detail = score(hname, ctx)
            t.findings.append(Finding(url=url, header=hname, canary=can,
                                      location=ctx, severity=sev, detail=detail))

        # ---- behavioural signal: spoofed Host with no reflection ----
        host_canary = new_canary("host")
        try:
            hb = await request(client, "GET", url,
                               {**base_headers, "Host": host_canary})
            changed = (hb.status_code != base_status or
                       abs(len(hb.text or "") - base_len) > 40)
            reflected = bool(where_reflected(hb, host_canary))
            if reflected:
                sev, detail = score("Host", (where_reflected(hb, host_canary) or
                                             ["response body"])[0])
                t.findings.append(Finding(url=url, header="Host",
                                          canary=host_canary,
                                          location=(where_reflected(
                                              hb, host_canary))[0],
                                          severity=sev, detail=detail))
            elif changed:
                t.notes.append(
                    f"Response changed when Host was spoofed "
                    f"(status {base_status}->{hb.status_code}, "
                    f"len {base_len}->{len(hb.text or '')}). No reflection "
                    f"seen; review manually for routing/SSRF behaviour.")
        except Exception:                            # noqa: BLE001
            pass

        # ---- optional: cache poisoning via X-Forwarded-Host ----
        if do_cache:
            await cache_poison_check(client, url, base_headers, t)

    # de-dupe findings by (header, severity)
    seen, uniq = set(), []
    for f in sorted(t.findings, key=lambda x: SEV_ORDER[x.severity]):
        key = (f.header, f.location)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    t.findings = uniq
    return t


async def cache_poison_check(client, url, base_headers, t: Target):
    """Poison with a cache-buster, then request the same URL clean.
    If the canary survives into the clean response, the cache served it."""
    buster = secrets.token_hex(3)
    parts = urlsplit(url)
    q = (parts.query + "&" if parts.query else "") + f"cb={buster}"
    poison_url = urlunsplit((parts.scheme, parts.netloc, parts.path, q,
                             parts.fragment))
    can = new_canary("cache")
    try:
        await request(client, "GET", poison_url,
                      {**base_headers, "X-Forwarded-Host": can})
        clean = await request(client, "GET", poison_url, base_headers)
    except Exception:                                # noqa: BLE001
        return
    if where_reflected(clean, can):
        t.findings.append(Finding(
            url=url, header="X-Forwarded-Host", canary=can,
            location="cached response",
            severity="CRITICAL",
            detail="A poisoned Host value was cached and served to a "
                   "subsequent clean request. This is web cache poisoning: the "
                   "malicious value is delivered to other users."))


# ------------------------------- runner -------------------------------------
async def run(urls, args):
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

    limits = httpx.Limits(max_connections=args.concurrency)
    sem = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(
            verify=not args.insecure, follow_redirects=False,
            timeout=args.timeout, limits=limits, cookies=cookies,
            proxy=args.proxy or None) as client:
        tasks = [scan_target(client, u, headers, args.cache, sem) for u in urls]
        return await asyncio.gather(*tasks)


# ------------------------------- output -------------------------------------
def print_report(targets, only_vuln):
    total = 0
    for t in targets:
        rows = t.findings
        if only_vuln:
            rows = [f for f in rows if f.severity not in ("INFO", "LOW")]
        if t.error and not rows:
            print(f"{C.GRY}[err]{C.RST} {t.url}  ({t.error})")
            continue
        if not rows and not (t.notes and not only_vuln):
            print(f"{C.GRN}[ok ]{C.RST} {t.url}")
            continue
        print(f"\n{C.BLD}{t.url}{C.RST}")
        for f in rows:
            total += 1
            col = SEV_COLOR[f.severity]
            print(f"  {col}{f.severity:<8}{C.RST} {f.header:<20} "
                  f"reflected in {f.location}")
            print(f"           {C.GRY}{f.detail}{C.RST}")
        if not only_vuln:
            for n in t.notes:
                print(f"  {C.GRY}NOTE     {n}{C.RST}")
    print(f"\n{C.BLD}{total}{C.RST} confirmed reflection finding(s) across "
          f"{len(targets)} target(s).")


def write_json(targets, path):
    out = [{"url": t.url, "error": t.error, "notes": t.notes,
            "findings": [asdict(f) for f in t.findings]} for t in targets]
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)


def write_csv(targets, path):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "severity", "header", "location", "canary", "detail"])
        for t in targets:
            for f in t.findings:
                w.writerow([f.url, f.severity, f.header, f.location, f.canary,
                            f.detail])


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
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="skip TLS verification")
    ap.add_argument("--user-agent", default="HostSweep/1.0")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--csv", dest="csv_out")
    ap.add_argument("--only-vuln", action="store_true",
                    help="hide OK/INFO/LOW rows and notes")
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

    targets = asyncio.run(run(urls, args))
    print_report(targets, args.only_vuln)
    if args.json_out:
        write_json(targets, args.json_out)
        print(f"{C.GRY}JSON -> {args.json_out}{C.RST}")
    if args.csv_out:
        write_csv(targets, args.csv_out)
        print(f"{C.GRY}CSV  -> {args.csv_out}{C.RST}")

    for t in targets:
        if any(f.severity in ("CRITICAL", "HIGH") for f in t.findings):
            sys.exit(2)


if __name__ == "__main__":
    main()
