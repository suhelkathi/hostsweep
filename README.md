# HostSweep

A Host header injection scanner focused on accurate, confirmation-based detection.

HostSweep tests whether a web application trusts client-supplied host information
and reflects it into a security-relevant location. It reports a finding only when
an injected canary value is provably reflected in the response, which keeps false
positives low enough to use the results directly in an engagement.

![HostSweep output](hostsweep_output.png)

## Detection approach

Each candidate header is injected with a unique canary value. A finding is
recorded only when that exact canary appears in the response — in the redirect
target, an HTML attribute, the response body, or a `Set-Cookie` value. Reflection
is treated as confirmation; indirect or behavioural signals are reported
separately and never counted as confirmed findings.

Scanning runs in two passes:

1. **Triage.** All candidate headers are sent in a single request, each carrying a
   distinct canary. The canary that is reflected identifies exactly which header
   the server trusts, using only one request.
2. **Confirmation.** Every header that reflected during triage is re-tested in
   isolation, with a fresh canary, to rule out interference from sending multiple
   headers at once. Only headers that reflect again are reported.

For every confirmed reflection, HostSweep also extracts the **exact value that
came back** and classifies whether the attacker still controls the resulting
host:

- **exact** — the value was returned unchanged (full control).
- **prefixed** — the server added a label in front, e.g. `evil.com` came back as
  `fr.evil.com`. The host still resolves to the attacker's domain, so this is
  still exploitable and is scored accordingly.
- **wrapped** — the server appended a suffix, e.g. `evil.com` came back as
  `evil.com.trusted.com`. The effective host is no longer attacker-controlled, so
  this is downgraded to informational rather than reported as a vulnerability.

This distinction is what prevents modified-but-not-controlled reflections from
being reported as false positives.

Output streams live: each target is printed as soon as it finishes, with a
progress counter, and `-v` adds a per-header trace while the scan runs.

## Headers tested

`X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`, `X-HTTP-Host-Override`,
`X-Original-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`,
`X-Forwarded-For`, and a spoofed `Host` value.

## Severity model

| Reflected in | Severity | Rationale |
|--------------|----------|-----------|
| Redirect `Location` (attacker-controlled) | High | Open redirect; potential password-reset poisoning |
| `Set-Cookie` domain (attacker-controlled) | High | Cookie scoping or fixation |
| HTML attribute (`href`/`src`/`action`) | Medium | May load attacker-controlled content |
| Response body (attacker-controlled) | Medium | Confirm the value reaches a security-relevant sink |
| Cached response (with `--cache`) | Critical | Web cache poisoning affecting other users |
| Reflected but `wrapped` (not attacker-controlled) | Info | Value modified into a non-attacker domain; likely not exploitable |

High and Medium findings require the reflected host to remain attacker-controlled
(`exact` or `prefixed`). A `wrapped` reflection is reported as informational only.
Behavioural changes with a spoofed Host but no reflection are reported as notes
for manual review, not as confirmed findings.

## Installation

```
git clone https://github.com/suhelkathi/hostsweep
cd hostsweep
pip install -r requirements.txt
```

## Usage

```
# single target
python3 hostsweep.py -u https://target.com

# authenticated test
python3 hostsweep.py -u https://target.com/account -c "session=..."

# scan a list, include the cache poisoning check, export JSON
python3 hostsweep.py -l hosts.txt --cache --json results.json

# route through Burp
python3 hostsweep.py -u https://target.com -k --proxy http://127.0.0.1:8080
```

## Options

| Flag | Description |
|------|-------------|
| `-u` / `-l` | single URL or file of URLs |
| `-c` | Cookie header for authenticated scans |
| `-H` | additional request header, repeatable |
| `-v` | live per-header trace while scanning |
| `--cache` | run the web cache poisoning check |
| `-t` | concurrency (default 15) |
| `--proxy` | send traffic through a proxy such as Burp |
| `-k` | skip TLS verification |
| `--json` / `--csv` | machine-readable output |
| `--only-vuln` | show only High/Critical findings |

The process exits with code 2 when any High or Critical finding is present, which
is convenient for CI pipelines.

## Manual confirmation

```
curl -s -I https://target.com \
  -H "X-Forwarded-Host: canary.example.com" | grep -i location
```

If the injected host appears in the `Location` header or in generated links, the
application trusts client-supplied host information. For reset-poisoning impact,
trigger the password reset flow and inspect the resulting link.

## Scope and limitations

Reflection confirms that a header is trusted, but not every reflection is
independently exploitable. High-impact cases such as password-reset poisoning
require out-of-band verification (for example, reading the reset email), which an
automated scanner cannot observe. HostSweep is designed to surface confirmed
reflections precisely and leave that final verification to the tester.

## Legal

Use only against systems you are explicitly authorised to test.

## License

MIT
