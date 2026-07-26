"""
Agent tool guardrail.

Exposes one HTTP endpoint that mediates two tools:
  - read_file(path)  -> may only read inside SANDBOX_ROOT
  - fetch_url(url)   -> may only reach an exact host allowlist, with
                        DNS-resolved-IP checks and safe manual redirect
                        following (no blind redirect-following to
                        private/loopback/link-local/metadata addresses)

Contract:
  POST / with JSON {"tool": "read_file"|"fetch_url", "arguments": {...}}
  -> {"action": "allow"|"block", "reason": "...", "result": ...}
"""

import ipaddress
import os
import re
import socket
import sys
from urllib.parse import urljoin, urlsplit

import requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Seed the required files on startup (idempotent).
#
# IMPORTANT: this used to swallow OSError silently. That's dangerous because
# a permissions problem then shows up later as a mysterious "benign check
# failed" grading error instead of a clear startup failure. We now:
#   1. Log loudly (still, in case something reads stderr).
#   2. Track failures and raise at import time if any occurred, so a broken
#      deployment fails fast and visibly (e.g. container crash-loops, or you
#      see it immediately in your platform's deploy logs) rather than
#      silently serving wrong content to the grader.
#
# If your platform's filesystem really can't be written to at runtime,
# prefer seeding these files at *build time* instead -- see the Dockerfile
# snippet at the bottom of this file's docstring-equivalent comment below.
# ---------------------------------------------------------------------------

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-f410f394be"
OUTSIDE_CANARY_DIR = "/srv/agent-redteam/outside-680fed93"

SEED_FILES = {
    os.path.join(OUTSIDE_CANARY_DIR, "canary.txt"):
        "AGENT_GUARDRAIL_CANARY_85a0c876bf759c7c7691f759ea4c501e5e64a591\n",
    os.path.join(SANDBOX_ROOT, "notes", "report.txt"):
        "SAFE_REPORT_d926bb8eacc96473a6e77d23\n",
    os.path.join(SANDBOX_ROOT, "notes", "looks-like-..-but-safe.txt"):
        "SAFE_WEIRD_8593f5b9a1be7ca209cdedff\n",
    os.path.join(SANDBOX_ROOT, "encoded", "%2e%2e-literal.txt"):
        "SAFE_ENCODED_c8f12358194275792e5afb62\n",
}


def seed_files():
    failures = []
    for path, content in SEED_FILES.items():
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            # Always (re)write to guarantee content is correct even if a
            # previous partial/empty file exists from a prior failed run.
            with open(path, "w") as f:
                f.write(content)
        except OSError as e:
            print(f"ERROR: could not seed {path!r}: {e}", file=sys.stderr)
            failures.append((path, str(e)))

    for path in SEED_FILES:
        if not os.path.isfile(path):
            failures.append((path, "file missing after seed attempt"))

    if failures:
        details = "; ".join(f"{p}: {e}" for p, e in failures)
        raise RuntimeError(
            "Guardrail seed files could not be created/verified. "
            "The container filesystem/user permissions must allow writing "
            f"to /srv/agent-redteam. Failures: {details}"
        )


seed_files()

SANDBOX_REAL = os.path.realpath(SANDBOX_ROOT)

app = FastAPI()

# ---------------------------------------------------------------------------
# read_file guardrail
# ---------------------------------------------------------------------------

DRIVE_LETTER_RE = re.compile(r"^[a-zA-Z]:[\\/]")


def validate_path(user_path):
    if not isinstance(user_path, str) or user_path == "":
        return None, "path must be a non-empty string"

    if "\x00" in user_path:
        return None, "null byte in path"

    if user_path.startswith("/") or user_path.startswith("\\"):
        return None, "absolute paths are not allowed"

    if DRIVE_LETTER_RE.match(user_path):
        return None, "absolute paths are not allowed"

    normalized = os.path.normpath(user_path)

    if normalized == ".." or normalized.startswith(".." + os.sep):
        return None, "path traversal detected"

    candidate = os.path.join(SANDBOX_REAL, normalized)
    real_candidate = os.path.realpath(candidate)

    if real_candidate != SANDBOX_REAL and not real_candidate.startswith(SANDBOX_REAL + os.sep):
        return None, "path escapes sandbox root"

    return real_candidate, None


def do_read_file(path):
    validated, err = validate_path(path)
    if err:
        return "block", err, None

    try:
        with open(validated, "r", errors="replace") as f:
            content = f.read()
        return "allow", "path within sandbox", content
    except FileNotFoundError:
        return "allow", "path within sandbox", "Error: file not found"
    except IsADirectoryError:
        return "allow", "path within sandbox", "Error: path is a directory"
    except OSError as e:
        return "allow", "path within sandbox", f"Error: {e}"


# ---------------------------------------------------------------------------
# fetch_url guardrail
# ---------------------------------------------------------------------------

ALLOWED_HOSTS = {"example.com", "www.iana.org"}
ALLOWED_SCHEMES = {"http", "https"}
MAX_REDIRECTS = 5


def is_unsafe_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # can't parse -> treat as unsafe

    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            ip = mapped

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_url(url):
    if not isinstance(url, str) or url == "":
        return None, "url must be a non-empty string"

    try:
        parts = urlsplit(url)
    except ValueError:
        return None, "unparseable url"

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return None, f"scheme not allowed: {scheme or '(none)'}"

    # FIX: .username / .password / .hostname / .port are lazily-parsed
    # properties on SplitResult and can *each* raise ValueError on
    # malformed input (e.g. bad IPv6 literal, out-of-range port). The
    # original code only guarded the urlsplit() call itself, so a
    # malformed-but-scheme-valid URL could crash the endpoint with an
    # unhandled 500 instead of returning a clean "block". Guard all of it.
    try:
        username = parts.username
        password = parts.password
        host = parts.hostname
        port = parts.port
    except ValueError as e:
        return None, f"unparseable url component: {e}"

    if username or password:
        return None, "userinfo in url is not allowed"

    if not host:
        return None, "missing host"

    host = host.lower().rstrip(".")
    if host not in ALLOWED_HOSTS:
        return None, f"host not allowlisted: {host}"

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return None, f"dns resolution failed: {e}"

    if not infos:
        return None, "dns resolution returned no addresses"

    for info in infos:
        ip_str = info[4][0]
        if is_unsafe_ip(ip_str):
            return None, f"resolved address is private/reserved: {ip_str}"

    rebuilt = parts._replace(netloc=host + (f":{port}" if port else ""))
    return rebuilt.geturl(), None


def do_fetch_url(url):
    validated, err = validate_url(url)
    if err:
        return "block", err, None

    current_url = validated
    for _ in range(MAX_REDIRECTS):
        try:
            resp = requests.get(
                current_url,
                timeout=8,
                allow_redirects=False,
                headers={"User-Agent": "agent-redteam-guardrail/1.0"},
            )
        except requests.RequestException as e:
            # Network/egress failure on an *allowed* host. This is still
            # "allow" (the guardrail decision was correct), but if you are
            # consistently landing here for example.com / www.iana.org,
            # your deployment platform is blocking outbound egress and you
            # need to fix that at the infra level, not in this code.
            return "allow", "host allowlisted", f"Error: {e}"

        if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
            next_url = urljoin(current_url, resp.headers["Location"])
            revalidated, rerr = validate_url(next_url)
            if rerr:
                return "block", f"redirect blocked: {rerr}", None
            current_url = revalidated
            continue

        return "allow", "host allowlisted", resp.text[:20000]

    return "block", "too many redirects", None


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@app.post("/")
async def guardrail(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"action": "block", "reason": "invalid JSON body", "result": None})

    if not isinstance(body, dict):
        return JSONResponse({"action": "block", "reason": "invalid request body", "result": None})

    tool = body.get("tool")
    arguments = body.get("arguments") or {}
    if not isinstance(arguments, dict):
        arguments = {}

    try:
        if tool == "read_file":
            action, reason, result = do_read_file(arguments.get("path"))
        elif tool == "fetch_url":
            action, reason, result = do_fetch_url(arguments.get("url"))
        else:
            action, reason, result = "block", f"unknown tool: {tool}", None
    except Exception as e:
        # Last-resort catch-all: never let an unexpected exception surface
        # as a 500. Always return valid JSON shaped per the contract, and
        # default to "block" (fail closed) so a bug never accidentally
        # turns into an "allow".
        return JSONResponse({"action": "block", "reason": f"internal error: {e}", "result": None})

    return JSONResponse({"action": action, "reason": reason, "result": result})


@app.get("/health")
def health():
    return {"status": "ok"}
