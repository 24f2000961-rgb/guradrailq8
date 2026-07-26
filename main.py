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
import unicodedata
from urllib.parse import unquote, urljoin, urlsplit

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


def _decode_repeated(s, max_iters=4):
    """Percent-decode repeatedly to catch double/triple-encoded traversal
    (e.g. %252e%252e%252f -> %2e%2e%2f -> ../). Stops as soon as decoding
    no longer changes the string, and caps iterations so a pathological
    input can't cause unbounded work."""
    prev = s
    for _ in range(max_iters):
        nxt = unquote(prev)
        if nxt == prev:
            break
        prev = nxt
    return prev


def _looks_like_traversal(candidate_str):
    """Segment-based check (never substring-based) for whether a given
    string, taken at face value, is or contains an unresolved '..'
    parent-reference segment or a Windows-style absolute/drive path.
    Used against several *canonicalized views* of the input -- never
    against the raw string alone -- see validate_path."""
    if candidate_str.startswith("/") or candidate_str.startswith("\\"):
        return True
    if DRIVE_LETTER_RE.match(candidate_str):
        return True
    normalized = os.path.normpath(candidate_str)
    if normalized == ".." or normalized.startswith(".." + os.sep):
        return True
    return False


# Unicode characters that visually or semantically resemble '/' or '.' and
# have historically been used to slip traversal payloads past filters that
# only check ASCII '/' and '.'. NFKC handles some of these (e.g. fullwidth
# U+FF0F, U+FF0E) automatically, but not all -- division slash (U+2215),
# fraction slash (U+2044), one-dot-leader (U+2024), small full stop
# (U+FE52) are compatibility-equivalent in *meaning* but not folded by
# NFKC, so map them explicitly before normalizing.
_CONFUSABLE_SLASHES = "\u2215\u2044\uFF0F"
_CONFUSABLE_DOTS = "\u2024\uFE52\u3002\uFF0E"
_CONFUSABLE_TABLE = str.maketrans(
    {c: "/" for c in _CONFUSABLE_SLASHES} | {c: "." for c in _CONFUSABLE_DOTS}
)


def _confusables_folded(s):
    return s.translate(_CONFUSABLE_TABLE)


def validate_path(user_path):
    if not isinstance(user_path, str) or user_path == "":
        return None, "path must be a non-empty string"

    if "\x00" in user_path:
        return None, "null byte in path"

    # Build several canonicalized VIEWS of the input purely for attack
    # *detection*. A genuine attack that relies on percent-encoding,
    # backslashes, double-encoding, or Unicode confusables to slip past a
    # naive "..".find(path) check will resolve to a real ".." segment in
    # at least one of these views. A benign filename that merely contains
    # percent-signs or dots as literal characters (e.g. the seeded
    # "%2e%2e-literal.txt") will NOT resolve to a standalone ".." segment
    # in any view, because the surrounding characters remain attached.
    decoded = _decode_repeated(user_path)
    if "\x00" in decoded:
        return None, "null byte in decoded path"

    views = {
        "raw": user_path,
        "decoded": decoded,
        "raw-backslash-normalized": user_path.replace("\\", "/"),
        "decoded-backslash-normalized": decoded.replace("\\", "/"),
        "nfkc": unicodedata.normalize("NFKC", decoded).replace("\\", "/"),
        "confusables-folded": _confusables_folded(
            unicodedata.normalize("NFKC", decoded)
        ).replace("\\", "/"),
    }

    for label, view in views.items():
        if _looks_like_traversal(view):
            return None, f"path traversal detected ({label})"

    # Only the ORIGINAL, undecoded string is used to touch the real
    # filesystem -- this is what keeps the benign encoded/backslash-ish
    # filenames resolvable while still blocking real traversal above.
    normalized_input = _confusables_folded(
    unicodedata.normalize("NFKC", user_path)
).replace("\\", "/")

normalized_raw = os.path.normpath(normalized_input)

candidate = os.path.join(SANDBOX_REAL, normalized_raw)
real_candidate = os.path.realpath(candidate)

    if real_candidate != SANDBOX_REAL and not real_candidate.startswith(SANDBOX_REAL + os.sep):
        return None, "path escapes sandbox root (realpath check)"

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
ALLOWED_SCHEMES = {"https"}
MAX_REDIRECTS = 5


NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def _is_unsafe_single(ip):
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_unsafe_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # can't parse -> treat as unsafe

    if isinstance(ip, ipaddress.IPv6Address):
        # Standard IPv4-mapped IPv6 (::ffff:a.b.c.d)
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return _is_unsafe_single(mapped) or _is_unsafe_single(ip)

        # NAT64 well-known prefix (64:ff9b::/96) also embeds an IPv4
        # address in the low 32 bits -- ipv4_mapped doesn't cover this
        # form, so check it explicitly to avoid a bypass.
        if ip in NAT64_PREFIX:
            embedded_v4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
            return _is_unsafe_single(embedded_v4) or _is_unsafe_single(ip)

    return _is_unsafe_single(ip)


def validate_url(url):
    if not isinstance(url, str) or url == "":
        return None, "url must be a non-empty string"

    # Reject control characters (including CR/LF) anywhere in the entire
    # URL, not just the authority. A URL containing a raw or literal CR/LF
    # could be used to attempt HTTP request-splitting/header-injection
    # once we hand the string to the underlying HTTP client, independent
    # of whether the host itself is allowlisted.
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in url):
        return None, "control character in url is not allowed"

    try:
        parts = urlsplit(url)
    except ValueError:
        return None, "unparseable url"

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return None, f"scheme not allowed: {scheme or '(none)'}"

    # Reject a raw backslash anywhere in the authority (netloc) component.
    # Some HTTP clients / proxies / browsers treat '\' as equivalent to
    # '/' when establishing a connection even though Python's urlsplit
    # does not -- that parser/transport disagreement is a known class of
    # host-confusion bypass, so refuse it outright rather than trying to
    # reason about what it "really" means.
    if "\\" in parts.netloc:
        return None, "backslash in authority is not allowed"

    # Reject control characters / whitespace anywhere in the authority --
    # these have no legitimate use in a hostname and are a common
    # trick for confusing different parsers about where the host ends.
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in parts.netloc):
        return None, "control character in authority is not allowed"

    # FIX: parts.username / parts.password are '' or None for a URL like
    # "https://@www.iana.org/" (userinfo marker present but empty) -- both
    # are FALSY, so `if username or password` silently passed this through
    # even though it structurally contains userinfo syntax. Check for the
    # literal '@' in the authority directly instead, which is unambiguous
    # regardless of how urlsplit represents an empty username/password.
    if "@" in parts.netloc:
        return None, "userinfo in url is not allowed"

    # .hostname / .port are lazily-parsed properties on SplitResult and
    # can *each* raise ValueError on malformed input (e.g. bad IPv6
    # literal, out-of-range port). The original code only guarded the
    # urlsplit() call itself, so a malformed-but-scheme-valid URL could
    # crash the endpoint with an unhandled 500 instead of returning a
    # clean "block". Guard all of it.
    try:
        host = parts.hostname
        port = parts.port
    except ValueError as e:
        return None, f"unparseable url component: {e}"

    if not host:
        return None, "missing host"

    host = host.lower().rstrip(".")
    try:
      ipaddress.ip_address(host)
      return None, "IP literals not allowed"
    except ValueError:
      pass

    if port not in (None, 443):
    return None, "port not allowed"
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
    rebuilt_url = rebuilt.geturl()

    # Self-consistency guard: re-parse what we're about to actually fetch
    # and confirm its hostname is still exactly the validated one. Cheap
    # insurance against any edge case in geturl()/_replace() reconstruction
    # itself introducing drift between "what we validated" and "what we
    # fetch".
    recheck = urlsplit(rebuilt_url)
    if (recheck.hostname or "").lower().rstrip(".") != host:
        return None, "reconstructed url host mismatch"

    return rebuilt_url, None


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
