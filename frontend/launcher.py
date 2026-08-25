#!/usr/bin/env python3
import argparse
import http.client
import http.server
import os
import signal
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

ROOT = os.path.dirname(os.path.abspath(__file__))
FALLBACK = os.path.join(ROOT, "fallback", "index.html")
HOST = os.environ.get("AEGISX_FRONTEND_HOST", "127.0.0.1")

class State:
    def __init__(self, upstream_port: int):
        self.upstream_port = upstream_port
        self.next_proc = None
        self.healthy = False
        self.lock = threading.Lock()

state = None

def probe(port: int) -> bool:
    try:
        c = http.client.HTTPConnection(HOST, port, timeout=1.5)
        c.request("GET", "/")
        r = c.getresponse()
        c.close()
        return 200 <= r.status < 400
    except Exception:
        return False

def load_fallback():
    try:
        with open(FALLBACK, "rb") as f:
            return f.read()
    except Exception:
        return b"<!doctype html><html><body><h1>AegisX</h1><p>Recovery UI unavailable.</p></body></html>"

class Gateway(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _fallback(self, status=200):
        body = load_fallback()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _proxy(self):
        path = self.path
        try:
            conn = http.client.HTTPConnection(HOST, state.upstream_port, timeout=8)
            headers = {k: v for k, v in self.headers.items() if k.lower() not in {"host", "content-length", "connection"}}
            headers["Host"] = f"{HOST}:{state.upstream_port}"
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else None
            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            status = resp.status
            response_headers = resp.getheaders()
            conn.close()
            if status >= 500:
                state.healthy = False
                self._fallback(200)
                return
            self.send_response(status)
            for k, v in response_headers:
                kl = k.lower()
                if kl in {"transfer-encoding", "connection", "content-length"}:
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if data:
                self.wfile.write(data)
        except Exception:
            state.healthy = False
            self._fallback(200)

    def do_GET(self):
        if state.healthy:
            self._proxy()
        else:
            self._fallback(200)

    def do_HEAD(self):
        if state.healthy:
            self._proxy()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()

    def do_POST(self):
        if state.healthy:
            self._proxy()
        else:
            self._fallback(200)

    def do_PUT(self):
        self.do_POST()

    def do_PATCH(self):
        self.do_POST()

    def do_DELETE(self):
        self.do_POST()

    def log_message(self, fmt, *args):
        sys.stdout.write("[AegisX UI] " + (fmt % args) + "\n")
        sys.stdout.flush()

def start_next(mode: str):
    next_bin = os.path.join(ROOT, "node_modules", ".bin", "next")
    if not os.path.exists(next_bin):
        print("[AegisX] Next.js dependencies unavailable; using recovery UI.", flush=True)
        return None
    args = [next_bin, mode, "-p", str(state.upstream_port), "-H", HOST]
    try:
        return subprocess.Popen(args, cwd=ROOT, env=os.environ.copy(), stdout=sys.stdout, stderr=sys.stderr)
    except Exception as exc:
        print(f"[AegisX] Could not start Next.js: {exc}", flush=True)
        return None

def monitor(proc):
    if proc is None:
        return
    deadline = time.time() + 15
    while time.time() < deadline and proc.poll() is None:
        if probe(state.upstream_port):
            state.healthy = True
            print(f"[AegisX] Next.js healthy on {HOST}:{state.upstream_port}; gateway remains on {HOST}:3000", flush=True)
            return
        time.sleep(0.5)
    state.healthy = False
    if proc.poll() is None:
        try: proc.terminate()
        except Exception: pass
    print("[AegisX] Next.js failed health check; gateway will serve recovery UI.", flush=True)

def main():
    global state
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["dev", "start"], nargs="?", default="dev")
    parser.add_argument("-p", "--port", type=int, default=3000)
    args = parser.parse_args()
    if args.port != 3000:
        print("[AegisX] Gateway is standardized on port 3000.", flush=True)
    state = State(3001)
    proc = None if os.environ.get("AEGISX_UI_MODE") == "standalone" else start_next(args.mode)
    state.next_proc = proc
    threading.Thread(target=monitor, args=(proc,), daemon=True).start()
    server = http.server.ThreadingHTTPServer((HOST, 3000), Gateway)
    print(f"[AegisX] Stable UI gateway: http://{HOST}:3000", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if proc and proc.poll() is None:
            try: proc.terminate()
            except Exception: pass

if __name__ == "__main__":
    main()
