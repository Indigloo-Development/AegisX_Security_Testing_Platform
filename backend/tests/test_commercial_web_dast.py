from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from app.commercial.dast.authenticated import AuthenticatedWebScanner
from app.commercial.models import AuthProfile, ScanPolicy

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/search'):
            body = '<html><a href="/next">next</a><form action="/login" method="POST"><input name="password"></form><p>' + self.path + '</p></html>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body.encode())
        else:
            body = '<html><a href="/search?q=hello">search</a></html>'
            self.send_response(200); self.send_header('Content-Type','text/html'); self.end_headers(); self.wfile.write(body.encode())
    def log_message(self, *args):
        pass

def test_deep_web_reflection_and_discovery():
    server = HTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        url = f'http://127.0.0.1:{server.server_port}/search?q=hello'
        result = AuthenticatedWebScanner(ScanPolicy(max_pages=5, max_requests=10), AuthProfile(name='qa', bearer_token='secret')).run(url)
        keys = {x['finding_key'] for x in result.findings}
        assert 'DAST-INPUT-001' in keys
        assert result.discovered_urls
        assert all('secret' not in str(x) for x in result.__dict__.values()) is True
    finally:
        server.shutdown(); server.server_close()
