import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Routes served by the live test server:
#   /a, /b        -> identical body (should group together at every level)
#   /c            -> different body (own level-1 group)
#   /status/418   -> same body as /a but different status (same L1, different L2)
#   /redirect     -> 302 redirect (komsu must not follow it)
ROUTES = {
    '/a': (200, 'OK', 'hello world', {}),
    '/b': (200, 'OK', 'hello world', {}),
    '/c': (200, 'OK', 'different body', {}),
    '/status/418': (418, "I'm a Teapot", 'hello world', {}),
    '/redirect': (302, 'Found', '', {'Location': '/a'}),
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = ROUTES.get(self.path)
        if route is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'not found')
            return
        status, _reason, body, extra_headers = route
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain')
        for name, value in extra_headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


@pytest.fixture(scope='session')
def live_server():
    """A real local HTTP server; yields its base URL, e.g. 'http://127.0.0.1:51234'."""
    server = HTTPServer(('127.0.0.1', 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{server.server_port}'
    server.shutdown()
    thread.join()
