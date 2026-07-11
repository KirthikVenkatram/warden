"""Minimal HTTP health endpoint for Render's free Web Service tier.

Render's free plan requires a bound HTTP port to consider a deploy healthy. Warden's
real functionality runs entirely over Slack Socket Mode (outbound only) and needs no
inbound HTTP — this exists solely to satisfy that platform requirement.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        pass  # keep request noise out of app logs


def create_server(port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("0.0.0.0", port), HealthHandler)


def run(port: int) -> None:
    server = create_server(port)
    server.serve_forever()
