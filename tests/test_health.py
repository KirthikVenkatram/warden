import http.client
import threading

import pytest

from slack_app import health


@pytest.fixture
def running_server():
    server = health.create_server(0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_health_route_returns_200_ok(running_server):
    conn = http.client.HTTPConnection("127.0.0.1", running_server, timeout=5)
    conn.request("GET", "/health")
    resp = conn.getresponse()
    body = resp.read()
    assert resp.status == 200
    assert body == b"ok"


def test_unknown_route_returns_404(running_server):
    conn = http.client.HTTPConnection("127.0.0.1", running_server, timeout=5)
    conn.request("GET", "/nope")
    resp = conn.getresponse()
    resp.read()
    assert resp.status == 404
