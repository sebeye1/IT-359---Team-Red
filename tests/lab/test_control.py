"""Tests for lab/control.py: starting the practice lab on demand."""

import socket

from webrecon.lab.control import ensure_local_server, port_open


def test_auto_lab_starts_and_reuses_server():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    assert not port_open("127.0.0.1", port)
    server = ensure_local_server(f"http://127.0.0.1:{port}", hardened=False)
    try:
        assert server is not None and port_open("127.0.0.1", port)
        assert ensure_local_server(f"http://127.0.0.1:{port}", hardened=False) is None
    finally:
        server.shutdown()
        server.server_close()


def test_auto_lab_ignores_remote_targets():
    assert ensure_local_server("http://example.com:8080", hardened=False) is None
