"""Small local HTTP CONNECT bridge for Android system proxy auth.

Android's global proxy setting stores only host:port.  When the upstream
proxy requires username/password, Chrome shows a proxy sign-in dialog.  This
bridge listens without auth on the Docker/WSL host and forwards to the real
authenticated upstream proxy.
"""
from __future__ import annotations

import argparse
import base64
import json
import select
import socket
import socketserver
import sys
from dataclasses import dataclass
from urllib.parse import unquote, urlparse


@dataclass(frozen=True)
class Upstream:
    scheme: str
    host: str
    port: int
    username: str | None
    password: str | None
    auth_header: str | None


def _parse_upstream(value: str) -> Upstream:
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "socks5", "socks5h"}:
        raise ValueError("proxy bridge supports HTTP and SOCKS5 upstream proxies")
    if not parsed.hostname or not parsed.port:
        raise ValueError("upstream proxy must include host and port")
    user = unquote(parsed.username) if parsed.username is not None else None
    password = unquote(parsed.password or "") if parsed.username is not None else None
    auth_header = None
    if user is not None and scheme in {"http", "https"}:
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        auth_header = f"Proxy-Authorization: Basic {token}\r\n"
    return Upstream(scheme, parsed.hostname, int(parsed.port), user, password, auth_header)


def _recv_headers(sock: socket.socket, limit: int = 1024 * 1024) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise OSError("request headers too large")
    return data


def _inject_proxy_auth(headers: bytes, auth_header: str | None) -> bytes:
    if not auth_header:
        return headers
    head, sep, body = headers.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    kept = [line for line in lines if not line.lower().startswith(b"proxy-authorization:")]
    return b"\r\n".join([*kept, auth_header.rstrip("\r\n").encode("ascii")]) + sep + body


def _relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, _ = select.select(sockets, [], [], 300)
        if not readable:
            return
        for src in readable:
            dst = right if src is left else left
            data = src.recv(65536)
            if not data:
                return
            dst.sendall(data)


def _socks5_connect(upstream: Upstream, target_host: str, target_port: int) -> socket.socket:
    sock = socket.create_connection((upstream.host, upstream.port), timeout=30)
    sock.settimeout(30)
    methods = b"\x00"
    if upstream.username is not None:
        methods += b"\x02"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    response = sock.recv(2)
    if len(response) != 2 or response[0] != 5 or response[1] == 0xFF:
        sock.close()
        raise OSError("SOCKS5 method negotiation failed")
    if response[1] == 0x02:
        user = (upstream.username or "").encode("utf-8")
        password = (upstream.password or "").encode("utf-8")
        if len(user) > 255 or len(password) > 255:
            sock.close()
            raise OSError("SOCKS5 credentials too long")
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        auth = sock.recv(2)
        if len(auth) != 2 or auth[1] != 0:
            sock.close()
            raise OSError("SOCKS5 authentication failed")

    host_bytes = target_host.encode("idna")
    if len(host_bytes) > 255:
        sock.close()
        raise OSError("target hostname too long")
    req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + target_port.to_bytes(2, "big")
    sock.sendall(req)
    head = sock.recv(4)
    if len(head) != 4 or head[1] != 0:
        sock.close()
        raise OSError("SOCKS5 connect failed")
    atyp = head[3]
    if atyp == 1:
        to_read = 4
    elif atyp == 3:
        to_read = sock.recv(1)[0]
    elif atyp == 4:
        to_read = 16
    else:
        sock.close()
        raise OSError("SOCKS5 bad address type")
    remaining = to_read + 2
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            sock.close()
            raise OSError("SOCKS5 response truncated")
        remaining -= len(chunk)
    return sock


def _connect_target_via_upstream(upstream: Upstream, first_line: str) -> socket.socket:
    if first_line.upper().startswith("CONNECT "):
        target = first_line.split(" ", 2)[1]
        host, _, port_text = target.rpartition(":")
        return _socks5_connect(upstream, host, int(port_text or 443))
    parsed = urlparse(first_line.split(" ", 2)[1])
    if not parsed.hostname:
        raise OSError("HTTP proxy request missing absolute URL")
    return _socks5_connect(upstream, parsed.hostname, parsed.port or 80)


class BridgeHandler(socketserver.BaseRequestHandler):
    upstream: Upstream

    def handle(self) -> None:
        client = self.request
        client.settimeout(30)
        headers = _recv_headers(client)
        if not headers:
            return
        first = headers.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
        method = first.split(" ", 1)[0].upper()

        if self.upstream.scheme in {"socks5", "socks5h"}:
            upstream = _connect_target_via_upstream(self.upstream, first)
            with upstream:
                if method == "CONNECT":
                    client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    _relay(client, upstream)
                    return
                upstream.sendall(headers)
                _relay(client, upstream)
                return

        with socket.create_connection((self.upstream.host, self.upstream.port), timeout=30) as upstream:
            upstream.settimeout(30)
            if method == "CONNECT":
                upstream.sendall(_inject_proxy_auth(headers, self.upstream.auth_header))
                response = _recv_headers(upstream)
                client.sendall(response)
                if b" 200 " not in response.split(b"\r\n", 1)[0]:
                    return
                _relay(client, upstream)
                return

            upstream.sendall(_inject_proxy_auth(headers, self.upstream.auth_header))
            _relay(client, upstream)


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    with open(args.config, "r", encoding="utf-8") as fh:
        config = json.load(fh)
    upstream = _parse_upstream(config["upstream"])
    host = str(config.get("listen_host") or "0.0.0.0")
    port = int(config["listen_port"])
    BridgeHandler.upstream = upstream
    with ThreadingTCPServer((host, port), BridgeHandler) as server:
        print(f"damru proxy bridge listening on {host}:{port} -> {upstream.host}:{upstream.port}", flush=True)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
