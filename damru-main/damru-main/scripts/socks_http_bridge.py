"""Small HTTP CONNECT bridge for authenticated SOCKS5/HTTP upstreams.

Use when Android can only consume an unauthenticated host:port HTTP proxy but
the real proxy is an authenticated proxy URL. Credentials are read from
UPSTREAM_PROXY at runtime and are never stored by this script.
"""

from __future__ import annotations

import argparse
import base64
import select
import socket
import socketserver
import urllib.parse

from damru.proxy import make_sticky_proxy_url


def _parse_upstream(url: str) -> dict[str, object]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in ("socks5", "http", "https"):
        raise ValueError("UPSTREAM_PROXY must be a socks5:// or http:// URL")
    if not parsed.hostname or not parsed.port:
        raise ValueError("UPSTREAM_PROXY must include host and port")
    return {
        "host": parsed.hostname,
        "port": parsed.port,
        "scheme": parsed.scheme.lower(),
        "username": urllib.parse.unquote(parsed.username or ""),
        "password": urllib.parse.unquote(parsed.password or ""),
    }


def _read_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("unexpected EOF")
        data += chunk
    return data


def _socks_connect(upstream: dict[str, object], target_host: str, target_port: int) -> socket.socket:
    sock = socket.create_connection((str(upstream["host"]), int(upstream["port"])), timeout=20)
    username = str(upstream.get("username") or "")
    password = str(upstream.get("password") or "")

    if username or password:
        sock.sendall(b"\x05\x01\x02")
        if _read_exact(sock, 2) != b"\x05\x02":
            raise OSError("SOCKS5 auth method rejected")
        u = username.encode()
        p = password.encode()
        sock.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        if _read_exact(sock, 2) != b"\x01\x00":
            raise OSError("SOCKS5 authentication failed")
    else:
        sock.sendall(b"\x05\x01\x00")
        if _read_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS5 no-auth method rejected")

    host = target_host.encode("idna")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + int(target_port).to_bytes(2, "big"))
    resp = _read_exact(sock, 4)
    if resp[:2] != b"\x05\x00":
        raise OSError(f"SOCKS5 connect failed: {resp[1]}")
    atyp = resp[3]
    if atyp == 1:
        _read_exact(sock, 4)
    elif atyp == 3:
        _read_exact(sock, _read_exact(sock, 1)[0])
    elif atyp == 4:
        _read_exact(sock, 16)
    _read_exact(sock, 2)
    return sock


def _http_connect(upstream: dict[str, object], target_host: str, target_port: int) -> socket.socket:
    sock = socket.create_connection((str(upstream["host"]), int(upstream["port"])), timeout=20)
    username = str(upstream.get("username") or "")
    password = str(upstream.get("password") or "")
    headers = [
        f"CONNECT {target_host}:{target_port} HTTP/1.1",
        f"Host: {target_host}:{target_port}",
    ]
    if username or password:
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        headers.append(f"Proxy-Authorization: Basic {token}")
    sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("iso-8859-1"))
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError("HTTP proxy closed connection")
        response += chunk
        if len(response) > 65536:
            raise OSError("HTTP proxy response too large")
    status = response.split(b"\r\n", 1)[0]
    if b" 200 " not in status:
        raise OSError(f"HTTP proxy CONNECT failed: {status.decode('iso-8859-1', 'replace')}")
    return sock


def _upstream_connect(upstream: dict[str, object], target_host: str, target_port: int) -> socket.socket:
    if str(upstream.get("scheme")) in ("http", "https"):
        return _http_connect(upstream, target_host, target_port)
    return _socks_connect(upstream, target_host, target_port)


class ProxyHandler(socketserver.StreamRequestHandler):
    upstream: dict[str, object]

    def handle(self) -> None:
        line = self.rfile.readline(65536).decode("iso-8859-1").strip()
        if not line:
            return
        parts = line.split()
        if len(parts) < 3:
            return
        method, target, _version = parts[:3]

        headers = []
        while True:
            header = self.rfile.readline(65536)
            if header in (b"\r\n", b"\n", b""):
                break
            headers.append(header)

        if method.upper() == "CONNECT":
            host, _, port_text = target.rpartition(":")
            port = int(port_text or "443")
            remote = _upstream_connect(self.upstream, host, port)
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = urllib.parse.urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
            remote = _upstream_connect(self.upstream, host, port)
            remote.sendall(f"{method} {path} HTTP/1.1\r\n".encode("iso-8859-1"))
            for header in headers:
                if not header.lower().startswith(b"proxy-"):
                    remote.sendall(header)
            remote.sendall(b"\r\n")

        with remote:
            self._relay(self.connection, remote)

    @staticmethod
    def _relay(left: socket.socket, right: socket.socket) -> None:
        sockets = [left, right]
        while sockets:
            readable, _, _ = select.select(sockets, [], [], 60)
            if not readable:
                return
            for sock in readable:
                data = sock.recv(65536)
                if not data:
                    return
                (right if sock is left else left).sendall(data)


class ThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser(description="Bridge local HTTP CONNECT to authenticated SOCKS5")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18888)
    parser.add_argument("--upstream", default=None)
    args = parser.parse_args()

    import os

    upstream_url = args.upstream or os.environ.get("UPSTREAM_PROXY")
    if not upstream_url:
        raise SystemExit("UPSTREAM_PROXY is required")

    upstream_url = make_sticky_proxy_url(upstream_url) or upstream_url
    ProxyHandler.upstream = _parse_upstream(upstream_url)
    with ThreadingServer((args.listen, args.port), ProxyHandler) as server:
        print(f"listening on {args.listen}:{args.port}", flush=True)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
