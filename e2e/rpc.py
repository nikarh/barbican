#!/usr/bin/env python3
"""Calls one method of barbican's WebSocket RPC and prints the result as JSON (exit status 1 on an error).

    rpc.py [--socket /run/barbican-ui/ui.sock | --url ws://127.0.0.1:8080/api/ws] [-H 'Name: value']... <method>
           [<params as JSON>]

By default over the agent's UI socket (only root, the agent's user and members of its group may use it); with --url
over TCP, through `barbican ui-proxy`.

Only the standard library: a minimal WebSocket client (text frames, masked, no extensions)."""

import base64
import json
import os
import socket
import struct
import sys
from urllib.parse import urlparse


def connect(url, unix, headers):
    if unix is not None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect(unix)
        host, path = "localhost", "/api/ws"
    else:
        u = urlparse(url)
        sock = socket.create_connection((u.hostname, u.port or 80), timeout=30)
        host, path = f"{u.hostname}:{u.port}", u.path or "/"
    key = base64.b64encode(os.urandom(16)).decode()
    extra = "".join(f"{h}\r\n" for h in headers)
    sock.sendall(
        (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
        ).encode()
    )
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise SystemExit("connection closed during the handshake")
        response += chunk
    if b" 101 " not in response.split(b"\r\n", 1)[0]:
        raise SystemExit(f"handshake refused: {response.splitlines()[0]!r}")
    return sock, response.split(b"\r\n\r\n", 1)[1]


def send(sock, text):
    payload = text.encode()
    header = bytearray([0x81])
    n = len(payload)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        header += bytes([0x80 | 127]) + struct.pack(">Q", n)
    mask = os.urandom(4)
    sock.sendall(bytes(header) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def frames(sock, buffer):
    while True:
        while len(buffer) < 2:
            buffer += sock.recv(65536)
        opcode, n = buffer[0] & 0x0F, buffer[1] & 0x7F
        offset = 2
        if n == 126:
            while len(buffer) < 4:
                buffer += sock.recv(65536)
            n, offset = struct.unpack(">H", buffer[2:4])[0], 4
        elif n == 127:
            while len(buffer) < 10:
                buffer += sock.recv(65536)
            n, offset = struct.unpack(">Q", buffer[2:10])[0], 10
        while len(buffer) < offset + n:
            buffer += sock.recv(65536)
        payload, buffer = buffer[offset : offset + n], buffer[offset + n :]
        if opcode == 1:
            yield payload.decode()
        elif opcode == 8:
            return


def main():
    args = sys.argv[1:]
    url, unix, headers = None, "/run/barbican-ui/ui.sock", []
    while args[:1] in (["--url"], ["--socket"], ["-H"]):
        if args[0] == "--url":
            url, unix = args[1], None
        elif args[0] == "--socket":
            unix = args[1]
        else:
            headers.append(args[1])
        args = args[2:]
    method = args[0]
    request = {"id": "1", "method": method}
    if len(args) > 1:
        request["params"] = json.loads(args[1])
    sock, rest = connect(url, unix, headers)
    send(sock, json.dumps(request))
    for text in frames(sock, rest):
        message = json.loads(text)
        if message.get("id") != "1":
            continue
        if message["type"] == "error":
            print(json.dumps(message["error"]), file=sys.stderr)
            sys.exit(1)
        print(json.dumps(message.get("result")))
        return


if __name__ == "__main__":
    main()
