#!/usr/bin/env python3
"""Minimal ndjson RPC client for the Ghidra function-command server.

Usage:
  python3 rpc_client.py <port> '<json-array-of-requests>'
Each array element is one request object; one response line is printed per request.
"""
import json
import socket
import sys


def call(requests, port, host="127.0.0.1", timeout=120):
    s = socket.create_connection((host, port), timeout=timeout)
    f = s.makefile("rwb")
    out = []
    try:
        for r in requests:
            f.write((json.dumps(r) + "\n").encode())
            f.flush()
            line = f.readline()
            out.append(json.loads(line.decode()) if line else {"_eof": True})
    finally:
        s.close()
    return out


if __name__ == "__main__":
    port = int(sys.argv[1])
    reqs = json.loads(sys.argv[2])
    for resp in call(reqs, port):
        print(json.dumps(resp))
