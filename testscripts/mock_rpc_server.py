#!/usr/bin/env python3
"""Mock ndjson RPC server for exercising the Rust CLI client.

Listens on 127.0.0.1:<port>, reads one JSON line per connection, echoes the
received request to stderr, and replies with a canned response chosen by an
env-configured mode:
  MODE=ok    -> {"success": true}
  MODE=err   -> {"success": false, "error": "<MSG>"}
  MODE=rich  -> a decompile-style response echoing back the request fields
"""
import json
import os
import socket
import sys

PORT = int(os.environ.get("PORT", "18999"))
MODE = os.environ.get("MODE", "ok")
MSG = os.environ.get("MSG", "mock failure")

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(8)
print(f"mock listening on {PORT} mode={MODE}", file=sys.stderr, flush=True)

while True:
    conn, _ = srv.accept()
    with conn:
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        line = buf.decode("utf-8").strip()
        print(f"REQUEST: {line}", file=sys.stderr, flush=True)
        try:
            req = json.loads(line)
        except Exception as e:
            req = {"_parse_error": str(e)}
        if MODE == "ok":
            resp = {"success": True}
        elif MODE == "err":
            resp = {"success": False, "error": MSG}
        elif MODE == "rich":
            resp = {
                "success": True,
                "function": "FUN_00401000",
                "address": req.get("address", "?"),
                "decompilation": "int main(void) {\n  return 0; /* é */\n}",
            }
        elif MODE == "disasm":
            resp = {
                "success": True,
                "function": "FUN_00401000",
                "address": req.get("address", "?"),
                "count": 3,
                "instructions": [
                    {"address": "00401000", "bytes": "55", "mnemonic": "PUSH",
                     "representation": "PUSH EBP"},
                    {"address": "00401001", "bytes": "8bec", "mnemonic": "MOV",
                     "representation": "MOV EBP,ESP"},
                    # no "bytes" -> exercise the omitted-bytes path
                    {"address": "00401003", "mnemonic": "CALL",
                     "representation": "CALL FUN_004100b0"},
                ],
            }
        else:
            resp = {"success": False, "error": "unknown mode"}
        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
