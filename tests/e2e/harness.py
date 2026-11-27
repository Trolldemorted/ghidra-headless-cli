"""Shared plumbing for the end-to-end tests.

One real RPC server is started for the whole test run, on a throwaway LOCAL
Ghidra project (no Ghidra Server involved, so nothing here can touch a shared
repository). Tests talk to it either through the CLI binary, like a user
would, or over a raw socket when the point is the wire protocol itself.

Environment:
  GHIDRA_HOME (or GHIDRA_INSTALL)  Ghidra installation to run against (required)
  GHIDRA_CLI                       CLI binary [default: the release build in this repo]
  E2E_KEEP=1                       keep the temporary project and server log
"""

import atexit
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURE = os.path.join(REPO, "tests", "e2e", "fixture", "fixture")
WRITE_PASSWORD = "write-secret-for-tests"
ADMIN_PASSWORD = "admin-secret-for-tests"
# Small on purpose, so the oversized-request test does not need to send much.
MAX_REQUEST_BYTES = 1 << 20
STARTUP_TIMEOUT_S = 300


class Result:
    """Outcome of one CLI invocation."""

    def __init__(self, proc):
        self.code = proc.returncode
        self.out = proc.stdout
        self.err = proc.stderr

    @property
    def ok(self):
        return self.code == 0

    @property
    def text(self):
        """stdout and stderr together, for 'does it mention X' checks."""
        return self.out + self.err

    def __repr__(self):
        return "exit=%d\n--- stdout\n%s--- stderr\n%s" % (self.code, self.out, self.err)


def ghidra_home():
    """The Ghidra installation under test; skips the calling test if there is none."""
    ghidra = os.environ.get("GHIDRA_HOME") or os.environ.get("GHIDRA_INSTALL")
    if not ghidra or not os.path.isdir(os.path.join(ghidra, "Ghidra")):
        raise unittest.SkipTest("set GHIDRA_HOME to a Ghidra installation to run the e2e tests")
    return os.path.abspath(ghidra)


def cli_binary():
    """The CLI binary under test; skips the calling test if it is missing."""
    cli = os.environ.get("GHIDRA_CLI") or os.path.join(
        REPO, "ghidra-headless-cli", "target", "release", "ghidra-headless-cli")
    if not os.path.isfile(cli):
        raise unittest.SkipTest("CLI binary not found at %s (cargo build --release)" % cli)
    return cli


def kill_group(proc, sig=signal.SIGTERM, timeout=30):
    """Signal a process started with start_new_session=True, and its whole
    group; escalate to SIGKILL if it does not exit within `timeout`."""
    if proc is None:
        return
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, sig)
            proc.wait(timeout=timeout)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=30)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
    # The leader may be a shell whose JVM child outlives it by a moment (and
    # still holds its listening socket): wait for the whole group to be gone.
    deadline = time.time() + timeout
    killed = False
    while _group_alive(proc.pid):
        if time.time() >= deadline:
            if killed:
                return  # unkillable; nothing more we can do
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                return
            killed = True
            deadline = time.time() + 30
        time.sleep(0.1)


def _group_alive(pgid):
    """Whether any non-zombie process is left in process group `pgid`."""
    if not os.path.isdir("/proc/self"):
        try:
            os.killpg(pgid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % entry) as f:
                stat = f.read()
        except OSError:
            continue
        # pid (comm) state ppid pgrp ...; comm may contain spaces/parens.
        fields = stat[stat.rfind(")") + 2:].split()
        if len(fields) < 3 or fields[2] != str(pgid):
            continue
        if fields[0] != "Z":
            return True
        # A zombie leader of a multi-threaded process (a JVM) is still tearing
        # down its other threads, and still holds its sockets, until it is
        # the last task left.
        try:
            if len(os.listdir("/proc/%s/task" % entry)) > 1:
                return True
        except OSError:
            pass
    return False


class Server:
    """A running RPC server on a temporary local project."""

    # Name prefix of the programs fresh_program() imports.
    PROGRAM_PREFIX = "p"

    def __init__(self):
        ghidra = ghidra_home()
        self.cli = cli_binary()

        self.dir = tempfile.mkdtemp(prefix="ghidra-rpc-e2e-")
        self.log = os.path.join(self.dir, "server.log")
        self.port = _free_port()
        env = dict(os.environ)
        env.update({
            # A private HOME keeps Ghidra's per-user settings and script cache
            # out of the real one (and makes the run independent of it).
            "HOME": os.path.join(self.dir, "home"),
            "RPC_BIND": "127.0.0.1",
            "RPC_PORT": str(self.port),
            "GHIDRA_RPC_WRITE_PASSWORD": WRITE_PASSWORD,
            "GHIDRA_RPC_ADMIN_PASSWORD": ADMIN_PASSWORD,
            "RPC_MAX_REQUEST_BYTES": str(MAX_REQUEST_BYTES),
        })
        os.makedirs(env["HOME"])
        with open(self.log, "wb") as log:
            self.proc = subprocess.Popen(
                [os.path.join(ghidra, "support", "analyzeHeadless"),
                 os.path.join(self.dir, "project"), "E2E", "-noanalysis",
                 "-scriptPath", os.path.join(REPO, "ghidra-rpc-server"),
                 "-preScript", "RpcServer.java"],
                stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                env=env, cwd=self.dir,
                # Own process group: analyzeHeadless is a shell chain around the
                # JVM, and stop() must take all of it down.
                start_new_session=True)
        os.makedirs(os.path.join(self.dir, "project"), exist_ok=True)
        self._wait_until_listening()
        self._counter = 0
        self._analyzed = None

    def _wait_until_listening(self):
        deadline = time.time() + STARTUP_TIMEOUT_S
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("RPC server exited during startup:\n" + self.log_tail())
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
                return
            except OSError:
                time.sleep(0.5)
        self.stop()
        raise RuntimeError("RPC server did not start listening:\n" + self.log_tail())

    def log_tail(self, lines=40):
        try:
            with open(self.log, errors="replace") as f:
                return "".join(f.readlines()[-lines:])
        except OSError:
            return "(no server log)"

    def stop(self):
        kill_group(self.proc)
        if os.environ.get("E2E_KEEP") == "1":
            print("e2e: kept %s" % self.dir)
        else:
            shutil.rmtree(self.dir, ignore_errors=True)

    # ---- talking to the server -------------------------------------------

    def cli_run(self, *args, password=WRITE_PASSWORD, admin_password=None, timeout=180):
        """Run the CLI. `password=None` runs it without the write password."""
        env = dict(os.environ)
        env["GHIDRA_RPC_HOST"] = "127.0.0.1:%d" % self.port
        for key, value in (("GHIDRA_RPC_WRITE_PASSWORD", password),
                           ("GHIDRA_RPC_ADMIN_PASSWORD", admin_password)):
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        proc = subprocess.run([self.cli] + [str(a) for a in args], env=env, timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return Result(proc)

    def rpc(self, request, password=WRITE_PASSWORD, timeout=180):
        """Send one request object over a fresh connection; return the parsed reply."""
        if password is not None and "password" not in request:
            request = dict(request, password=password)
        reply = self.rpc_raw((json.dumps(request) + "\n").encode(), timeout=timeout)
        if not reply:
            raise AssertionError("connection closed without a response to %r" % (request,))
        return json.loads(reply)

    def rpc_raw(self, data, timeout=180):
        """Send raw bytes; return the first response line as text ('' if none)."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as s:
            try:
                s.sendall(data)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the server may answer and close before reading it all
            buf = b""
            try:
                while not buf.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            except (ConnectionResetError, socket.timeout):
                pass
        return buf.decode(errors="replace").strip()

    # ---- programs ---------------------------------------------------------

    def fresh_program(self, analyze=False):
        """Import the fixture under a new name and return its project path.

        Not analysed unless asked: importing takes a fraction of a second,
        analysis several, and most data-type / label / listing tests do not
        need functions. Each test gets its own program, so tests cannot
        disturb each other.
        """
        self._counter += 1
        name = "%s%03d.bin" % (self.PROGRAM_PREFIX, self._counter)
        r = self.cli_run("file", "load", "--name", name, "--file", FIXTURE)
        if not r.ok:
            raise AssertionError("import failed: %r" % r)
        path = "/" + name
        if analyze:
            r = self.cli_run("file", "analyze", "--file", path)
            if not r.ok:
                raise AssertionError("analysis failed: %r" % r)
        return path

    def analyzed_program(self):
        """One shared, analysed program for tests that only READ functions.

        Tests that change functions take their own `fresh_program(analyze=True)`.
        """
        if self._analyzed is None:
            self._analyzed = self.fresh_program(analyze=True)
        return self._analyzed


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_server = None


def server():
    """The run-wide server, started on first use and stopped at exit."""
    global _server
    if _server is None:
        _server = Server()
        atexit.register(_server.stop)
    return _server


def symbols(path=FIXTURE):
    """name -> address for the ELF64 little-endian symbol table of `path`."""
    with open(path, "rb") as f:
        data = f.read()
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    out = {}
    for sec in sections:
        if sec[1] != 2:  # SHT_SYMTAB
            continue
        strtab = sections[sec[6]]
        for off in range(sec[4], sec[4] + sec[5], sec[9]):
            name_off, _info, _other, _shndx, value, _size = struct.unpack_from("<IBBHQQ", data, off)
            end = data.index(b"\0", strtab[4] + name_off)
            name = data[strtab[4] + name_off:end].decode()
            if name and value:
                out[name] = value
    return out


SYM = symbols()


def hx(value):
    """An address the way the CLI takes it."""
    return "0x%x" % value


class E2ETest(unittest.TestCase):
    """Base class: `self.srv` is the shared server."""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.srv = server()

    def cli(self, *args, **kw):
        return self.srv.cli_run(*args, **kw)

    def ok(self, *args, **kw):
        """Run the CLI and require success."""
        r = self.cli(*args, **kw)
        self.assertTrue(r.ok, "expected success: %s\n%r" % (" ".join(map(str, args)), r))
        return r

    def fails(self, *args, mentions=None, **kw):
        """Run the CLI and require a non-zero exit (optionally mentioning text)."""
        r = self.cli(*args, **kw)
        self.assertFalse(r.ok, "expected failure: %s\n%r" % (" ".join(map(str, args)), r))
        if mentions is not None:
            self.assertIn(mentions.lower(), r.text.lower())
        return r

    def rpc(self, request, **kw):
        return self.srv.rpc(request, **kw)

    def listing(self, program, start, end, with_bytes=True):
        """Listing rows for [start, end) as parsed JSON objects."""
        reply = self.rpc({"procedure": "Listings", "file": program, "bytes": with_bytes,
                          "addressSet": [{"start": hx(start), "end": hx(end)}]})
        self.assertTrue(reply.get("success"), reply)
        # The server omits empty fields; fill them in so tests can index.
        return [dict({"label": "", "bytes": ""}, **{k: v for k, v in u.items() if v is not None})
                for u in reply["units"]]

    def undefine(self, program, start, end):
        """Clear [start, end) back to undefined bytes."""
        self.ok("memory", "undefine", "--file", program, "--address-set", "%s:%s" % (hx(start), hx(end)))
