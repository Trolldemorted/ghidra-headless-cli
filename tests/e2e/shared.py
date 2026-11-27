"""Fixtures for the shared-repository e2e tests (a real Ghidra Server).

Three processes make up one shared-repository environment, all on 127.0.0.1
and all inside one temporary directory:

  GhidraServer   the Ghidra Server shipped with GHIDRA_HOME, started as
                 `java ... ghidra.server.remote.GhidraServer -a0 -u ...` on a
                 private repositories directory (nothing is written into the
                 Ghidra install). Users are created by pre-writing the server's
                 `users` file.
  RepoClient     a second, independent Ghidra client (ghidra_scripts/
                 RepoClient.java under analyzeHeadless on a throwaway local
                 project) logged in as OTHER_USER. It creates the repository
                 and answers "what does the repository really contain":
                 versions, checkouts, program content. It can also act as
                 another user (terminate checkouts, check in its own versions).
  SharedServer   the RPC server under test, launched exactly as in production:
                 ghidra-rpc-server/ghidra-headless.sh against
                 ghidra://127.0.0.1:<port>/E2E as RPC_USER.

Every piece can be stopped, killed and restarted on the same ports and data
directory, which is what the crash and connection-loss tests need.

Environment: as harness.py, plus
  E2E_SHARED=0   skip the shared-repository tests
"""

import atexit
import hashlib
import json
import os
import random
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest

import harness
from harness import ADMIN_PASSWORD, MAX_REQUEST_BYTES, REPO, WRITE_PASSWORD, E2ETest, kill_group

REPOSITORY = "E2E"
RPC_USER = "rpcuser"
RPC_USER_PASSWORD = "rpc-login-for-tests"
OTHER_USER = "otheruser"
OTHER_USER_PASSWORD = "other-login-for-tests"
SERVER_START_TIMEOUT_S = 120
CLIENT_START_TIMEOUT_S = 300
JAVA_HEAP = "-Xmx768m"


def _port_free(port):
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _listening(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


def _free_port_triple():
    """A base port whose base, base+1 and base+2 are free (the Ghidra Server
    uses three consecutive ports)."""
    for _ in range(200):
        base = random.randint(20000, 60000)
        if all(_port_free(base + i) for i in range(3)):
            return base
    raise RuntimeError("no three consecutive free ports found")


def _wait_for(predicate, timeout, interval=0.25, what="condition"):
    """Poll `predicate` until it returns something truthy; return that value."""
    deadline = time.time() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.time() >= deadline:
            raise AssertionError("timed out after %ss waiting for %s" % (timeout, what))
        time.sleep(interval)


def _salted_sha256(password):
    """The password hash format of the Ghidra Server's `users` file
    (HashUtilities.getSaltedHash: 4 salt chars + hex SHA-256 of salt+password)."""
    salt = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(4))
    return salt + hashlib.sha256((salt + password).encode("ascii")).hexdigest()


class LogFile:
    """A log file that survives restarts; tests look only at what was written
    after a mark."""

    def __init__(self, path):
        self.path = path

    def mark(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def since(self, mark=0):
        try:
            with open(self.path, "rb") as f:
                f.seek(mark)
                return f.read().decode(errors="replace")
        except OSError:
            return ""

    def tail(self, lines=60):
        return "".join(self.since().splitlines(True)[-lines:])

    def wait_for(self, text, mark=0, timeout=60):
        return _wait_for(lambda: text in self.since(mark), timeout, what="%r in %s" % (text, self.path))


class GhidraServer:
    """A Ghidra Server on a private repositories directory."""

    def __init__(self, ghidra, workdir):
        self.ghidra = ghidra
        self.root = os.path.join(workdir, "repositories")
        self.tmp = os.path.join(workdir, "ghidra-server-tmp")
        os.makedirs(self.root)
        os.makedirs(self.tmp)
        self.port = _free_port_triple()
        self.log = LogFile(os.path.join(workdir, "ghidra-server.out"))
        self.proc = None
        self.classpath = self._classpath()

    def _classpath(self):
        # The service wrapper (server.conf) builds its classpath from this
        # fragment; reuse it instead of the wrapper so nothing is installed.
        frag = os.path.join(self.ghidra, "Ghidra", "Features", "GhidraServer", "data", "classpath.frag")
        entries = []
        with open(frag) as f:
            for line in f:
                line = line.strip()
                if line.startswith("wrapper.java.classpath.") and "=" in line:
                    entries.append(line.split("=", 1)[1].replace("${ghidra_home}", self.ghidra))
        if not entries:
            raise RuntimeError("no classpath entries in " + frag)
        return ":".join(entries)

    def add_users(self, users):
        """Create users by writing the server's `users` file
        (UserManager.readUserList format: name:saltedhash:passwordTime).

        The password time is "now", exactly what `svrAdmin -add` records: the
        password counts as a temporary one that expires after the default
        expiration period (1 day) unless the user resets it - which the RPC
        server does on every start (RpcServer.refreshPasswordIfRequested).
        Must be called while the server is stopped.
        """
        assert self.proc is None or self.proc.poll() is not None
        now = "%x" % int(time.time() * 1000)
        with open(os.path.join(self.root, "users"), "w") as f:
            for name, password in users.items():
                f.write("%s:%s:%s\n" % (name, _salted_sha256(password), now))

    def user_entry(self, name):
        """The raw `users` line fields of `name`: [name, hash, time] or None."""
        try:
            with open(os.path.join(self.root, "users")) as f:
                for line in f:
                    fields = line.strip().split(":")
                    if fields and fields[0] == name:
                        return fields
        except OSError:
            pass
        return None

    def start(self):
        mark = self.log.mark()
        cmd = ["java", JAVA_HEAP,
               # As in server/server.conf (wrapper.java.additional.*).
               "-Djava.net.preferIPv4Stack=true",
               "-Djava.io.tmpdir=" + self.tmp, "-Djna.tmpdir=" + self.tmp,
               "-Dghidra.tls.server.protocols=TLSv1.2;TLSv1.3",
               "-Ddb.buffers.DataBuffer.compressedOutput=true",
               "-Djava.awt.headless=true",
               "-cp", self.classpath, "ghidra.server.remote.GhidraServer",
               "-ip", "127.0.0.1", "-i", "127.0.0.1", "-p%d" % self.port,
               "-a0",  # local Ghidra passwords (the users file)
               "-u",   # take the user name from the client's login, not user.name
               self.root]
        with open(self.log.path, "ab") as out:
            out.write(("\n==== start %s\n" % time.strftime("%H:%M:%S")).encode())
            out.flush()
            self.proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT,
                                         stdin=subprocess.DEVNULL, cwd=self.tmp,
                                         start_new_session=True)
        deadline = time.time() + SERVER_START_TIMEOUT_S
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("Ghidra Server exited during startup:\n" + self.log.tail())
            # Logged after the RMI registry and the server object are bound.
            if "Registered Ghidra Server" in self.log.since(mark):
                return
            time.sleep(0.25)
        self.stop()
        raise RuntimeError("Ghidra Server did not come up:\n" + self.log.tail())

    def stop(self, sig=signal.SIGTERM):
        kill_group(self.proc, sig)

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None


class RepoClient:
    """The second client (ghidra_scripts/RepoClient.java), logged in as OTHER_USER."""

    def __init__(self, ghidra, workdir, server):
        self.ghidra = ghidra
        self.dir = os.path.join(workdir, "repo-client")
        os.makedirs(os.path.join(self.dir, "home"))
        os.makedirs(os.path.join(self.dir, "project"))
        os.makedirs(os.path.join(self.dir, "tmp"))
        self.server = server
        self.port = harness._free_port()
        self.log = LogFile(os.path.join(self.dir, "repo-client.log"))
        self.proc = None

    def start(self):
        env = dict(os.environ)
        env.update({
            "HOME": os.path.join(self.dir, "home"),
            "JDK_JAVA_OPTIONS": "-Djava.io.tmpdir=%s -Duser.home=%s" % (
                os.path.join(self.dir, "tmp"), os.path.join(self.dir, "home")),
            "E2E_GHIDRA_HOST": "127.0.0.1",
            "E2E_GHIDRA_PORT": str(self.server.port),
            "E2E_CLIENT_USER": OTHER_USER,
            "E2E_CLIENT_PASSWORD": OTHER_USER_PASSWORD,
            "E2E_CLIENT_PORT": str(self.port),
        })
        with open(self.log.path, "ab") as out:
            self.proc = subprocess.Popen(
                [os.path.join(self.ghidra, "support", "analyzeHeadless"),
                 os.path.join(self.dir, "project"), "RepoClient", "-noanalysis",
                 "-scriptPath", os.path.join(REPO, "tests", "e2e", "ghidra_scripts"),
                 "-preScript", "RepoClient.java"],
                stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                env=env, cwd=self.dir, start_new_session=True)
        deadline = time.time() + CLIENT_START_TIMEOUT_S
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("RepoClient exited during startup:\n" + self.log.tail())
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
                return
            except OSError:
                time.sleep(0.5)
        self.stop()
        raise RuntimeError("RepoClient did not start:\n" + self.log.tail())

    def stop(self):
        if self.running:
            try:
                self.call("quit", timeout=10)
                self.proc.wait(timeout=30)
            except Exception:
                pass
        kill_group(self.proc)

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def healthy(self):
        try:
            return bool(self.try_call("getAccess", timeout=30, repo=REPOSITORY).get("success"))
        except (OSError, AssertionError, ValueError):
            return False

    def call(self, op, timeout=180, **fields):
        """One request; returns the reply dict, raises on success:false."""
        reply = self.try_call(op, timeout=timeout, **fields)
        if not reply.get("success"):
            raise AssertionError("RepoClient %s %r failed: %s" % (op, fields, reply.get("error")))
        return reply

    def try_call(self, op, timeout=180, **fields):
        request = dict(fields, op=op)
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as s:
            s.sendall((json.dumps(request) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        if not buf:
            raise AssertionError("RepoClient closed the connection on %s %r" % (op, fields))
        return json.loads(buf)

    # ---- server-side truth ------------------------------------------------

    def versions(self, path):
        """[{version, user, comment}] of `path` on the server ([] if it does not exist)."""
        return self.call("versions", repo=REPOSITORY, path=path)["versions"]

    def exists(self, path):
        return self.call("versions", repo=REPOSITORY, path=path)["exists"]

    def checkouts(self, path):
        return self.call("checkouts", repo=REPOSITORY, path=path)["checkouts"]

    def all_checkouts(self, user=None):
        """{path: [checkout]} for every file with checkouts (optionally of one user)."""
        out = {}
        for f in self.call("items", repo=REPOSITORY)["files"]:
            cos = [c for c in self.checkouts(f["path"]) if user is None or c["user"] == user]
            if cos:
                out[f["path"]] = cos
        return out

    def files(self):
        return {f["path"]: f["version"] for f in self.call("items", repo=REPOSITORY)["files"]}

    def read(self, path, version=None, address=None, data_types=None):
        fields = {"repo": REPOSITORY, "path": path}
        if version is not None:
            fields["version"] = version
        if address is not None:
            fields["address"] = address
        if data_types is not None:
            fields["dataTypes"] = data_types
        return self.call("read", **fields)

    def labels(self, path, address, version=None):
        return self.read(path, version=version, address=address)["labels"]

    def terminate(self, path, user=None):
        fields = {"repo": REPOSITORY, "path": path}
        if user is not None:
            fields["user"] = user
        return self.call("terminate", **fields)["terminated"]

    def delete_item(self, path):
        """Delete `path` with all its versions, as OTHER_USER (a repository admin)."""
        return self.call("deleteItem", repo=REPOSITORY, path=path)

    def edit_label(self, path, address, label, comment="edit by " + OTHER_USER):
        return self.call("editLabel", repo=REPOSITORY, path=path, address=address,
                         label=label, comment=comment)["version"]

    def set_access(self, users):
        return self.call("setAccess", repo=REPOSITORY, users=users)["users"]


class SharedServer(harness.Server):
    """The RPC server under test, launched through ghidra-headless.sh against
    the shared repository. Unlike the local-mode Server it can be killed and
    restarted; its log is appended to across restarts."""

    PROGRAM_PREFIX = "s"

    def __init__(self, env):
        self.cli = harness.cli_binary()
        self.env = env
        self.dir = os.path.join(env.dir, "rpc")
        self.home = os.path.join(self.dir, "home")
        self.tmp = os.path.join(self.dir, "tmp")
        os.makedirs(self.home)
        os.makedirs(self.tmp)
        self.logfile = LogFile(os.path.join(self.dir, "server.log"))
        self.log = self.logfile.path
        self.port = harness._free_port()
        self.proc = None
        self._counter = 0
        self._analyzed = None

    def start(self, extra_env=None):
        env = dict(os.environ)
        env.update({
            "HOME": self.home,
            # ghidra-headless.sh appends its own options to these.
            "JDK_JAVA_OPTIONS": "%s -Djava.io.tmpdir=%s -Duser.home=%s" % (JAVA_HEAP, self.tmp, self.home),
            "GHIDRA_INSTALL": self.env.ghidra,
            "GHIDRA_ADDRESS": "127.0.0.1:%d" % self.env.ghidra_server.port,
            "GHIDRA_PROJECT": REPOSITORY,
            "GHIDRA_USER": RPC_USER,
            "GHIDRA_PASSWORD": RPC_USER_PASSWORD,
            "RPC_BIND": "127.0.0.1",
            "RPC_PORT": str(self.port),
            "GHIDRA_RPC_WRITE_PASSWORD": WRITE_PASSWORD,
            "GHIDRA_RPC_ADMIN_PASSWORD": ADMIN_PASSWORD,
            "RPC_MAX_REQUEST_BYTES": str(MAX_REQUEST_BYTES),
        })
        for key in ("_JAVA_OPTIONS", "GHIDRA_SCRIPT", "GHIDRA_SCRIPTPATH", "GHIDRA_READONLY",
                    "GHIDRA_PROGRAM", "GHIDRA_FOLDER", "GHIDRA_COMMIT_MSG"):
            env.pop(key, None)
        env.update(extra_env or {})
        # A previous instance must be completely gone, or the readiness probe
        # below would talk to it.
        _wait_for(lambda: not _listening(self.port), 60, what="RPC port %d to be released" % self.port)
        mark = self.logfile.mark()
        with open(self.log, "ab") as out:
            out.write(("\n==== start %s\n" % time.strftime("%H:%M:%S")).encode())
            out.flush()
            self.proc = subprocess.Popen(
                [os.path.join(REPO, "ghidra-rpc-server", "ghidra-headless.sh")],
                stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                env=env, cwd=self.dir, start_new_session=True)
        self._wait_until_listening()
        return mark

    def log_since(self, mark):
        return self.logfile.since(mark)

    def log_tail(self, lines=60):
        return self.logfile.tail(lines)

    def kill(self, sig=signal.SIGKILL):
        """Kill the RPC server (default: SIGKILL, i.e. a crash)."""
        kill_group(self.proc, sig)

    def wait_exit(self, timeout):
        """Wait for the RPC server to exit by itself; return its exit code."""
        return self.proc.wait(timeout=timeout)

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def healthy(self):
        try:
            reply = self.rpc({"procedure": "ListFiles", "recursive": False, "includeFolders": False,
                              "limit": 1}, timeout=60)
        except (OSError, AssertionError, ValueError):
            return False
        return bool(reply.get("success"))

    def jvm_pid(self):
        """PID of the server's JVM. ghidra-headless.sh runs `printf | exec java`,
        so java is a child of the script's shell, not the shell itself."""
        out = subprocess.run(["pgrep", "-P", str(self.proc.pid)], stdout=subprocess.PIPE,
                             text=True).stdout.split()
        for pid in out:
            try:
                with open("/proc/%s/cmdline" % pid, "rb") as f:
                    if b"java" in f.read():
                        return int(pid)
            except OSError:
                pass
        raise AssertionError("no java child of %d" % self.proc.pid)

    def stop(self):
        kill_group(self.proc)


class SharedEnv:
    """Ghidra Server + RepoClient + RPC server, started once per test run."""

    def __init__(self):
        if os.environ.get("E2E_SHARED") == "0":
            raise unittest.SkipTest("shared-repository tests disabled (E2E_SHARED=0)")
        self.ghidra = harness.ghidra_home()
        harness.cli_binary()
        if shutil.which("java") is None:
            raise unittest.SkipTest("no `java` on PATH; the Ghidra Server cannot be started")
        self.dir = tempfile.mkdtemp(prefix="ghidra-rpc-e2e-shared-")
        self.ghidra_server = GhidraServer(self.ghidra, self.dir)
        self.client = RepoClient(self.ghidra, self.dir, self.ghidra_server)
        self.rpc = SharedServer(self)
        self.failed = None
        try:
            self.ghidra_server.add_users({RPC_USER: RPC_USER_PASSWORD, OTHER_USER: OTHER_USER_PASSWORD})
            self.ghidra_server.start()
            self.client.start()
            self.client.call("createRepo", repo=REPOSITORY)
            # The creator (OTHER_USER) is the repository admin; the RPC user
            # gets plain write access.
            self.client.set_access({OTHER_USER: "ADMIN", RPC_USER: "WRITE"})
            self.rpc.start()
        except Exception:
            self.stop()
            raise

    def stop(self):
        for part in (self.rpc, self.client, self.ghidra_server):
            try:
                part.stop()
            except Exception:
                pass
        if os.environ.get("E2E_KEEP") == "1":
            print("e2e: kept %s" % self.dir)
        else:
            shutil.rmtree(self.dir, ignore_errors=True)

    def ensure_healthy(self):
        """Bring every part back up after a test that stopped or killed one.

        A Ghidra Server restart leaves both clients with a dead connection,
        so each is health-checked with a real request and restarted if that
        fails.
        """
        if not self.ghidra_server.running:
            self.ghidra_server.start()
        if not self.client.running or not self.client.healthy():
            self.client.stop()
            self.client.start()
        if not self.rpc.running or not self.rpc.healthy():
            self.rpc.kill()
            self.rpc.start()


_env = None
_env_error = None


def shared_env():
    """The run-wide shared environment, started on first use and stopped at exit.

    If it cannot be started, every shared-repository test is skipped with the
    reason (instead of failing one by one).
    """
    global _env, _env_error
    if _env_error is not None:
        raise unittest.SkipTest(_env_error)
    if _env is None:
        try:
            _env = SharedEnv()
        except unittest.SkipTest:
            raise
        except Exception as e:  # noqa: BLE001 - reported as the skip reason
            _env_error = "could not start the Ghidra Server environment: %s" % e
            raise unittest.SkipTest(_env_error)
        atexit.register(_env.stop)
    return _env


class SharedRepoTest(E2ETest):
    """Base class: `self.env` is the shared environment, `self.srv` its RPC
    server, `self.repo` the second client."""

    @classmethod
    def setUpClass(cls):
        cls.env = shared_env()
        cls.srv = cls.env.rpc
        cls.repo = cls.env.client

    def setUp(self):
        # A test that crashed or stopped something must not take the next one down.
        self.env.ensure_healthy()

    def nversions(self, path):
        return len(self.repo.versions(path))
