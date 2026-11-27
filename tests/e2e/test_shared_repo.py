"""Checkout, check-in, version history and recovery against a real Ghidra Server.

The RPC server under test runs exactly as in production (ghidra-headless.sh
against ghidra://.../E2E). Assertions are made on server-side truth wherever
possible: version histories, checkouts and program content as seen by an
independent second client (RepoClient, logged in as another user), not just
on the RPC server's own replies. See shared.py for the fixture.
"""

import os
import shutil
import signal
import subprocess
import threading
import time
import unittest

from harness import ADMIN_PASSWORD, FIXTURE, SYM, hx
from shared import OTHER_USER, RPC_USER, SharedRepoTest, _wait_for

LABEL_AT = hx(SYM["g_blob"])


class SharedCase(SharedRepoTest):
    """Helpers shared by the test classes below."""

    def label(self, program, name, **kw):
        return self.cli("memory", "create-label", "--file", program, "--address", LABEL_AT,
                        "--name", name, **kw)

    def add_label(self, program, name):
        """Create a label through the RPC server and require success."""
        r = self.label(program, name)
        self.assertTrue(r.ok, "create-label %s failed: %r" % (name, r))
        return r

    def rpc_labels(self, program):
        """Label names at LABEL_AT as the RPC server sees them."""
        reply = self.rpc({"procedure": "GetLabel", "file": program, "address": LABEL_AT})
        self.assertTrue(reply.get("success"), reply)
        return [entry["name"] for entry in reply["all"]]

    def server_labels(self, program, version=None):
        """Label names at LABEL_AT in the repository (latest or a given version)."""
        return self.repo.labels(program, LABEL_AT, version=version)

    def history(self, program):
        """(user, comment) of every version on the server, oldest first."""
        return [(v["user"], v["comment"]) for v in self.repo.versions(program)]

    def rpc_checkouts(self, program):
        return [c for c in self.repo.checkouts(program) if c["user"] == RPC_USER]

    def restore_access(self):
        self.repo.set_access({OTHER_USER: "ADMIN", RPC_USER: "WRITE"})


class Versioning(SharedCase):

    def test_import_creates_one_version_visible_to_another_user(self):
        program = self.srv.fresh_program()
        self.assertEqual(self.history(program), [(RPC_USER, "RPC import " + program[1:])])
        # The other user can open it: it is a real program in the repository.
        self.assertIn("g_blob", self.server_labels(program))
        r = self.ok("file", "metadata", "--file", program)
        self.assertIn("versioned: true", r.out)

    def test_each_successful_write_creates_exactly_one_version(self):
        program = self.srv.fresh_program()
        for i in range(3):
            before = self.nversions(program)
            self.add_label(program, "one_%d" % i)
            history = self.history(program)
            self.assertEqual(len(history), before + 1)
            self.assertEqual(history[-1], (RPC_USER, "RPC CreateLabel"))
        # The newest version has the label; the one before it does not.
        latest = self.nversions(program)
        self.assertIn("one_2", self.server_labels(program))
        self.assertNotIn("one_2", self.server_labels(program, version=latest - 1))
        self.assertIn("one_1", self.server_labels(program, version=latest - 1))

    def test_reads_create_no_version(self):
        program = self.srv.fresh_program()
        self.add_label(program, "seen")
        before = self.repo.versions(program)
        self.ok("memory", "get-label", "--file", program, "--address", LABEL_AT, password=None)
        self.ok("listing", "--file", program, "--address", LABEL_AT, password=None)
        self.ok("file", "metadata", "--file", program, password=None)
        self.ok("file", "list", password=None)
        self.ok("memory", "read-bytes", "--file", program, "--address", LABEL_AT, "--length", "16", password=None)
        self.assertEqual(self.repo.versions(program), before)

    def test_rejected_write_creates_no_version(self):
        program = self.srv.fresh_program()
        before = self.repo.versions(program)
        self.assertFalse(self.label(program, "nopass", password=None).ok)
        self.assertFalse(self.label(program, "badpass", password="wrong").ok)
        self.assertEqual(self.repo.versions(program), before)
        self.assertNotIn("nopass", self.server_labels(program))

    def test_import_without_password_or_with_existing_name_adds_nothing(self):
        program = self.srv.fresh_program()
        files = self.repo.files()
        self.fails("file", "load", "--name", "unauth.bin", "--file", FIXTURE, password=None,
                   mentions="password")
        self.fails("file", "load", "--name", program[1:], "--file", FIXTURE, mentions="already exists")
        self.assertEqual(self.repo.files(), files)

    def test_failing_write_rolls_back_and_creates_no_version(self):
        program = self.srv.fresh_program()
        self.ok("datatype", "create", "--file", program, "--kind", "typedef", "--name", "E2ETd",
                "--base", "int")
        before = self.repo.versions(program)
        # The rename is applied first, then the description throws (typedefs
        # cannot hold one): the whole request has to be undone.
        self.fails("datatype", "edit", "--file", program, "--path", "/E2ETd", "--rename", "E2ERenamed",
                   "--description", "x", mentions="typedef")
        self.assertEqual(self.repo.versions(program), before)
        types = ["/E2ETd", "/E2ERenamed"]
        self.assertEqual(self.repo.read(program, data_types=types)["dataTypes"],
                         {"/E2ETd": True, "/E2ERenamed": False})
        self.ok("datatype", "show", "--file", program, "--path", "/E2ETd")
        self.fails("datatype", "show", "--file", program, "--path", "/E2ERenamed")
        # The rolled-back rename must not ride along with the next commit.
        self.add_label(program, "after_rollback")
        self.assertEqual(len(self.repo.versions(program)), len(before) + 1)
        self.assertEqual(self.repo.read(program, data_types=types)["dataTypes"],
                         {"/E2ETd": True, "/E2ERenamed": False})

    def test_failed_check_in_is_reported_and_the_change_discarded(self):
        program = self.srv.fresh_program()
        self.add_label(program, "landed")
        before = self.repo.versions(program)
        # Revoke write access while the RPC server holds the checkout: the
        # edit succeeds locally, the push is refused by the Ghidra Server.
        self.addCleanup(self.restore_access)
        self.repo.set_access({OTHER_USER: "ADMIN", RPC_USER: "READ_ONLY"})
        r = self.label(program, "refused")
        self.assertFalse(r.ok, r)
        self.assertIn("check-in", r.text.lower())
        self.assertEqual(self.repo.versions(program), before)
        self.restore_access()
        # The next request resets to the server's state: the refused change is gone.
        self.assertNotIn("refused", self.rpc_labels(program))
        self.add_label(program, "landed_later")
        self.assertEqual(len(self.repo.versions(program)), len(before) + 1)
        labels = self.server_labels(program)
        self.assertIn("landed_later", labels)
        self.assertNotIn("refused", labels)

    def test_concurrent_writes_each_create_one_version(self):
        program = self.srv.fresh_program()
        before = self.nversions(program)
        results = {}

        def write(i):
            results[i] = self.label(program, "conc_%d" % i)

        threads = [threading.Thread(target=write, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for i, r in results.items():
            self.assertTrue(r.ok, "writer %d: %r" % (i, r))
        self.assertEqual(self.nversions(program), before + 4)
        labels = self.server_labels(program)
        for i in range(4):
            self.assertIn("conc_%d" % i, labels)


class VersionHistory(SharedCase):

    def test_list_and_metadata_report_the_server_version(self):
        program = self.srv.fresh_program()
        self.add_label(program, "h1")
        self.add_label(program, "h2")
        latest = self.repo.versions(program)[-1]["version"]
        self.assertEqual(latest, 3)
        self.assertIn("%s  Program  v%d" % (program, latest), self.ok("file", "list").out)
        reply = self.rpc({"procedure": "FileMetadata", "file": program})
        self.assertTrue(reply["success"], reply)
        self.assertEqual(reply["version"], latest)
        self.assertTrue(reply["versioned"])

    def test_delete_version_is_admin_gated(self):
        program = self.srv.fresh_program()
        self.add_label(program, "g1")
        before = self.repo.versions(program)
        self.fails("file", "delete-version", "--file", program, "--keep", "1", mentions="admin password")
        self.fails("file", "delete-version", "--file", program, "--keep", "1", admin_password="wrong")
        reply = self.rpc({"procedure": "PurgeVersions", "file": program, "keep": 1})
        self.assertFalse(reply["success"])
        self.assertIn("adminPassword", reply["error"])
        self.assertEqual(self.repo.versions(program), before)

    def test_delete_version_keeps_the_newest(self):
        program = self.srv.fresh_program()
        for i in range(4):
            self.add_label(program, "k%d" % i)
        self.assertEqual([v["version"] for v in self.repo.versions(program)], [1, 2, 3, 4, 5])
        reply = self.rpc({"procedure": "PurgeVersions", "file": program, "keep": 2,
                          "adminPassword": ADMIN_PASSWORD})
        self.assertTrue(reply["success"], reply)
        self.assertEqual((reply["before"], reply["after"], reply["deleted"]), (5, 2, 3))
        self.assertEqual([v["version"] for v in self.repo.versions(program)], [4, 5])
        self.assertIn("k3", self.server_labels(program))
        # Still editable afterwards.
        self.add_label(program, "after_purge")
        self.assertEqual([v["version"] for v in self.repo.versions(program)], [4, 5, 6])
        self.assertIn("after_purge", self.server_labels(program))

    def test_delete_version_refuses_to_keep_nothing(self):
        # Removing every version removes the file: that is `file delete`'s job.
        program = self.srv.fresh_program()
        self.add_label(program, "k0")
        before = self.repo.versions(program)
        r = self.fails("file", "delete-version", "--file", program, "--keep", "0",
                       admin_password=ADMIN_PASSWORD)
        self.assertIn("--keep", r.text)
        for bad in (0, -1):
            reply = self.rpc({"procedure": "PurgeVersions", "file": program, "keep": bad,
                              "adminPassword": ADMIN_PASSWORD})
            self.assertFalse(reply["success"], reply)
            self.assertIn("file delete", reply["error"])
        self.assertEqual(self.repo.versions(program), before)
        self.add_label(program, "still_here")
        self.assertEqual(len(self.repo.versions(program)), len(before) + 1)

    def test_purge_stops_at_another_users_version(self):
        # The RPC user has WRITE (not ADMIN) access: the Ghidra Server only
        # lets it delete its own versions. The error must say how far it got.
        program = self.srv.fresh_program()                    # v1 rpcuser
        self.repo.terminate(program, user=RPC_USER)
        self.repo.edit_label(program, LABEL_AT, "by_other")   # v2 otheruser
        self.add_label(program, "mine")                       # v3 rpcuser
        reply = self.rpc({"procedure": "PurgeVersions", "file": program, "keep": 1,
                          "adminPassword": ADMIN_PASSWORD})
        self.assertFalse(reply["success"], reply)
        self.assertIn("1 older version(s) were already deleted", reply["error"])
        self.assertIn(OTHER_USER, reply["error"])
        self.assertEqual([v["version"] for v in self.repo.versions(program)], [2, 3])


class FileDelete(SharedCase):

    def test_delete_removes_a_checked_out_file_from_the_repository(self):
        program = self.srv.fresh_program()
        self.add_label(program, "d1")
        self.assertTrue(self.rpc_checkouts(program))     # cached and checked out
        self.ok("file", "delete", "--file", program, admin_password=ADMIN_PASSWORD)
        self.assertFalse(self.repo.exists(program))
        self.assertNotIn(program, self.ok("file", "list").out)
        self.fails("file", "metadata", "--file", program)
        # The name is free again.
        self.ok("file", "load", "--name", program[1:], "--file", FIXTURE)
        self.assertEqual(self.history(program), [(RPC_USER, "RPC import " + program[1:])])
        self.assertNotIn("d1", self.server_labels(program))

    def test_delete_is_admin_gated(self):
        program = self.srv.fresh_program()
        self.add_label(program, "d2")
        before = self.repo.versions(program)
        self.fails("file", "delete", "--file", program, mentions="admin password")
        self.fails("file", "delete", "--file", program, admin_password="wrong")
        self.assertEqual(self.repo.versions(program), before)

    def test_delete_refused_by_the_server_is_reported(self):
        # Non-admin users may only delete files whose versions are all theirs.
        program = self.srv.fresh_program()
        self.repo.terminate(program, user=RPC_USER)
        self.repo.edit_label(program, LABEL_AT, "foreign")
        self.add_label(program, "own")
        before = self.repo.versions(program)
        self.fails("file", "delete", "--file", program, admin_password=ADMIN_PASSWORD,
                   mentions="owned by " + OTHER_USER)
        self.assertEqual(self.repo.versions(program), before)
        # The server dropped its checkout to try; it must still be able to write.
        self.add_label(program, "still_writable")
        self.assertEqual(len(self.repo.versions(program)), len(before) + 1)

    def test_delete_after_lost_checkout_deletes_the_server_file(self):
        # The local copy is a private "hijack" file once another session has
        # terminated this server's checkout. Deleting that copy only reveals
        # the server file; the delete has to remove that too.
        program = self.srv.fresh_program()
        self.add_label(program, "kept")
        self.repo.terminate(program, user=RPC_USER)
        self.ok("file", "delete", "--file", program, admin_password=ADMIN_PASSWORD)
        self.assertFalse(self.repo.exists(program))
        self.assertNotIn(program, self.ok("file", "list").out)

    def test_delete_after_lost_checkout_refused_by_the_server_is_reported(self):
        # Same, but the server file has another user's version, which the
        # RPC user (not a repository admin) may not delete: an error, never
        # "deleted", and the file stays usable.
        program = self.srv.fresh_program()
        self.add_label(program, "mine")
        self.repo.terminate(program, user=RPC_USER)
        self.repo.edit_label(program, LABEL_AT, "foreign")
        before = self.repo.versions(program)
        self.fails("file", "delete", "--file", program, admin_password=ADMIN_PASSWORD,
                   mentions="owned by " + OTHER_USER)
        self.assertEqual(self.repo.versions(program), before)
        self.add_label(program, "still_writable")
        self.assertEqual(len(self.repo.versions(program)), len(before) + 1)
        self.assertIn("foreign", self.server_labels(program))

    def test_write_to_a_file_removed_from_the_repository_is_not_a_success(self):
        # Another client deletes the file while this server has it cached and
        # checked out: what is left here is a private copy, and a write to it
        # must not be reported as saved.
        program = self.srv.fresh_program()
        self.add_label(program, "cached")
        self.repo.terminate(program, user=RPC_USER)
        self.assertFalse(self.repo.delete_item(program)["exists"])
        for _ in range(2):  # the first attempt may still see the old checkout
            r = self.label(program, "nowhere")
            self.assertFalse(r.ok, r)
        self.assertIn("not in the Ghidra Server repository", r.text)
        self.assertFalse(self.repo.exists(program))
        self.assertNotIn("nowhere", self.rpc_labels(program))
        # The private copy can be removed, and the name reused.
        self.ok("file", "delete", "--file", program, admin_password=ADMIN_PASSWORD)
        self.ok("file", "load", "--name", program[1:], "--file", FIXTURE)
        self.assertEqual(len(self.repo.versions(program)), 1)


class LostCheckout(SharedCase):

    def test_write_after_checkout_was_terminated_reaches_the_server(self):
        program = self.srv.fresh_program()
        self.add_label(program, "before_loss")
        self.assertTrue(self.rpc_checkouts(program))
        self.assertEqual(self.repo.terminate(program, user=RPC_USER), 1)
        self.assertFalse(self.rpc_checkouts(program))
        before = self.nversions(program)
        mark = self.srv.logfile.mark()
        self.add_label(program, "after_loss")
        self.assertEqual(self.nversions(program), before + 1)
        labels = self.server_labels(program)
        self.assertIn("before_loss", labels)
        self.assertIn("after_loss", labels)
        self.assertTrue(self.rpc_checkouts(program))     # checked out again
        self.assertIn("was terminated by another session", self.srv.log_since(mark))

    def test_newer_version_from_another_user_is_built_upon(self):
        program = self.srv.fresh_program()
        self.add_label(program, "rpc_first")
        self.repo.terminate(program, user=RPC_USER)
        self.repo.edit_label(program, LABEL_AT, "other_second")
        # A read already shows the other user's version...
        self.assertIn("other_second", self.rpc_labels(program))
        # ...and the next write goes on top of it, losing nothing.
        self.add_label(program, "rpc_third")
        self.assertEqual([u for u, _ in self.history(program)], [RPC_USER, RPC_USER, OTHER_USER, RPC_USER])
        labels = self.server_labels(program)
        for name in ("rpc_first", "other_second", "rpc_third"):
            self.assertIn(name, labels)

    def test_success_is_never_reported_for_a_write_that_did_not_land(self):
        # Terminate and write straight away, repeatedly: whatever the timing
        # of the termination notice, a reported success must be a version on
        # the server, and a failure must leave the history unchanged.
        program = self.srv.fresh_program()
        self.add_label(program, "start")
        for i in range(5):
            name = "race_%d" % i
            before = self.nversions(program)
            self.repo.terminate(program, user=RPC_USER)
            r = self.label(program, name)
            after = self.nversions(program)
            if r.ok:
                self.assertEqual(after, before + 1, "round %d: success without a version" % i)
                self.assertIn(name, self.server_labels(program))
            else:
                self.assertEqual(after, before, "round %d: failure but a version appeared" % i)
                # Retrying recovers.
                self.add_label(program, name)
                self.assertIn(name, self.server_labels(program))


class CrashRecovery(SharedCase):

    def test_restart_after_sigkill_cleans_up_and_loses_nothing(self):
        programs = [self.srv.fresh_program() for _ in range(2)]
        for p in programs:
            self.add_label(p, "before_crash")
        held = {p: self.rpc_checkouts(p) for p in programs}
        self.assertTrue(all(held.values()), held)
        history = {p: self.repo.versions(p) for p in programs}

        gs_mark = self.env.ghidra_server.log.mark()
        self.srv.kill()                                 # SIGKILL: no shutdown hook
        mark = self.srv.start()
        log = self.srv.log_since(mark)
        self.assertIn("Stale-checkout scan: terminated", log)
        for p in programs:
            old_ids = {c["id"] for c in held[p]}
            # The dead session's checkouts are gone: terminated by the startup
            # scan, or (if the restart was slow) reaped by the Ghidra Server,
            # which drops a dead client's transient checkouts after 30-60 s.
            self.assertFalse([c for c in self.repo.checkouts(p) if c["id"] in old_ids],
                             "stale checkout left on %s:\n%s" % (p, log[-3000:]))
            scanned = all("terminating checkout id=%d on %s " % (i, p) in log for i in old_ids)
            reaped = "transiet checkouts" in self.env.ghidra_server.log.since(gs_mark)  # sic
            self.assertTrue(scanned or reaped, "neither the startup scan nor the Ghidra Server "
                            "released the checkouts of %s:\n%s" % (p, log[-3000:]))
            self.assertEqual(self.repo.versions(p), history[p])
        # Every file is writable again and nothing committed before the crash is lost.
        for p in programs:
            self.add_label(p, "after_crash")
            self.assertEqual(len(self.repo.versions(p)), len(history[p]) + 1)
            labels = self.server_labels(p)
            self.assertIn("before_crash", labels)
            self.assertIn("after_crash", labels)


class ConnectionLoss(SharedCase):

    def stop_ghidra_server_and_wait_for_rpc_exit(self):
        """Stop the Ghidra Server; the RPC server must exit with the restart
        code (RpcServer.exitOnConnectionLost) within a bounded time. Returns
        the replies it gave to requests in the meantime."""
        self.env.ghidra_server.stop()
        replies = []
        deadline = time.time() + 45
        while self.srv.running and time.time() < deadline:
            try:
                replies.append(self.rpc({"procedure": "GetLabel", "file": "/x", "address": "0"},
                                        timeout=30))
            except (OSError, AssertionError, ValueError):
                pass  # the server closed its socket on the way out
            time.sleep(0.5)
        try:
            code = self.srv.wait_exit(timeout=max(1, deadline - time.time()))
        except subprocess.TimeoutExpired:
            code = None
        self.assertEqual(code, 70, "RPC server did not exit with the restart code within 45 s "
                         "of the Ghidra Server stopping:\n" + self.srv.log_tail())
        for reply in replies:
            self.assertFalse(reply.get("success"), reply)
        return replies

    def test_rpc_server_exits_for_restart_and_nothing_is_lost(self):
        program = self.srv.fresh_program()
        self.add_label(program, "committed")
        history = self.repo.versions(program)
        mark = self.srv.logfile.mark()

        self.stop_ghidra_server_and_wait_for_rpc_exit()
        self.assertIn("Ghidra Server connection lost", self.srv.log_since(mark))

        # Restart the Ghidra Server on the same ports and repositories, then
        # the RPC server (as the orchestrator would) and the second client.
        self.env.ghidra_server.start()
        self.env.ensure_healthy()
        self.assertEqual(self.repo.versions(program), history)
        self.assertIn("committed", self.server_labels(program))
        self.assertIn("committed", self.rpc_labels(program))
        self.add_label(program, "after_outage")
        self.assertEqual(len(self.repo.versions(program)), len(history) + 1)
        self.assertIn("after_outage", self.server_labels(program))

    def test_disconnect_listener_survives_garbage_collection(self):
        """The listener used to be registered as an otherwise unreferenced
        object in Ghidra's weak listener set, was collected after startup and
        never fired. Force a full GC first: it must still fire."""
        jcmd = shutil.which("jcmd")
        if not jcmd:
            self.skipTest("jcmd not available; cannot force a GC in the RPC server")
        subprocess.run([jcmd, str(self.srv.jvm_pid()), "GC.run"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        self.stop_ghidra_server_and_wait_for_rpc_exit()

    def test_clean_stop_is_not_a_connection_loss(self):
        # SIGTERM disconnects the repository as part of shutting down; that
        # must not be treated as a lost connection (exit 70) or hang.
        mark = self.srv.logfile.mark()
        os.kill(self.srv.jvm_pid(), signal.SIGTERM)  # what `docker stop` does to the JVM
        code = self.srv.wait_exit(timeout=60)
        log = self.srv.log_since(mark)
        self.assertEqual(code, 128 + signal.SIGTERM, log[-3000:])
        self.assertIn("Stopped.", log)
        self.assertNotIn("connection lost", log.lower())


class LoginPassword(SharedCase):

    def test_rpc_server_makes_its_login_password_non_expiring(self):
        # Both users were created with a temporary password (what svrAdmin -add
        # records: expires after a day). RpcServer re-sets its own password on
        # every start, which the Ghidra Server stores as non-expiring ('*').
        gs = self.env.ghidra_server
        rpc_entry = _wait_for(lambda: gs.user_entry(RPC_USER), 10, what="users entry")
        self.assertEqual(rpc_entry[2], "*", rpc_entry)
        other_entry = gs.user_entry(OTHER_USER)
        self.assertNotEqual(other_entry[2], "*", other_entry)


if __name__ == "__main__":
    unittest.main()
