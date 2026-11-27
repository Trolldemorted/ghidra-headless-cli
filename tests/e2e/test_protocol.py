"""Wire protocol, authentication gates and request limits."""

import time

from harness import ADMIN_PASSWORD, E2ETest, FIXTURE, MAX_REQUEST_BYTES, SYM, hx


class Framing(E2ETest):

    def test_unknown_procedure_is_an_error_response(self):
        reply = self.rpc({"procedure": "NoSuchProcedure"})
        self.assertFalse(reply["success"])
        self.assertIn("NoSuchProcedure", reply["error"])

    def test_non_string_procedure_is_answered_not_dropped(self):
        # Used to throw outside the handler: connection closed, no response.
        for bad in ({}, [], 5, None, True):
            reply = self.rpc({"procedure": bad})
            self.assertFalse(reply["success"], bad)

    def test_garbage_line_is_answered(self):
        reply = self.srv.rpc_raw(b"this is not json\n")
        self.assertIn('"success":false', reply.replace(" ", ""))

    def test_oversized_request_line_is_rejected(self):
        reply = self.srv.rpc_raw(b'{"procedure":"ListFiles","pad":"' + b"a" * (MAX_REQUEST_BYTES + 4096) + b'"}\n')
        self.assertIn("exceeds", reply)
        # ... and the server is still there afterwards.
        self.assertFalse(self.rpc({"procedure": "NoSuchProcedure"})["success"])

    def test_integer_fields_must_be_exact_32_bit(self):
        # gson's getAsInt() wraps 4294967296 to 0; for `keep` that meant
        # "delete every version". The gate must fire before anything happens.
        program = self.srv.fresh_program()
        for bad in (4294967296, 1.5, -4294967295):
            reply = self.rpc({"procedure": "PurgeVersions", "file": program, "keep": bad,
                              "adminPassword": ADMIN_PASSWORD})
            self.assertFalse(reply["success"], bad)
            self.assertIn("32-bit integer", reply["error"])
        self.ok("file", "metadata", "--file", program)


class WritePassword(E2ETest):

    def test_reads_need_no_password(self):
        program = self.srv.analyzed_program()
        self.ok("file", "list", password=None)
        self.ok("listing", "--file", program, "--address", hx(SYM["main"]), password=None)
        # Read-only, but used to inherit mutates() == true and demand the password.
        self.ok("stack", "get-depth-change", "--file", program, "--address", hx(SYM["main"]), password=None)

    def test_mutation_without_password_is_rejected(self):
        program = self.srv.fresh_program()
        self.fails("memory", "create-label", "--file", program, "--address", hx(SYM["g_blob"]),
                   "--name", "nope", password=None, mentions="password")
        self.fails("memory", "create-label", "--file", program, "--address", hx(SYM["g_blob"]),
                   "--name", "nope", password="wrong", mentions="password")
        r = self.ok("memory", "get-label", "--file", program, "--address", hx(SYM["g_blob"]))
        self.assertNotIn("nope", r.text)

    def test_import_needs_the_password(self):
        # Import declared mutates() == false, which skipped the gate entirely.
        self.fails("file", "load", "--name", "unauth.bin", "--file", FIXTURE, password=None,
                   mentions="password")
        self.assertNotIn("unauth.bin", self.ok("file", "list").text)


class AdminPassword(E2ETest):

    def test_file_delete_is_admin_only(self):
        program = self.srv.fresh_program()
        # No admin password at all: the CLI refuses before sending anything.
        self.fails("file", "delete", "--file", program, mentions="admin password")
        # The server enforces it too, with only the write password on the request.
        reply = self.rpc({"procedure": "DeleteFile", "file": program})
        self.assertFalse(reply["success"])
        self.assertIn("adminPassword", reply["error"])
        self.fails("file", "delete", "--file", program, admin_password="wrong")
        self.assertIn(program.lstrip("/"), self.ok("file", "list").text)

    def test_file_delete_works_on_a_file_the_server_has_open(self):
        # Ghidra refuses to delete an open or checked-out file, and the server
        # keeps every file it has touched open; it has to release it first.
        program = self.srv.fresh_program()
        self.ok("listing", "--file", program, "--address", hx(SYM["g_blob"]))
        self.ok("file", "delete", "--file", program, admin_password=ADMIN_PASSWORD)
        self.assertNotIn(program.lstrip("/"), self.ok("file", "list").text)
        self.fails("file", "metadata", "--file", program)

    def test_delete_version_needs_admin_password(self):
        program = self.srv.fresh_program()
        self.fails("file", "delete-version", "--file", program, "--keep", "1", admin_password="wrong")
        # u32 on the CLI side as well.
        self.fails("file", "delete-version", "--file", program, "--keep", "4294967296",
                   admin_password=ADMIN_PASSWORD)
        self.ok("file", "metadata", "--file", program)


class RegexBudget(E2ETest):

    def test_catastrophic_regex_is_cut_off(self):
        # Matching runs under the server-wide lock and cannot be interrupted;
        # this pattern needs minutes on a 50-character function name.
        program = self.srv.analyzed_program()
        start = time.time()
        r = self.fails("function", "find", "--file", program, "--query", r"(\w*a?){40}!",
                       "--name", "--regex", password=None)
        elapsed = time.time() - start
        self.assertIn("simplify the pattern", r.text)
        self.assertLess(elapsed, 30, "the 10 s budget did not hold")
        # An ordinary pattern still works.
        r = self.ok("function", "find", "--file", program, "--query", "^tw.ce$", "--name", "--regex")
        self.assertIn("twice", r.text)
