"""Listing rows, clearing and typing memory, byte dumps."""

import subprocess

from harness import E2ETest, SYM, hx

BLOB = SYM["g_blob"]


class ListingRows(E2ETest):

    def setUp(self):
        self.program = self.srv.fresh_program()
        # The ELF loader types g_blob as undefined1[64] from its symbol size.
        self.undefine(self.program, BLOB, BLOB + 64)

    def test_undefined_bytes_come_in_rows_of_at_most_16(self):
        rows = self.listing(self.program, BLOB, BLOB + 64)
        self.assertEqual([r["kind"] for r in rows], ["undefined"] * 4)
        self.assertEqual([int(r["address"], 16) for r in rows], [BLOB, BLOB + 16, BLOB + 32, BLOB + 48])
        self.assertEqual(rows[0]["bytes"], "01020304050607080900000000000000")
        self.assertEqual(rows[0]["label"], "g_blob")

    def test_a_labelled_byte_starts_a_new_row(self):
        self.ok("memory", "create-label", "--file", self.program, "--address", hx(BLOB + 5), "--name", "mid")
        rows = self.listing(self.program, BLOB, BLOB + 32)
        self.assertEqual([(int(r["address"], 16) - BLOB, r["label"], len(r["bytes"]) // 2) for r in rows],
                         [(0, "g_blob", 5), (5, "mid", 16), (21, "", 11)])

    def test_ranges_do_not_leak_into_each_other(self):
        reply = self.rpc({"procedure": "Listings", "file": self.program, "bytes": True, "addressSet": [
            {"start": hx(BLOB), "end": hx(BLOB + 2)}, {"start": hx(BLOB + 40), "end": hx(BLOB + 44)}]})
        self.assertEqual([(int(u["address"], 16) - BLOB, u["bytes"]) for u in reply["units"]],
                         [(0, "0102"), (40, "00000000")])

    def test_unmapped_addresses_produce_no_rows(self):
        reply = self.rpc({"procedure": "Listings", "file": self.program, "bytes": False,
                          "addressSet": [{"start": "0x10", "end": "0x20"}, {"start": "0xfffffffffffffff0"}]})
        self.assertTrue(reply["success"], reply)
        self.assertEqual(reply["count"], 0)

    def test_request_size_is_capped(self):
        reply = self.rpc({"procedure": "Listings", "file": self.program, "bytes": False,
                          "addressSet": [{"start": "0x400000", "end": "0x600000"}]})
        self.assertFalse(reply["success"])
        self.assertIn("too large", reply["error"])

    def test_cli_bytes_flag_can_be_turned_off(self):
        on = self.ok("listing", "--file", self.program, "--address-set", "%s:%s" % (hx(BLOB), hx(BLOB + 16))).out
        off = self.ok("listing", "--file", self.program, "--address-set", "%s:%s" % (hx(BLOB), hx(BLOB + 16)),
                      "--bytes", "false").out
        self.assertIn("0102030405060708", on)
        self.assertNotIn("0102030405060708", off)

    def test_closed_stdout_is_not_a_panic(self):
        # What `... | head -1` does to the CLI, made deterministic: the read
        # end is closed before the CLI has had its answer from the server, so
        # its first line of output hits a closed pipe.
        cmd = [self.srv.cli, "--host", "127.0.0.1:%d" % self.srv.port, "listing", "--file", self.program,
               "--address-set", "%s:%s" % (hx(BLOB), hx(BLOB + 64))]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.stdout.close()
        err = p.stderr.read().decode()
        self.assertEqual(p.wait(), 141, err)
        self.assertNotIn("panicked", err)


class InstructionRows(E2ETest):

    def test_range_starting_inside_an_instruction_shows_it(self):
        program = self.srv.analyzed_program()
        rows = self.listing(program, SYM["helper"], SYM["helper"] + 16)
        second = int(rows[1]["address"], 16)
        inside = self.listing(program, second + 1, second + 2)
        self.assertEqual(inside[0]["kind"], "instruction")
        self.assertEqual(int(inside[0]["address"], 16), second)


class ClearAndApply(E2ETest):

    def setUp(self):
        self.program = self.srv.fresh_program()
        self.f = ("--file", self.program)

    def blank(self):
        self.undefine(self.program, BLOB, BLOB + 64)

    def rng(self, start, end):
        return ("--address-set", "%s:%s" % (hx(start), hx(end)))

    def test_undefine_counts_defined_units(self):
        # The loader's undefined1[64] at g_blob is one unit ...
        self.assertIn("cleared 1 code unit", self.ok("memory", "undefine", *self.f, *self.rng(BLOB, BLOB + 64)).err)
        # ... and the 64 undefined bytes left behind are none.
        self.assertIn("cleared 0 code unit", self.ok("memory", "undefine", *self.f, *self.rng(BLOB, BLOB + 64)).err)
        self.ok("memory", "apply-type", *self.f, "--address", hx(BLOB), "--type", "int")
        self.ok("memory", "apply-type", *self.f, "--address", hx(BLOB + 8), "--type", "int")
        # A range that only touches the tail of the first int still clears it.
        self.assertIn("cleared 1 code unit",
                      self.ok("memory", "undefine", *self.f, *self.rng(BLOB + 2, BLOB + 4)).err)
        self.assertIn("cleared 1 code unit",
                      self.ok("memory", "undefine", *self.f, *self.rng(BLOB, BLOB + 64)).err)

    def test_apply_type_replaces_data_that_starts_at_the_address(self):
        self.blank()
        self.ok("memory", "apply-type", *self.f, "--address", hx(BLOB), "--type", "int")
        self.ok("memory", "apply-type", *self.f, "--address", hx(BLOB), "--type", "uint")
        self.assertEqual(self.listing(self.program, BLOB, BLOB + 4)[0]["type"], "uint")

    def test_apply_type_into_the_middle_of_a_unit_is_a_conflict(self):
        self.blank()
        self.ok("memory", "apply-type", *self.f, "--address", hx(BLOB), "--type", "int")
        r = self.fails("memory", "apply-type", *self.f, "--address", hx(BLOB + 2), "--type", "char",
                       mentions="Conflicting data")
        # The suggested fix must cover the byte the type needs (END is exclusive).
        self.assertIn("--address-set %08x:%08x" % (BLOB + 2, BLOB + 3), r.text)
        self.assertEqual(self.listing(self.program, BLOB, BLOB + 4)[0]["type"], "int")
        self.ok("memory", "apply-type", *self.f, "--address", hx(BLOB + 2), "--type", "char", "--force")

    def test_apply_type_does_not_silently_clear_an_instruction(self):
        program = self.srv.fresh_program(analyze=True)
        self.fails("memory", "apply-type", "--file", program, "--address", hx(SYM["twice"]), "--type", "int",
                   mentions="Conflicting instruction")
        self.assertEqual(self.listing(program, SYM["twice"], SYM["twice"] + 1)[0]["kind"], "instruction")

    def test_address_set_end_must_be_after_start(self):
        for bad in ("%s:%s" % (hx(BLOB + 8), hx(BLOB)), "0X%x:0X%x" % (BLOB + 8, BLOB)):
            self.fails("memory", "undefine", *self.f, "--address-set", bad, mentions="strictly greater")
            self.fails("memory", "apply-type", *self.f, "--type", "int", "--address-set", bad,
                       mentions="strictly greater")


class Bytes(E2ETest):

    def test_dump_rows_carry_their_own_address(self):
        program = self.srv.analyzed_program()
        out = self.ok("memory", "read-bytes", "--file", program, "--address", hx(BLOB), "--length", "40",
                      "--format", "dump").out.splitlines()
        self.assertEqual(len(out), 3)
        self.assertEqual([line.split()[0].rstrip(":").lower().lstrip("0") for line in out],
                         ["%x" % BLOB, "%x" % (BLOB + 16), "%x" % (BLOB + 32)])

    def test_string_rows_go_to_stdout(self):
        program = self.srv.analyzed_program()
        r = self.ok("string", "search", "--file", program, "--query", "fixture")
        self.assertIn("hello fixture string", r.out)
