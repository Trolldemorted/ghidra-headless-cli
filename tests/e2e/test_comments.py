"""Comment procedures, named after the GUI's Comments menu."""

from harness import E2ETest, SYM, hx


class Comments(E2ETest):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.program = cls.srv.fresh_program(analyze=True)

    def get(self, kind, address):
        return self.ok("comment", kind, "get", "--file", self.program, "--address", hx(address)).out.rstrip("\n")

    def test_set_get_append_clear(self):
        addr = SYM["twice"]
        f = ("--file", self.program, "--address", hx(addr))
        for kind in ("eol", "pre", "post", "repeatable"):
            self.ok("comment", kind, "set", *f, "--text", "first " + kind)
            self.assertEqual(self.get(kind, addr), "first " + kind)
            self.ok("comment", kind, "append", *f, "--text", "second")
            self.assertEqual(self.get(kind, addr), "first %s\nsecond" % kind)
            self.ok("comment", kind, "clear", *f)
            self.assertEqual(self.get(kind, addr), "")

    def test_clear_removes_the_comment_instead_of_storing_an_empty_one(self):
        # A stored "" made the next append start with the separator.
        addr = SYM["sw"]
        f = ("--file", self.program, "--address", hx(addr))
        self.ok("comment", "eol", "clear", *f)
        self.ok("comment", "eol", "append", *f, "--text", "x")
        self.assertEqual(self.get("eol", addr), "x")
        # Set without text clears as well.
        self.ok("comment", "eol", "set", *f)
        self.ok("comment", "eol", "append", *f, "--text", "y")
        self.assertEqual(self.get("eol", addr), "y")

    def test_decompiler_comment_at_function_entry_is_the_plate_comment(self):
        addr = SYM["helper"]
        r = self.ok("comment", "decompiler", "set", "--file", self.program, "--address", hx(addr),
                    "--text", "banner for helper")
        self.assertIn("PLATE", r.err)
        self.assertEqual(self.get("plate", addr), "banner for helper")
        self.assertEqual(self.get("decompiler", addr), "banner for helper")

    def test_decompiler_comment_inside_a_function_is_a_pre_comment(self):
        # Second instruction of helper; ask for an address in its middle, as a
        # click in the Decompiler window may give.
        rows = self.listing(self.program, SYM["helper"], SYM["helper"] + 16)
        second = int(rows[1]["address"], 16)
        r = self.ok("comment", "decompiler", "set", "--file", self.program, "--address", hx(second + 1),
                    "--text", "about this statement")
        self.assertIn("PRE", r.err)
        self.assertIn("%08x" % second, r.err)
        self.assertEqual(self.get("pre", second), "about this statement")
        # The function's own banner is untouched by it.
        self.assertNotIn("about this statement", self.get("plate", SYM["helper"]))

    def test_both_show_up_in_the_decompiled_function(self):
        entry = SYM["mkbig"]
        rows = self.listing(self.program, entry, entry + 16)
        inner = int(rows[1]["address"], 16)
        self.ok("comment", "decompiler", "set", "--file", self.program, "--address", hx(entry),
                "--text", "MKBIG-BANNER")
        self.ok("comment", "decompiler", "set", "--file", self.program, "--address", hx(inner),
                "--text", "MKBIG-INNER")
        code = self.ok("function", "decompile", "--file", self.program, "--function", hx(entry)).out
        self.assertIn("MKBIG-BANNER", code)
        self.assertIn("MKBIG-INNER", code)

    def test_decompiler_comment_outside_a_function_is_an_error(self):
        self.fails("comment", "decompiler", "set", "--file", self.program, "--address", hx(SYM["g_blob"]),
                   "--text", "x", mentions="No function contains")
