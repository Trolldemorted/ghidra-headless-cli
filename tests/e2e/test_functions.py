"""Function-level procedures."""

import json

from harness import E2ETest, SYM, hx


class Functions(E2ETest):

    def setUp(self):
        self.program = self.srv.fresh_program(analyze=True)
        self.f = ("--file", self.program)

    def test_function_definition_from_source_skips_the_hidden_return_pointer(self):
        # A __thiscall function returning a 32-byte struct has two auto
        # parameters: `this` and __return_storage_ptr__. Only `this` belongs
        # in the function definition; the other follows from the return type.
        entry = hx(SYM["mkbig"])
        self.ok("datatype", "create", *self.f, "--name", "big",
                "--definition", "struct big { long a; long b; long c; long d; };")
        self.ok("function", "apply-signature", *self.f, "--address", entry, "--signature", "big mkbig(long v)")
        self.ok("function", "update", *self.f, "--address", entry, "--calling-convention", "__thiscall")
        shown = self.ok("function", "show", *self.f, "--address", entry).text
        self.assertIn("__return_storage_ptr__", shown)
        self.assertIn("this", shown)

        self.ok("function", "create-definition", *self.f, "--address", entry)
        out = self.ok("datatype", "show", *self.f, "--path", "/mkbig", "--json").out
        detail = json.loads(out)
        detail = detail.get("detail", detail)
        self.assertEqual([p["name"] for p in detail["parameters"]], ["this", "v"])
        self.assertEqual(detail["returnType"], "big")
        self.assertEqual(detail["callingConvention"], "__thiscall")

    def test_switch_analysis(self):
        self.ok("analysis", "decompiler-switch", *self.f, "--address", hx(SYM["sw"]), "--timeout", "60")
        rows = self.listing(self.program, SYM["sw"], SYM["sw"] + 0x60)
        self.assertTrue(any(r["label"].startswith("caseD_") for r in rows), [r["label"] for r in rows])
        self.fails("analysis", "decompiler-switch", *self.f, "--address", hx(SYM["g_blob"]), "--timeout", "60",
                   mentions="No function")

    def test_comment_and_return_type_need_a_function(self):
        # Ghidra's commands return true when there is no function there.
        nowhere = hx(SYM["g_blob"])
        self.fails("function", "set-repeatable-comment", *self.f, "--address", nowhere, "--comment", "x")
        self.fails("function", "set-return-type", *self.f, "--address", nowhere, "--data-type", "int")

    def test_tags(self):
        entry = hx(SYM["twice"])
        self.ok("function", "tag", "create", *self.f, "--name", "hot", "--comment", "c")
        self.ok("function", "tag", "add", *self.f, "--address", entry, "--tag", "hot")
        # Deleting a tag that does not exist is an error, not a silent success.
        self.fails("function", "tag", "delete", *self.f, "--name", "no-such-tag")
        # An unknown field used to be treated as "rename the tag".
        self.fails("function", "tag", "change", *self.f, "--tag-name", "hot", "--value", "oops",
                   "--field", "coment")
        self.ok("function", "tag", "change", *self.f, "--tag-name", "hot", "--value", "described",
                "--field", "comment")

    def test_decompile_and_disassemble(self):
        code = self.ok("function", "decompile", *self.f, "--function", "twice").out
        self.assertEqual(code.count("helper("), 3)
        asm = self.ok("function", "disassemble", *self.f, "--function", "twice").out
        self.assertEqual(asm.count("CALL"), 3)

    def test_decompiler_variable_rename(self):
        code = self.ok("function", "decompile", *self.f, "--function", "helper").out
        self.assertIn("param_1", code)
        self.ok("function", "variable", "set-decompiler-name", *self.f, "--address", hx(SYM["helper"]),
                "--decompiler-name", "param_1", "--name", "count")
        code = self.ok("function", "decompile", *self.f, "--function", "helper").out
        self.assertIn("count", code)
        self.assertNotIn("param_1", code)
