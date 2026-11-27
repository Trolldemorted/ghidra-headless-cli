"""Classes, namespaces, and labels inside them."""

from harness import E2ETest, SYM, hx

BLOB = SYM["g_blob"]


class Namespaces(E2ETest):

    def setUp(self):
        self.program = self.srv.fresh_program(analyze=True)
        self.f = ("--file", self.program)

    def classes(self, *extra):
        out = self.ok("namespace", "list-class", *self.f, *extra).out
        return [line.strip() for line in out.splitlines() if line.strip()]

    def make(self, parent, name):
        self.ok("namespace", "create-class", *self.f, "--parent", parent, "--name", name)

    def labels(self, address):
        reply = self.rpc({"procedure": "GetLabel", "file": self.program, "address": hx(address)})
        return {(e["name"], e.get("namespace")) for e in reply["all"]}

    def test_nested_classes_are_listed(self):
        self.make("/", "Outer")
        self.make("/Outer", "Inner")
        self.make("/Outer/Inner", "Deep")
        self.assertEqual(self.classes(), ["/Outer", "/Outer/Inner", "/Outer/Inner/Deep"])
        self.assertEqual(self.classes("--parent", "/Outer"), ["/Outer/Inner", "/Outer/Inner/Deep"])
        self.assertEqual(self.classes("--recursive", "false"), ["/Outer"])

    def test_a_function_with_the_same_name_does_not_make_the_class_ambiguous(self):
        self.make("/", "Widget")
        self.ok("function", "set-name", *self.f, "--address", hx(SYM["sw"]), "--name", "Widget")
        self.ok("namespace", "get-class", *self.f, "--class", "/Widget")

    def test_a_function_is_not_a_namespace(self):
        self.fails("memory", "create-label", *self.f, "--address", hx(BLOB), "--name", "x",
                   "--namespace", "/helper", mentions="No namespace found")

    def test_create_label_in_a_class(self):
        self.make("/", "Outer")
        self.make("/Outer", "Inner")
        r = self.ok("memory", "create-label", *self.f, "--address", hx(BLOB + 16), "--name", "vtab",
                    "--namespace", "/Outer/Inner")
        self.assertIn("/Outer/Inner", r.err)
        self.ok("memory", "create-label", *self.f, "--address", hx(BLOB + 16), "--name", "vtab")
        # Same name twice at one address, told apart by namespace.
        self.assertEqual(self.labels(BLOB + 16), {("vtab", "/Outer/Inner"), ("vtab", None)})

    def test_create_label_in_a_missing_namespace_is_an_error(self):
        self.fails("memory", "create-label", *self.f, "--address", hx(BLOB + 16), "--name", "x",
                   "--namespace", "/Nope", mentions="No namespace found")
        self.assertEqual(self.labels(BLOB + 16), set())

    def test_colons_in_a_name_are_not_a_path(self):
        self.ok("memory", "create-label", *self.f, "--address", hx(BLOB + 24), "--name", "A::b")
        self.assertEqual(self.labels(BLOB + 24), {("A::b", None)})

    def test_deleting_a_class_keeps_its_functions_and_labels(self):
        self.make("/", "Outer")
        self.make("/Outer", "Inner")
        self.ok("function", "set-class-association", *self.f, "--address", hx(SYM["helper"]),
                "--class", "/Outer/Inner")
        self.ok("memory", "create-label", *self.f, "--address", hx(BLOB + 16), "--name", "inner_label",
                "--namespace", "/Outer/Inner")
        self.ok("memory", "create-label", *self.f, "--address", hx(BLOB + 20), "--name", "outer_label",
                "--namespace", "/Outer")

        self.ok("namespace", "delete-class", *self.f, "--class", "/Outer")

        self.assertEqual(self.classes(), [])
        self.assertEqual(self.labels(BLOB + 16), {("inner_label", None)})
        self.assertEqual(self.labels(BLOB + 20), {("outer_label", None)})
        # The function is still a function, now in the global namespace.
        self.assertIn("helper", self.ok("function", "show", *self.f, "--address", hx(SYM["helper"])).text)
        self.assertEqual(self.labels(SYM["helper"]), {("helper", None)})

    def test_rename_nested_class(self):
        self.make("/", "Outer")
        self.make("/Outer", "Inner")
        self.ok("namespace", "rename-class", *self.f, "--class", "/Outer/Inner", "--name", "Renamed")
        self.assertEqual(self.classes(), ["/Outer", "/Outer/Renamed"])


class Labels(E2ETest):

    def setUp(self):
        self.program = self.srv.fresh_program(analyze=True)
        self.f = ("--file", self.program)

    def test_dynamic_label_cannot_be_deleted(self):
        # A default label (LAB_/DAT_...) is generated from references; "deleting"
        # it used to report success while nothing happened.
        # main() takes &g_blob[2]; once g_blob is no longer one array, that
        # reference gets a generated DAT_ label.
        self.undefine(self.program, SYM["g_blob"], SYM["g_blob"] + 64)
        rows = self.listing(self.program, SYM["g_blob"], SYM["g_blob"] + 8)
        dynamic = [r for r in rows if r["label"].startswith("DAT_")]
        self.assertTrue(dynamic, rows)
        self.fails("memory", "delete-label", *self.f, "--query", dynamic[0]["label"],
                   "--address", "0x" + dynamic[0]["address"])

    def test_create_rename_delete(self):
        addr = hx(SYM["g_bss"] + 8)
        self.ok("memory", "create-label", *self.f, "--address", addr, "--name", "first")
        self.ok("memory", "rename-label", *self.f, "--query", "first", "--name", "second")
        self.assertEqual(self.ok("memory", "get-label", *self.f, "--address", addr).out.strip(), "second")
        self.ok("memory", "delete-label", *self.f, "--query", "second")
        self.fails("memory", "delete-label", *self.f, "--query", "second")
