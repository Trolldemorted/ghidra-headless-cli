"""Data-type management."""

import json

from harness import E2ETest


class DataTypes(E2ETest):

    def setUp(self):
        self.program = self.srv.fresh_program()
        self.f = ("--file", self.program)

    def struct(self, name, fields, *extra):
        return self.ok("datatype", "create", *self.f, "--kind", "struct", "--name", name,
                       "--fields", json.dumps(fields), *extra)

    def show(self, path):
        return self.ok("datatype", "show", *self.f, "--path", path).out

    def detail(self, path):
        out = self.ok("datatype", "show", *self.f, "--path", path, "--json").out
        data = json.loads(out)
        return data.get("detail", data)

    # ---- create / show / delete ------------------------------------------

    def test_create_show_delete(self):
        self.struct("S", [{"name": "a", "type": "int"}, {"name": "b", "type": "char"}])
        text = self.show("/S")
        self.assertIn("int a;", text)
        self.assertIn("char b;", text)
        self.ok("datatype", "delete", *self.f, "--path", "/S")
        self.fails("datatype", "show", *self.f, "--path", "/S")

    def test_64_bit_enum_values_survive(self):
        # 2^53 + 1 is the first integer an f64 cannot hold.
        self.ok("datatype", "create", *self.f, "--kind", "enum", "--name", "E", "--enum-size", "8",
                "--entries", json.dumps([{"name": "BIG", "value": 9007199254740993},
                                         {"name": "NEG", "value": -2}]))
        text = self.show("/E")
        self.assertIn("BIG=9007199254740993", text)
        self.assertIn("NEG=-2", text)

    def test_body_flags_must_be_json_arrays(self):
        r = self.fails("datatype", "create", *self.f, "--kind", "struct", "--name", "X",
                       "--fields", '{"name":"a","type":"int"}', mentions="must be a JSON array")
        self.fails("datatype", "show", *self.f, "--path", "/X")
        self.assertNotIn("created", r.text)

    def test_body_flags_must_match_the_kind(self):
        self.fails("datatype", "create", *self.f, "--kind", "enum", "--name", "X",
                   "--fields", '[{"name":"a","type":"int"}]', mentions="does not apply")
        self.fails("datatype", "create", *self.f, "--kind", "struct", "--name", "X",
                   "--entries", '[{"name":"A","value":1}]', mentions="does not apply")
        self.fails("datatype", "show", *self.f, "--path", "/X")

    # ---- protection of built-ins -----------------------------------------

    def test_builtins_cannot_be_replaced_or_deleted(self):
        self.fails("datatype", "replace", *self.f, "--kind", "struct", "--name", "int",
                   "--fields", '[{"name":"a","type":"char"}]', mentions="built-in")
        # Built-ins appear in the program once something uses them; deleting
        # one would turn those fields into -BAD-.
        self.struct("P", [{"name": "p", "type": "int *"}, {"name": "i", "type": "int"}])
        self.fails("datatype", "delete", *self.f, "--path", "/int", mentions="built-in")
        self.fails("datatype", "delete", *self.f, "--path", "/int *", mentions="built-in")
        self.assertIn("int *p;", self.show("/P"))

    # ---- limits -----------------------------------------------------------

    def test_struct_size_is_capped(self):
        reply = self.rpc({"procedure": "CreateDataType", "file": self.program, "kind": "struct",
                          "name": "Huge", "size": 2000000000, "enumSize": 4, "varArgs": False,
                          "noReturn": False, "fields": []})
        self.assertFalse(reply["success"])

    def test_deeply_nested_parentheses_are_rejected_quickly(self):
        # Ghidra's C parser backtracks exponentially on these (a minute at 24).
        nested = "(" * 30 + "x" + ")" * 30
        self.fails("datatype", "create", *self.f, "--name", "Deep",
                   "--definition", "struct Deep { int a[sizeof(%s)]; };" % nested,
                   mentions="parentheses", timeout=30)

    # ---- edit by definition -----------------------------------------------

    def test_edit_by_definition_edits_the_type_in_its_category(self):
        # The parser creates types in the root category; the edit used to
        # leave /Cat/T alone and create a second T in the root.
        self.ok("datatype", "replace", *self.f, "--path", "/Cat/T", "--kind", "struct",
                "--fields", '[{"name":"old","type":"int"}]')
        self.ok("datatype", "edit", *self.f, "--path", "/Cat/T",
                "--definition", "struct T { char renewed; };")
        self.assertIn("char renewed;", self.show("/Cat/T"))
        self.fails("datatype", "show", *self.f, "--path", "/T")

    # ---- fields -----------------------------------------------------------

    def filler(self):
        """A 16-byte struct that is all undefined filler."""
        reply = self.rpc({"procedure": "CreateDataType", "file": self.program, "kind": "struct",
                          "name": "Fill", "size": 16, "enumSize": 4, "varArgs": False,
                          "noReturn": False, "fields": []})
        self.assertTrue(reply["success"], reply)

    def test_undefined_filler_cannot_be_named_or_commented(self):
        self.filler()
        self.fails("datatype", "set-field-name", *self.f, "--path", "/Fill", "--field", "@0x4",
                   "--name", "foo", mentions="undefined filler")
        self.fails("datatype", "set-field-comment", *self.f, "--path", "/Fill", "--field", "@0x4",
                   "--comment", "hi", mentions="undefined filler")
        self.assertNotIn("foo", self.show("/Fill"))

    def test_filler_becomes_a_field_by_typing_it(self):
        self.filler()
        self.ok("datatype", "set-field-type", *self.f, "--path", "/Fill", "--field", "@0x4", "--type", "char")
        # A longer type needs --force.
        self.fails("datatype", "set-field-type", *self.f, "--path", "/Fill", "--field", "@0x8", "--type", "int",
                   mentions="does not match")
        self.ok("datatype", "set-field-type", *self.f, "--path", "/Fill", "--field", "@0x8", "--type", "int",
                "--force")
        r = self.ok("datatype", "set-field-name", *self.f, "--path", "/Fill", "--field", "@0x8",
                    "--name", "my field")
        # Ghidra rewrites the space; the reply shows what was stored.
        self.assertIn("my_field", r.text)
        self.ok("datatype", "set-field-comment", *self.f, "--path", "/Fill", "--field", "@0x8",
                "--comment", "has a } brace")
        text = self.show("/Fill")
        self.assertIn("int my_field;", text)
        self.assertEqual(self.detail("/Fill")["size"], 16)
        # The brace in the comment must not cut the C output short.
        self.assertTrue(text.rstrip().endswith("};"), text)

    def test_retyping_a_bitfield_needs_force(self):
        self.ok("datatype", "create", *self.f, "--name", "BF",
                "--definition", "struct BF { unsigned a:3; unsigned b:5; int z; };")
        self.fails("datatype", "set-field-type", *self.f, "--path", "/BF", "--field", "a", "--type", "uchar",
                   mentions="bitfield")
        names = [fld["name"] for fld in self.detail("/BF")["fields"]]
        self.assertEqual(names, ["a", "b", "z"])

    # ---- referrers --------------------------------------------------------

    def test_referrers_are_told_apart_by_full_path(self):
        # /A/X/T and /B/X/T used to be the same "X/T" to the referrer search.
        for path, field in (("/A/X/T", "int"), ("/B/X/T", "char")):
            self.ok("datatype", "replace", *self.f, "--path", path, "--kind", "struct",
                    "--fields", json.dumps([{"name": "v", "type": field}]))
        self.struct("UsesA", [{"name": "t", "type": "/A/X/T"}])
        r = self.ok("datatype", "delete", *self.f, "--path", "/B/X/T")
        self.assertNotIn("UsesA", r.text)
        r = self.ok("datatype", "delete", *self.f, "--path", "/A/X/T")
        self.assertIn("/UsesA", r.text)

    def test_list_shows_types_in_nested_categories(self):
        self.ok("datatype", "replace", *self.f, "--path", "/Top/Mid/Leaf/T", "--kind", "struct",
                "--fields", '[{"name":"v","type":"int"}]')
        for category in ("/Top", "/Top/", "Top"):
            out = self.ok("datatype", "list", *self.f, "--category", category).out
            self.assertIn("Mid/", out, category)
            self.assertIn("Leaf/", out, category)
            self.assertIn("T ", out, category)
