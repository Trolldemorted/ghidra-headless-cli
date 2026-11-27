"""Cross-references and the call graph."""

import json

from harness import E2ETest, SYM, hx


class Xrefs(E2ETest):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.program = cls.srv.fresh_program(analyze=True)

    def xrefs(self, to, kind="address", offcut=True):
        reply = self.rpc({"procedure": "GetXrefs", "file": self.program, "to": to, "type": kind,
                          "includeOffcut": offcut, "limit": 0})
        self.assertTrue(reply["success"], reply)
        return reply["refs"]

    def test_calls_to_a_function_are_not_offcut(self):
        refs = [r for r in self.xrefs("helper", "function") if "CALL" in r["refType"]]
        self.assertEqual(len(refs), 3)
        self.assertEqual({r["fromFunction"] for r in refs}, {"twice"})
        self.assertFalse(any(r["isOffcut"] for r in refs))

    def test_reference_into_the_middle_of_data_is_offcut(self):
        # helper() reads g_pts[1].y, 0x14 bytes into g_pts. Make g_pts one
        # 64-byte item so that address is interior to it.
        pts, field = SYM["g_pts"], SYM["g_pts"] + 0x14
        self.ok("memory", "undefine", "--file", self.program, "--address-set", "%s:%s" % (hx(pts), hx(pts + 64)))
        self.ok("memory", "apply-type", "--file", self.program, "--address", hx(pts), "--type", "byte[64]")

        direct = [r for r in self.xrefs(hx(field)) if r.get("fromFunction") == "helper"]
        self.assertEqual(len(direct), 1)
        self.assertTrue(direct[0]["isOffcut"])
        self.assertFalse(direct[0]["compositeMatch"])

        # Asking for the item's head finds it through the composite walk ...
        via_head = [r for r in self.xrefs(hx(pts)) if r.get("fromFunction") == "helper"]
        self.assertEqual(len(via_head), 1)
        self.assertTrue(via_head[0]["compositeMatch"])
        self.assertEqual(int(via_head[0]["componentAddress"], 16), field)
        # ... but not when only exact matches are wanted.
        self.assertEqual([r for r in self.xrefs(hx(pts), offcut=False) if r.get("fromFunction") == "helper"], [])


class Callgraph(E2ETest):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.program = cls.srv.analyzed_program()

    def graph(self, function, direction="called"):
        out = self.ok("callgraph", "--file", self.program, "--function", function, "--direction", direction,
                      "--depth", "3", "--format", "json").out
        return out

    def test_repeated_call_sites_are_one_edge(self):
        reply = self.rpc({"procedure": "Callgraph", "file": self.program, "function": "main",
                          "direction": "called", "depth": 3, "format": "json", "includeRefs": False})
        self.assertTrue(reply["success"], reply)
        edges = [(e["from"], e["to"]) for e in reply["edges"]]
        self.assertEqual(edges.count(("twice", "helper")), 1)
        self.assertIn(("main", "twice"), edges)
        self.assertIn(("main", "sw"), edges)
        # Edges identify their nodes by address, since names are not unique.
        by_address = {n["address"]: n["name"] for n in reply["nodes"]}
        for e in reply["edges"]:
            self.assertEqual(by_address[e["fromAddress"]], e["from"])
            self.assertEqual(by_address[e["toAddress"]], e["to"])
        self.assertEqual(len(by_address), len(reply["nodes"]), "two nodes share an address")

    def test_mermaid_output_is_well_formed(self):
        out = self.ok("callgraph", "--file", self.program, "--function", "main", "--depth", "3").out
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        self.assertEqual(lines[0], "graph TD")
        ids = set()
        for line in lines[1:]:
            if "-->" in line:
                a, b = [part.strip() for part in line.split("-->")]
                self.assertIn(a, ids, line)
                self.assertIn(b, ids, line)
            elif line.startswith("classDef"):
                continue
            elif line.startswith("class "):
                # `class id1,id2 name`: exactly one space-separated name after the list.
                self.assertEqual(len(line.split()), 3, line)
            else:
                node_id = line.split("[")[0]
                self.assertNotIn(node_id, ids, "duplicate node id: " + line)
                ids.add(node_id)
        self.assertIn("n_main", ids)

    def test_callers(self):
        reply = self.rpc({"procedure": "Callgraph", "file": self.program, "function": "helper",
                          "direction": "calling", "depth": 3, "format": "json", "includeRefs": False})
        self.assertTrue(reply["success"], reply)
        self.assertEqual({(e["from"], e["to"]) for e in reply["edges"]}, {("twice", "helper"), ("main", "twice")})
