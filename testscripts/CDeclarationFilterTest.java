import procedures.ghidra.program.model.data.CDeclarationFilter;

/**
 * Standalone unit test for {@link CDeclarationFilter#filter} — no Ghidra
 * runtime needed (the filter only imports java.util.regex.Pattern).
 *
 * Compile & run:
 *   mkdir -p /tmp/cdftest
 *   javac -d /tmp/cdftest \
 *     /workdir/ghidra-rpc-server/procedures/ghidra/program/model/data/CDeclarationFilter.java \
 *     /workdir/testscripts/CDeclarationFilterTest.java
 *   java -cp /tmp/cdftest CDeclarationFilterTest
 *
 * Covers the bug where a struct referencing another user struct (by
 * pointer OR by-value) rendered only the header + a forward-decl typedef
 * and stopped before the body.
 */
public final class CDeclarationFilterTest {

    private static int failures = 0;

    public static void main(String[] args) {
        testPointerRef();
        testByValueRef();
        testLeafStruct();
        testPreambleStripped();
        testMultipleReferencedFwdDecls();

        if (failures == 0) {
            System.out.println("ALL PASS");
        } else {
            System.out.println(failures + " FAILURE(S)");
            System.exit(1);
        }
    }

    /** Referenced struct via pointer: writer emits only Town's fwd decl. */
    private static void testPointerRef() {
        String raw = String.join("\n",
            "typedef unsigned char byte;",
            "typedef unsigned int dword;",
            "typedef struct GameWorld GameWorld, *PGameWorld;",
            "",
            "typedef struct Town Town, *PTown;",
            "",
            "struct GameWorld {",
            "    PTown townSortIndexByTown;",
            "    int merchantsBase;",
            "};");
        String out = CDeclarationFilter.filter(raw, "struct", "GameWorld");
        check("pointerRef keeps requested fwd decl",
            out.contains("typedef struct GameWorld GameWorld, *PGameWorld;"), out);
        check("pointerRef keeps referenced fwd decl",
            out.contains("typedef struct Town Town, *PTown;"), out);
        check("pointerRef emits body header", out.contains("struct GameWorld {"), out);
        check("pointerRef emits fields",
            out.contains("townSortIndexByTown") && out.contains("merchantsBase"), out);
        check("pointerRef emits body close", out.contains("};"), out);
        check("pointerRef drops builtins preamble", !out.contains("typedef unsigned char byte;"), out);
    }

    /** Referenced struct by value: writer inlines Town's FULL body before ours. */
    private static void testByValueRef() {
        String raw = String.join("\n",
            "typedef struct Outer Outer, *POuter;",
            "",
            "typedef struct Inner Inner, *PInner;",
            "",
            "struct Inner {",
            "    int a;",
            "    int b;",
            "};",
            "",
            "struct Outer {",
            "    Inner embedded;",
            "    int tag;",
            "};");
        String out = CDeclarationFilter.filter(raw, "struct", "Outer");
        check("byValue emits Outer body header", out.contains("struct Outer {"), out);
        check("byValue emits Outer fields",
            out.contains("embedded") && out.contains("int tag;"), out);
        check("byValue keeps Inner fwd decl", out.contains("typedef struct Inner Inner, *PInner;"), out);
        // Inner's inlined body must be stepped over, not emitted.
        check("byValue drops Inner body header", !out.contains("struct Inner {"), out);
        check("byValue drops Inner fields", !out.contains("int a;"), out);
    }

    /** Leaf struct with no user refs still renders fully (regression). */
    private static void testLeafStruct() {
        String raw = String.join("\n",
            "typedef struct Leaf Leaf, *PLeaf;",
            "",
            "struct Leaf {",
            "    int x;",
            "    int y;",
            "};");
        String out = CDeclarationFilter.filter(raw, "struct", "Leaf");
        check("leaf emits body", out.contains("struct Leaf {") && out.contains("int x;"), out);
        check("leaf ends at close", out.trim().endsWith("};"), out);
    }

    /** Builtins preamble ahead of everything is dropped. */
    private static void testPreambleStripped() {
        String raw = String.join("\n",
            "typedef unsigned char byte;",
            "typedef unsigned short word;",
            "typedef struct S S, *PS;",
            "",
            "struct S {",
            "    byte flag;",
            "};");
        String out = CDeclarationFilter.filter(raw, "struct", "S");
        check("preamble stripped", !out.contains("typedef unsigned char byte;"), out);
        check("preamble case body kept", out.contains("struct S {") && out.contains("byte flag;"), out);
    }

    /** Several referenced fwd decls before the body — all kept, body reached. */
    private static void testMultipleReferencedFwdDecls() {
        String raw = String.join("\n",
            "typedef struct Host Host, *PHost;",
            "typedef struct A A, *PA;",
            "typedef struct B B, *PB;",
            "typedef struct C C, *PC;",
            "struct Host {",
            "    PA pa;",
            "    PB pb;",
            "    PC pc;",
            "};");
        String out = CDeclarationFilter.filter(raw, "struct", "Host");
        check("multi keeps all fwd decls",
            out.contains("*PA;") && out.contains("*PB;") && out.contains("*PC;"), out);
        check("multi reaches body", out.contains("struct Host {") && out.contains("PC pc;"), out);
    }

    private static void check(String label, boolean cond, String ctx) {
        if (cond) {
            System.out.println("PASS: " + label);
        } else {
            failures++;
            System.out.println("FAIL: " + label + "\n--- output ---\n" + ctx + "\n--------------");
        }
    }
}
