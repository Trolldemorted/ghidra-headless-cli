// CreateStructHeadless.java
// Headless post-script that creates (or replaces) a struct definition in the
// current program's DataTypeManager. When this program lives in a shared Ghidra
// Server repository and analyzeHeadless is run WITHOUT -readOnly and WITH -commit,
// the saved struct is checked in as a new program version and becomes visible to
// every other Ghidra client that opens the file.
//
// Config via environment variables (all optional, sensible defaults):
//   STRUCT_NAME      name of the struct to create            (default ClaudeHeadlessStruct)
//   STRUCT_CATEGORY  category path inside the program's DTM  (default /ClaudeHeadless)
//
//@category Examples.Headless
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;

public class CreateStructHeadless extends GhidraScript {
    @Override
    public void run() throws Exception {
        String name = env("STRUCT_NAME", "ClaudeHeadlessStruct");
        CategoryPath cat = new CategoryPath(env("STRUCT_CATEGORY", "/ClaudeHeadless"));
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        println("[CreateStruct] program=" + currentProgram.getDomainFile().getPathname()
                + " versioned=" + currentProgram.getDomainFile().isVersioned());

        // Remove a previous version of our struct so the script is re-runnable.
        DataType existing = dtm.getDataType(cat, name);
        if (existing != null) {
            println("[CreateStruct] replacing existing " + cat.getPath() + "/" + name);
            dtm.remove(existing, monitor);
        }

        // Build a small, self-contained struct (no commit/transaction code needed:
        // headless wraps the script in a transaction and saves/commits afterward).
        StructureDataType s = new StructureDataType(cat, name, 0, dtm);
        s.add(new UnsignedIntegerDataType(dtm), 4, "magic", "marker written by headless claude");
        s.add(new IntegerDataType(dtm), 4, "count", "example field");
        s.add(new PointerDataType(new UnsignedIntegerDataType(dtm), dtm), "next", "self-ish pointer");
        s.setDescription("Created headlessly by CreateStructHeadless.java to prove "
                + "server-visible edits.");

        DataType added = dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);
        println("[CreateStruct] created " + added.getPathName()
                + " size=" + added.getLength() + " bytes");
        println("[CreateStruct] DTM data type count now: " + dtm.getDataTypeCount(true));
    }

    private String env(String k, String dflt) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? dflt : v;
    }
}
