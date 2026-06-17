// VerifyStruct.java - read-only check that the committed struct is present in the
// LATEST repository version, i.e. visible to a fresh/other Ghidra client.
//@category Examples.Headless
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;

public class VerifyStruct extends GhidraScript {
    @Override
    public void run() throws Exception {
        String name = env("STRUCT_NAME", "ClaudeHeadlessStruct");
        CategoryPath cat = new CategoryPath(env("STRUCT_CATEGORY", "/ClaudeHeadless"));
        DataType dt = currentProgram.getDataTypeManager().getDataType(cat, name);
        println("[Verify] program=" + currentProgram.getDomainFile().getPathname()
                + " version=" + currentProgram.getDomainFile().getVersion());
        if (dt == null) {
            println("[Verify] RESULT=MISSING " + cat.getPath() + "/" + name);
        } else {
            println("[Verify] RESULT=PRESENT " + dt.getPathName()
                    + " size=" + dt.getLength() + " desc=\"" + dt.getDescription() + "\"");
        }
    }

    private String env(String k, String d) { String v = System.getenv(k); return (v == null || v.isEmpty()) ? d : v; }
}
