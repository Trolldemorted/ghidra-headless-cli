// Read-only check that function-command RPC edits persisted to the server.
//@category RPC
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class VerifyFnCmd extends GhidraScript {
    @Override
    public void run() throws Exception {
        Function f = currentProgram.getFunctionManager().getFunctionAt(
            currentProgram.getAddressFactory().getAddress("4024f1"));
        if (f == null) {
            println("VERIFY 4024f1 -> <none>");
            return;
        }
        println("VERIFY name=" + f.getName()
            + " returnType=" + f.getReturnType().getName()
            + " params=" + f.getParameterCount()
            + " tags=" + f.getTags()
            + " version=" + currentProgram.getDomainFile().getVersion());
    }
}
