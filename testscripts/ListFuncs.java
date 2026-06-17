// ListFuncs.java - read-only: print the first few function entries of currentProgram.
//@category Examples.Headless
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ListFuncs extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("[ListFuncs] program=" + currentProgram.getDomainFile().getPathname());
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int n = 0;
        while (it.hasNext() && n < 8) {
            Function f = it.next();
            println("[Func] " + f.getEntryPoint() + " " + f.getName());
            n++;
        }
        println("[ListFuncs] total=" + currentProgram.getFunctionManager().getFunctionCount());
    }
}
