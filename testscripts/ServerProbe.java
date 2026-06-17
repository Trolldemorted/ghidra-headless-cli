// ServerProbe.java - read-only headless probe.
// Confirms we connected to the shared Ghidra Server repository and can see programs.
// Run by analyzeHeadless as a -postScript over an existing (shared) program.
//@category Examples.Headless
import ghidra.app.script.GhidraScript;

public class ServerProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("[ServerProbe] connected program: " + currentProgram.getDomainFile().getPathname());
        println("[ServerProbe] is shared/versioned: " + currentProgram.getDomainFile().isVersioned());
        println("[ServerProbe] data type count: " +
                currentProgram.getDataTypeManager().getDataTypeCount(true));
    }
}
