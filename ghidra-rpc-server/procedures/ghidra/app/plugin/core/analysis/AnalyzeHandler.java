package procedures.ghidra.app.plugin.core.analysis;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;

/**
 * Procedure Analyze: run Ghidra's full auto-analysis pipeline over a program.
 *
 * Imports ({@code ProgramLoader}) land RAW — no functions, no disassembly. This is the
 * standalone pass that recovers them. It mirrors the headless analyzer's own sequence
 * (see {@code HeadlessAnalyzer}): {@code initializeOptions} -> {@code reAnalyzeAll(null)}
 * -> {@code startAnalysis(monitor)} inside one transaction, then mark the program
 * analyzed. {@code startAnalysis} runs on the calling thread and BLOCKS until analysis
 * completes — there is no GUI analysis tool in a headless server.
 *
 * Program-targeted and mutating (the defaults), so {@link RpcContext#dispatch} resolves
 * the {@code "file"} field, takes an EXCLUSIVE checkout BEFORE opening, and checks the
 * new version in afterward. CONCURRENCY: that exclusive checkout is held for the ENTIRE
 * analysis, which can run for minutes on a large binary; for its duration this server is
 * single-flight (the dispatch lock) AND no other repository client can check the file out.
 *
 * Request: {@code {"procedure":"Analyze","file":"/imports/foo.exe","force":true}} —
 * {@code force} (default true) re-analyzes even if already analyzed; when false an
 * already-analyzed program is left untouched and reported as such.
 */
public final class AnalyzeHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Program program = ctx.program();
        boolean force = RpcContext.reqBool(req, "force");

        boolean wasAnalyzed = GhidraProgramUtilities.isAnalyzed(program);
        if (wasAnalyzed && !force) {
            // Nothing to do: report as a no-op so dispatch still checks in cleanly (no change).
            return new AnalyzeResponse(program, false, true);
        }

        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        // One transaction around the whole pass, exactly like HeadlessAnalyzer.
        ctx.runWrite("Analysis", () -> {
            mgr.initializeOptions();      // load analysis options (program's own, or defaults)
            mgr.reAnalyzeAll(null);       // null restrict-set = the entire initialized address space
            mgr.startAnalysis(ctx.monitor()); // blocks on this thread until analysis finishes
            GhidraProgramUtilities.markProgramAnalyzed(program);
        });
        return new AnalyzeResponse(program, true, wasAnalyzed);
    }

    /** Counts that let the client confirm analysis actually recovered something. */
    static final class AnalyzeResponse extends RpcResponse {
        final boolean analyzed;       // did this call run the pipeline?
        final boolean wasAnalyzed;    // had the program been analyzed before this call?
        final long functionCount;
        final long symbolCount;
        final String format;

        AnalyzeResponse(Program program, boolean analyzed, boolean wasAnalyzed) {
            this.success = true;
            this.analyzed = analyzed;
            this.wasAnalyzed = wasAnalyzed;
            this.functionCount = program.getFunctionManager().getFunctionCount();
            this.symbolCount = program.getSymbolTable().getNumSymbols();
            this.format = program.getExecutableFormat();
        }
    }
}
