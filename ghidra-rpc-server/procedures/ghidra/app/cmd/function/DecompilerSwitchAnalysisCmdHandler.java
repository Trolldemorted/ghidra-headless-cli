package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.SwitchAnalysisDecompileConfigurer;
import ghidra.program.model.listing.Function;

/**
 * Procedure DecompilerSwitchAnalysisCmd: recover switch tables for the function at
 * {@code address}. Decompiles the function first to feed the command its results.
 *
 * <p>The decompiler is set up exactly like Ghidra's "Decompiler Switch
 * Analysis" analyzer does ({@link SwitchAnalysisDecompileConfigurer}): jump
 * loads on (without them the command has no table addresses to label), no C
 * output or syntax tree, and dead-code elimination off, since the switch may
 * sit in code the decompiler considers unreachable.
 */
public final class DecompilerSwitchAnalysisCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Function f = ctx.requireFunctionAt(RpcContext.reqStr(req, "address"));
        int timeout = RpcContext.reqInt(req, "timeout");
        DecompInterface di = new DecompInterface();
        try {
            new SwitchAnalysisDecompileConfigurer(ctx.program()).configure(di);
            if (!di.openProgram(ctx.program())) {
                return RpcResponse.error("Could not start the decompiler: " + di.getLastMessage());
            }
            DecompileResults results = di.decompileFunction(f, timeout, ctx.monitor());
            if (results == null || !results.decompileCompleted()
                    || results.getHighFunction() == null) {
                String why = results == null ? null : results.getErrorMessage();
                return RpcResponse.error("Decompilation did not complete for " + f.getName()
                    + (why == null || why.isBlank() ? "." : ": " + why.trim()));
            }
            DecompilerSwitchAnalysisCmd cmd = new DecompilerSwitchAnalysisCmd(results);
            RpcResponse r = ctx.applyCommand(cmd);
            // The command returns true even when it failed; the only sign is
            // its status message.
            String status = cmd.getStatusMsg();
            if (r.success && status != null && !status.isBlank()) {
                return RpcResponse.error("Switch analysis failed for " + f.getName() + ": " + status);
            }
            return r;
        } finally {
            di.dispose();
        }
    }
}
