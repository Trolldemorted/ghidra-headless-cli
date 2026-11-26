package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.DeleteVariableCmd;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;

/** Procedure DeleteVariableCmd: delete a named variable from a function. */
public final class DeleteVariableCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Function f = ctx.requireFunctionAt(RpcContext.reqStr(req, "address"));
        Variable v = ctx.requireVariable(f, RpcContext.reqStr(req, "name"));
        if (v instanceof ghidra.program.model.listing.Parameter
                && ((ghidra.program.model.listing.Parameter) v).isAutoParameter()) {
            // Auto-parameters (this, __return_storage_ptr__) are synthesized from
            // the calling convention; Ghidra silently ignores removal on them
            // and the command still returns true.
            return RpcResponse.error("'" + v.getName() + "' is an auto-parameter injected by the "
                + "calling convention; it cannot be deleted.");
        }
        return ctx.applyCommand(new DeleteVariableCmd(v));
    }
}
