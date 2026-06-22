package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.program.model.address.Address;

/**
 * Procedure SetFunctionNameCmd: rename the function whose entry point is
 * {@code address}.
 *
 * <p><b>No-op guard.</b> Ghidra's
 * {@link ghidra.app.cmd.function.SetFunctionNameCmd#applyTo} returns
 * {@code true} immediately when
 * {@code Listing.getFunctionAt(entry)} is {@code null} (verified by
 * disassembling {@code SetFunctionNameCmd.class} in
 * {@code Base.jar} for Ghidra 12.1.2 — bytecode at offset 31-36 is
 * {@code ifnonnull 37; iconst_1; ireturn}). The caller would see
 * {@code success: true} but nothing was renamed — the program is not
 * dirty, no function is created, no symbol is renamed. The user has
 * no way to tell the call was a no-op without doing a follow-up
 * {@code find-by-name}.
 *
 * <p>This handler detects that case up front and surfaces a clear
 * error pointing at {@code CreateFunctionCmd} (which can create the
 * function with the desired name in one call) or
 * {@code CreateFunctionCmd} followed by a fresh
 * {@code SetFunctionNameCmd}. This mirrors the silent-no-op guard
 * added to {@code CreateFunctionCmdHandler}.
 */
public final class SetFunctionNameCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String name = RpcContext.reqStr(req, "name");
        if (ctx.program().getFunctionManager().getFunctionAt(entry) == null) {
            return RpcResponse.error(
                "No function at " + entry + "; SetFunctionNameCmd cannot rename what does not exist. "
                + "Use `function create --address " + entry + " --name " + name
                + "` to create the function with this name in one call, "
                + "or call `function create` first and then `function set-name`.");
        }
        return ctx.applyCommand(
            new SetFunctionNameCmd(entry, name, ctx.sourceType(RpcContext.optStr(req, "source"))));
    }
}
