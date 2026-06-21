package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/**
 * Procedure CreateFunctionCmd: create a function at {@code address}. Optional
 * {@code name} (default FUN_/thunk naming); body is computed by disassembly.
 *
 * <p><b>No-op guard.</b> {@link CreateFunctionCmd#applyTo} returns {@code true}
 * for an address that is already inside an existing function — even when the
 * caller passed a {@code --name} that does not match the existing function's
 * name. In that case the program is not dirty and no push happens, but the
 * status string is silently dropped and {@code RpcResponse.ok()} goes back to
 * the caller. The user would believe the function was renamed.
 *
 * <p>This handler detects the no-op by comparing the desired name against
 * the existing function's name and returns an error pointing the caller at
 * {@code SetFunctionNameCmd} (the right verb for renaming). When no
 * {@code --name} is supplied, a no-op against an existing function is still
 * a success: the function already exists, which is the desired outcome.
 */
public final class CreateFunctionCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String name = RpcContext.optStr(req, "name"); // null -> default name
        RpcResponse resp = ctx.applyCommand(new CreateFunctionCmd(
            name, entry, null, ctx.sourceType(RpcContext.optStr(req, "source"))));
        if (!resp.success || name == null || name.isEmpty()) {
            return resp;
        }
        // Command claimed success. Verify the function actually carries the
        // requested name — CreateFunctionCmd.applyTo reports success even
        // when the address already had a function with a different name.
        Function existing = ctx.program().getFunctionManager().getFunctionAt(entry);
        if (existing != null && !name.equals(existing.getName())) {
            return RpcResponse.error("Function already exists at " + entry
                + " with name '" + existing.getName()
                + "'; rename via SetFunctionNameCmd instead (or omit --name to keep the existing name).");
        }
        return resp;
    }
}
