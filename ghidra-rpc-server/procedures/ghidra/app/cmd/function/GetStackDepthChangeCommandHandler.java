package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.program.model.address.Address;

/**
 * Procedure GetStackDepthChangeCommand: read the stack-depth-change
 * override currently in effect at {@code address}, if any.
 *
 * <p>Wraps the read-only half of the override machinery
 * ({@link CallDepthChangeInfo#getStackDepthChange}). Distinguishes
 * "unset" ({@code depthChange: null}) from "set and ignored" (returns
 * the value that the decompiler would consult) — see
 * {@link SetStackDepthChangeCommandHandler} for why the latter is
 * possible at indirect call sites.
 *
 * <p>Subclasses {@link RpcResponse} so the extra {@code address} /
 * {@code depthChange} fields are emitted by gson alongside the
 * standard {@code success} flag.
 */
public final class GetStackDepthChangeCommandHandler implements RpcProcedure {

    public static final class GetResponse extends RpcResponse {
        public String address;
        // Integer boxed so unset -> JSON null. Set to a primitive int
        // when present.
        public Integer depthChange;

        public GetResponse(String address, Integer depthChange) {
            this.success = true;
            this.address = address;
            this.depthChange = depthChange;
        }
    }

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address addr = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        Integer value = CallDepthChangeInfo.getStackDepthChange(
            ctx.program(), addr);
        return new GetResponse(addr.toString(), value);
    }
}