package procedures.ghidra.program.model.listing;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure DeleteString: remove the Defined String at {@code address} from
 * the listing. Mirrors {@link GetStringHandler}'s lookup shape — same
 * point-lookup, same "is this a defined string?" check (via
 * {@link StringDataInstance#isString(Data)}).
 *
 * <p>Mutating. The whole {@code Data} unit (which may span several bytes for
 * a Pascal or fixed-length string) is removed in one transaction; the
 * underlying memory bytes are left intact so the caller can re-define a
 * different string at the same address later. Goes through
 * {@link RpcContext#runWrite} for the standard transaction + checkout path.
 */
public final class DeleteStringHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address addr = ctx.requireAddress(RpcContext.reqStr(req, "address"));

        Data data = ctx.program().getListing().getDataAt(addr);
        if (data == null) {
            return RpcResponse.error("No defined data at " + addr + ".");
        }
        if (!StringDataInstance.isString(data)) {
            return RpcResponse.error("No defined string at " + addr
                + " (data type is " + data.getDataType().getName() + ").");
        }

        // Capture the data type name + byte length BEFORE delete so the
        // response can echo what was removed.
        final String typeName = data.getDataType().getName();
        final int length = data.getLength();
        final Address start = data.getAddress();
        final Address end = start.add(length - 1);

        Throwable[] error = { null };
        try {
            ctx.runWrite("delete-string @ " + addr, () -> {
                try {
                    // clearBytes=false: remove the Data type interpretation but
                    // keep the underlying memory bytes intact, so the caller
                    // can re-define a different string at the same address.
                    Listing listing = ctx.program().getListing();
                    listing.clearCodeUnits(start, end, false);
                } catch (Exception e) {
                    error[0] = e;
                    throw new RuntimeException(e);
                }
            });
        } catch (RuntimeException re) {
            Throwable cause = re.getCause() != null ? re.getCause() : re;
            return RpcResponse.error(
                "Cannot delete string at " + addr + ": " + cause.getMessage());
        }
        if (error[0] != null) {
            return RpcResponse.error(
                "Cannot delete string at " + addr + ": " + error[0].getMessage());
        }

        return new DeleteStringResponse(addr.toString(), typeName, length);
    }

    @Override
    public boolean mutates() {
        return true;
    }
}
