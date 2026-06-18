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
 * Procedure GetString: return the single defined string (if any) at
 * {@code address}. Mirrors {@link GetLabelHandler}'s shape — the response
 * carries the {@code address} back plus a {@code string} field that is
 * either the per-string details or {@code null} when the address does not
 * host a defined string.
 *
 * <p>Read-only. Unlike {@link SearchStringsHandler} this procedure does NOT
 * walk the program — it is an O(1) listing lookup ({@link Listing#getDataAt}).
 */
public final class GetStringHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address addr = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        Data data = ctx.program().getListing().getDataAt(addr);
        // Use isString (not just getStringDataInstance != null): the latter
        // returns a non-null wrapper for any initialized-memory data, so after
        // a delete that left a 1-byte undefined Data at the address, the miss
        // would otherwise look like a hit with dataType="undefined".
        DefinedStringMatch match = null;
        if (data != null && StringDataInstance.isString(data)) {
            StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
            match = new DefinedStringMatch(
                data.getAddress().toString(),
                sdi.getStringValue(),
                sdi.getStringRepresentation(),
                data.getLength(),
                sdi.getCharsetName(),
                data.getDataType().getName()
            );
        }
        return new GetStringResponse(addr.toString(), match);
    }

    @Override
    public boolean mutates() {
        return false;
    }
}
