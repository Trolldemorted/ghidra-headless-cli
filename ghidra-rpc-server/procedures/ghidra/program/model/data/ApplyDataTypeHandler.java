package procedures.ghidra.program.model.data;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure ApplyDataType: apply a data type at an address (or address range).
 *
 * Either {@code address} (single) or {@code addressSet} ({@code [{start,end?},...]})
 * is required. {@code type} is parsed via {@link RpcContext#requireDataType} against
 * the program's DTM. {@code length} (single-address only) is the number of bytes to
 * consume; defaults to the type's length. When a range is supplied, the type is
 * applied at every aligned address within the range.
 *
 * Reads-then-mutates: existing code units are cleared first (so an instruction
 * doesn't fight the new data), then {@link Listing#createData} lays the type.
 * Built-in-only types like {@code int} work fine; user-defined types work too.
 */
public final class ApplyDataTypeHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String typeText = RpcContext.reqStr(req, "type");
        DataType dt = ctx.requireDataType(typeText);

        // Ghidra's Listing.createData(addr, dt, len) honors `len` ONLY for
        // Dynamic types (typedefs of arrays, strings, FactoryDataType-based
        // composites). For fixed-length types (int, char, struct, union,
        // primitive pointer, ...) it silently overwrites `len` with
        // dt.getLength(). Treating --length as a hint that works
        // everywhere would be a footgun: passing --length 1 on int lays 4
        // bytes, surprising the caller. So when --length is supplied for a
        // non-Dynamic type AND it differs from dt.getLength(), hard-error.
        // Equal-length requests are silently accepted (no-op hint).
        boolean lengthRequested = req.has("length");
        boolean isDynamic = dt instanceof ghidra.program.model.data.Dynamic;
        int requestedLen = (int) Math.min((long) dt.getLength(), Integer.MAX_VALUE);
        if (lengthRequested) {
            requestedLen = RpcContext.optInt(req, "length", requestedLen);
            if (!isDynamic && requestedLen != dt.getLength()) {
                return RpcResponse.error(
                    "Cannot override length for non-Dynamic type '" + dt.getName()
                    + "' (" + dt.getLength() + " bytes); 'length' is only honored for Dynamic types "
                    + "(typedefs, strings, FactoryDataType). Drop --length or pick a Dynamic type.");
            }
        }
        int len = requestedLen;

        AddressSetView range = ctx.addressSet(req);

        int[] created = {0};
        long[] bytes = {0};
        ctx.runWrite("ApplyDataType", () -> {
            Listing listing = ctx.program().getListing();
            // Iterate every address in the range. Single-address requests use a
            // single-element set, so the loop handles both uniformly.
            AddressIterator it = range.getAddresses(true);
            while (it.hasNext()) {
                Address a = it.next();
                listing.clearCodeUnits(a, a, false);
                Data d = listing.createData(a, dt, len);
                if (d != null) {
                    created[0]++;
                    bytes[0] += d.getLength();
                }
            }
        });

        JsonObject o = new JsonObject();
        o.addProperty("success", true);
        o.addProperty("type", dt.getDisplayName());
        o.addProperty("path", DataTypeSerializer.pathOf(dt));
        o.addProperty("created", created[0]);
        o.addProperty("bytes", bytes[0]);
        return new ApplyResponse(o);
    }

    static final class ApplyResponse extends RpcResponse {
        final String type;
        final String path;
        final int created;
        final long bytes;
        ApplyResponse(JsonObject o) {
            this.success = true;
            this.type = o.get("type").getAsString();
            this.path = o.has("path") ? o.get("path").getAsString() : null;
            this.created = o.get("created").getAsInt();
            this.bytes = o.get("bytes").getAsLong();
        }
    }
}
