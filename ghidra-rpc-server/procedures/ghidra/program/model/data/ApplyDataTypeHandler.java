package procedures.ghidra.program.model.data;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
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
 * consume; defaults to the type's length.
 *
 * <p><b>Single-application semantics.</b> Each range in {@code addressSet}
 * is treated as a guard for the upper bound of one type application: the
 * type is laid ONCE at the range's start address, and {@code dt.getLength()}
 * (or {@code length} for Dynamic types) determines how many bytes are
 * consumed. The range's {@code end} is an upper bound; if the type's
 * consumption is shorter than the range, the remaining bytes are left
 * untouched (and a warning is attached to the response). If the type's
 * consumption is longer than the range, the request is rejected before
 * any mutation runs.
 *
 * <p>This is what the GUI does (press D, type name, ENTER) — apply once
 * at the cursor, let the type's length extend it. The previous
 * implementation iterated every byte in the range and laid the type at
 * each address, which produced overlapping copies for any type that
 * consumes more than one byte (the user-reported {@code 17×16-byte struct
 * over a 16-byte range} bug).
 *
 * <p>Reads-then-mutates: existing code units are cleared first (so an
 * instruction doesn't fight the new data), then {@link Listing#createData}
 * lays the type. Built-in-only types like {@code int} work fine;
 * user-defined types work too.
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

        // Parse addressSet directly as [{start, end?}, ...] (or single
        // address) — we need the per-element ranges, not the flat
        // AddressSetView of every byte (the old per-byte iteration was
        // the source of the 17×16-byte bug).
        List<AddressRange> ranges = parseRanges(req, ctx);
        if (ranges.isEmpty()) {
            return RpcResponse.error("No address or addressSet provided.");
        }

        // Pre-validate every range fits the type's consumption. Reject
        // the whole request before any mutation if any range is too
        // small. Single-address entries (start == end) are exempt from
        // the size check — the type naturally extends forward from the
        // single address and the size is just `len`.
        List<String> underCoverage = new ArrayList<>();
        for (AddressRange r : ranges) {
            boolean isSingle = r.start.equals(r.end);
            if (isSingle) continue;
            long rangeBytes = r.end.subtract(r.start) + 1;
            if (len > rangeBytes) {
                return RpcResponse.error(
                    "Type '" + dt.getName() + "' consumes " + len + " bytes but range "
                    + r.start + ":" + r.end + " is only " + rangeBytes + " byte(s). "
                    + "Widen the range, shorten the type, or remove the entry from "
                    + "addressSet. --length is honored for Dynamic types only.");
            }
            if (len < rangeBytes) {
                underCoverage.add(r.start + ":" + r.end + " (type consumes "
                    + len + " of " + rangeBytes + " bytes)");
            }
        }

        int[] created = {0};
        long[] bytes = {0};
        ctx.runWrite("ApplyDataType", () -> {
            Listing listing = ctx.program().getListing();
            for (AddressRange r : ranges) {
                listing.clearCodeUnits(r.start, r.start, false);
                Data d = listing.createData(r.start, dt, len);
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
        if (!underCoverage.isEmpty()) {
            JsonArray warns = new JsonArray();
            for (String s : underCoverage) warns.add(s);
            o.add("warnings", warns);
        }
        return new ApplyResponse(o, underCoverage);
    }

    /** Internal (start, end) pair, inclusive. */
    private static final class AddressRange {
        final Address start;
        final Address end;
        AddressRange(Address start, Address end) { this.start = start; this.end = end; }
    }

    /**
     * Parse the request into a list of {@link AddressRange}. Accepts either
     * a single {@code "address"} (one-element list, end == start) or an
     * {@code "addressSet"} array of {@code {start, end?}} objects.
     */
    private static List<AddressRange> parseRanges(JsonObject req, RpcContext ctx) {
        List<AddressRange> out = new ArrayList<>();
        if (req.has("addressSet") && req.get("addressSet").isJsonArray()) {
            JsonArray arr = req.getAsJsonArray("addressSet");
            if (arr.size() == 0) return out;
            for (JsonElement e : arr) {
                JsonObject o = e.getAsJsonObject();
                Address start = ctx.requireAddress(o.get("start").getAsString());
                Address end = o.has("end") && !o.get("end").isJsonNull()
                    ? ctx.requireAddress(o.get("end").getAsString())
                    : start;
                if (end.compareTo(start) < 0) {
                    throw new IllegalArgumentException(
                        "addressSet entry end '" + end + "' precedes start '"
                        + start + "'.");
                }
                out.add(new AddressRange(start, end));
            }
            return out;
        }
        if (req.has("address") && !req.get("address").isJsonNull()) {
            Address a = ctx.requireAddress(req.get("address").getAsString());
            out.add(new AddressRange(a, a));
            return out;
        }
        return out;
    }

    static final class ApplyResponse extends RpcResponse {
        final String type;
        final String path;
        final int created;
        final long bytes;
        // List of (start:end + byte counts) for addressSet entries where
        // the type's consumption is shorter than the range. Empty when the
        // range exactly matches the type's length or when --address was
        // used (single-address entries don't track coverage). Serialized
        // by gson as a `warnings` JSON array on the response.
        final java.util.List<String> warnings;
        ApplyResponse(JsonObject o, java.util.List<String> underCoverage) {
            this.success = true;
            this.type = o.get("type").getAsString();
            this.path = o.has("path") ? o.get("path").getAsString() : null;
            this.created = o.get("created").getAsInt();
            this.bytes = o.get("bytes").getAsLong();
            this.warnings = underCoverage == null
                ? java.util.Collections.emptyList() : underCoverage;
        }
    }
}
