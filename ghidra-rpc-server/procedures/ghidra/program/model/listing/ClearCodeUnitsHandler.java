package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure ClearCodeUnits: remove Data/Instruction listings from the
 * program at one or more addresses (or address ranges). Bytes are
 * preserved; the listing entries (Data type definitions, disassembled
 * Instructions, comments) at the affected addresses are cleared back to
 * "undefined".
 *
 * <p>Mirrors the GUI's "Clear Code Bytes" action on the Bytes panel —
 * useful for undoing a wrong {@code memory apply-type} (the accidental
 * 17×16-byte overlap from the per-byte iteration bug), re-laying a type
 * at the same address, or stripping disassembled instructions from a
 * region.
 *
 * <p>{@code addressSet} is {@code [{start, end?}, ...]} (mirroring
 * {@code ApplyDataType}). {@code address} (single) is also accepted; it
 * clears the code unit at that address and, per Ghidra semantics,
 * expands backward to the containing unit's min address (so clearing a
 * byte in the middle of a 4-byte int removes the whole int). Range mode
 * clears everything in {@code [start, end)} — the wire {@code end} is
 * EXCLUSIVE, so {@code 0x400000:0x400080} clears bytes
 * {@code 0x400000..0x40007f} (the wire-end is one past the last cleared
 * byte). Bare {@code {start}} (no end) clears a single byte.
 *
 * <p>The third arg to {@link Listing#clearCodeUnits} is
 * {@code clearContext}: we pass {@code false} so references and analysis
 * state are preserved — only the listing entries are removed. Pass
 * {@code clearContext: true} via the request to also drop references.
 *
 * <p>Mutating. Goes through {@link RpcContext#runWrite} so the
 * transaction, checkout and check-in happen via the standard path.
 */
public final class ClearCodeUnitsHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        List<AddressRange> ranges = parseRanges(req, ctx);
        if (ranges.isEmpty()) {
            return RpcResponse.error("Missing 'address' or 'addressSet'.");
        }
        boolean clearContext = RpcContext.reqBool(req, "clearContext");

        int[] unitsCleared = {0};
        Throwable[] error = {null};
        ctx.runWrite("ClearCodeUnits", () -> {
            try {
                Listing listing = ctx.program().getListing();
                for (AddressRange r : ranges) {
                    // Count units before clear so the response can report
                    // how many definitions actually existed. Iterating
                    // the [start, end] window and walking CodeUnits at
                    // each address is the cheapest portable approach —
                    // there's no public Listing.countCodeUnits API.
                    unitsCleared[0] += countUnits(listing, r.start, r.end);
                    listing.clearCodeUnits(r.start, r.end, clearContext);
                }
            } catch (Exception e) {
                error[0] = e;
                throw new RuntimeException(e.getMessage(), e);
            }
        });
        if (error[0] != null) {
            return RpcResponse.error(
                "ClearCodeUnits failed: " + error[0].getMessage());
        }
        return new ClearResponse(ranges.size(), unitsCleared[0]);
    }

    /** Count Data + Instruction units in [start, end] (inclusive). */
    private static int countUnits(Listing listing, Address start, Address end) {
        int n = 0;
        Address a = start;
        while (a != null && a.compareTo(end) <= 0) {
            Data d = listing.getDataAt(a);
            Instruction ins = listing.getInstructionAt(a);
            if (d != null || ins != null) n++;
            ghidra.program.model.listing.CodeUnit cu = listing.getCodeUnitAfter(a);
            if (cu == null) break;
            Address next = cu.getMinAddress();
            // getCodeUnitAfter can return an address before `a` (when the
            // next unit is at a higher address but there's an empty gap)
            // — guard against infinite loop.
            if (next.compareTo(a) <= 0) break;
            a = next;
        }
        return n;
    }

    /** Internal (start, end) pair, inclusive. */
    private static final class AddressRange {
        final Address start;
        final Address end;
        AddressRange(Address start, Address end) {
            this.start = start;
            this.end = end;
        }
    }

    /**
     * Parse the request into a list of {@link AddressRange}. Accepts
     * either a single {@code "address"} (one-element list, end == start)
     * or an {@code "addressSet"} array of {@code {start, end?}} objects.
     */
    private static List<AddressRange> parseRanges(JsonObject req, RpcContext ctx) {
        // Wire convention: `end` is EXCLUSIVE (the byte at `end` is NOT
        // included). We subtract one to get the inclusive AddressRange end.
        // Bare `{start}` (no end) is a single-byte range.
        List<AddressRange> out = new ArrayList<>();
        if (req.has("addressSet") && req.get("addressSet").isJsonArray()) {
            JsonArray arr = req.getAsJsonArray("addressSet");
            if (arr.size() == 0) return out;
            for (JsonElement e : arr) {
                JsonObject o = e.getAsJsonObject();
                Address start = ctx.requireAddress(o.get("start").getAsString());
                if (o.has("end") && !o.get("end").isJsonNull()) {
                    Address wireEnd = ctx.requireAddress(o.get("end").getAsString());
                    if (wireEnd.compareTo(start) <= 0) {
                        throw new IllegalArgumentException(
                            "addressSet entry end '" + wireEnd + "' must be strictly greater "
                            + "than start '" + start + "' (use a bare {start} for a single-byte "
                            + "range, or start:start+1 for an explicit one-byte range).");
                    }
                    out.add(new AddressRange(start, wireEnd.previous()));
                } else {
                    out.add(new AddressRange(start, start));
                }
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

    @Override
    public boolean mutates() {
        return true;
    }

    static final class ClearResponse extends RpcResponse {
        final int ranges;
        final int cleared;
        ClearResponse(int ranges, int cleared) {
            this.success = true;
            this.ranges = ranges;
            this.cleared = cleared;
        }
    }
}