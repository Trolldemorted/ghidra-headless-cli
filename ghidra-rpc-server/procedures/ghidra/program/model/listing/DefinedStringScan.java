package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import com.google.gson.JsonObject;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.util.DefinedStringIterator;

import procedures.RpcContext;
import procedures.RpcResponse;
import procedures.StringQuery;

/**
 * Shared iterator body for {@link SearchStringsHandler}. Walks
 * {@link DefinedStringIterator} over either an explicit scope
 * ({@code addressSet} or {@code address} in the request) or the whole program
 * if neither is present, filters the decoded string values via
 * {@link StringQuery#containsOptional} (an absent/empty {@code query} matches
 * every defined string), and caps the result at {@code limit}.
 *
 * <p>Read-only — no transaction, no checkout; the per-request dispatcher
 * already holds the program open and the file checked out by policy.
 */
final class DefinedStringScan {

    private DefinedStringScan() {}

    static RpcResponse execute(RpcContext ctx, JsonObject req) throws Exception {
        Predicate<String> matches = StringQuery.containsOptional(req);

        int limit = RpcContext.reqInt(req, "limit");
        AddressSetView scope = (req.has("address") || req.has("addressSet"))
            ? ctx.addressSet(req)
            : null;

        DefinedStringIterator it = (scope == null)
            ? DefinedStringIterator.forProgram(ctx.program())
            : DefinedStringIterator.forProgram(ctx.program(), scope);

        List<DefinedStringMatch> results = new ArrayList<>();
        boolean truncated = false;
        while (it.hasNext()) {
            ctx.monitor().checkCancelled();
            Data d = it.next();
            // StringDataInstance.getStringDataInstance returns null for non-string Data,
            // but DefinedStringIterator only yields actual strings — guard anyway.
            StringDataInstance sdi = StringDataInstance.getStringDataInstance(d);
            if (sdi == null) continue;
            String value = sdi.getStringValue();
            if (!matches.test(value)) continue;
            results.add(new DefinedStringMatch(
                d.getAddress().toString(),
                value,
                sdi.getStringRepresentation(),
                d.getLength(),
                sdi.getCharsetName(),
                d.getDataType().getName()
            ));
            if (limit > 0 && results.size() >= limit) {
                truncated = true;
                break;
            }
        }
        return new DefinedStringListResponse(results.size(), truncated, results);
    }
}
