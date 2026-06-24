package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;
import procedures.StringQuery;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;

/**
 * Procedure FindFunction: unified function search.
 *
 * <p>Replaces the older {@code FindFunctionsByName} and
 * {@code FindFunctionsByTag} procedures; adds address lookup.
 * Dispatch is by the optional {@code field} request field:
 *
 * <ul>
 *   <li>{@code field == "all"} (default) — search the query against the
 *       function's qualified name AND each of its tags AND (if
 *       {@code parseAddress(query)} succeeds) try
 *       {@link ghidra.program.model.listing.FunctionManager#getFunctionContaining}
 *       then {@link ghidra.program.model.listing.FunctionManager#getFunctionAt}.
 *   <li>{@code field == "name"} — match query against the qualified name only.
 *   <li>{@code field == "tag"} — match query against each tag name (substring
 *       default, regex with {@code regex:true}).
 *   <li>{@code field == "address"} — parse the query as an address; return
 *       the function whose body covers it, or the function whose entry
 *       point equals it, or empty if neither matches.
 * </ul>
 *
 * <p>{@code query} is required on the wire. The CLI enforces this with
 * clap's {@code required = true}; the server also defensively checks
 * via {@link RpcContext#reqStr}. The CLI enforces
 * {@code field}-mutual-exclusion (one of {@code name}, {@code tag},
 * {@code address}; absent means {@code all}). The server re-checks the
 * same — a hand-rolled request can bypass clap.
 *
 * <p>{@code limit} caps the result and sets {@code truncated}. Matches
 * are returned in program-defined function iteration order (address
 * order). Read-only.
 */
public final class FindFunctionHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String query = RpcContext.reqStr(req, "query");
        String fieldRaw = RpcContext.optStr(req, "field");
        Field field = Field.parse(fieldRaw);

        // Defense-in-depth: a hand-rolled request could pass multiple
        // field values (the JSON object is just a map; clap only
        // enforces conflicts on the CLI side). Reject anything we
        // didn't ask for here too. (Single-choice conflict among
        // name/tag/address is enforced by Field.parse rejecting an
        // unknown value.)
        // No additional check needed beyond Field.parse below.

        int limit = RpcContext.optInt(req, "limit", 0);

        List<FunctionMatch> results = new ArrayList<>();
        boolean truncated = false;

        switch (field) {
            case NAME: {
                Predicate<String> nameMatch = StringQuery.contains(req);
                for (Function f : ctx.program().getFunctionManager().getFunctions(true)) {
                    ctx.monitor().checkCancelled();
                    String qualified = f.getName(true);
                    if (nameMatch.test(qualified)) {
                        results.add(matchedWithTags(f));
                        if (limit > 0 && results.size() >= limit) {
                            truncated = true;
                            break;
                        }
                    }
                }
                break;
            }
            case TAG: {
                // Per the unified-verb tag-match semantics, --tag
                // shares StringQuery.contains (substring default, regex
                // with --regex). The old find-by-tag used .exact; this
                // is a deliberate behavior change for consistency.
                Predicate<String> tagMatch = StringQuery.contains(req);
                for (Function f : ctx.program().getFunctionManager().getFunctions(true)) {
                    ctx.monitor().checkCancelled();
                    List<String> tags = tagsOf(f);
                    if (tags.stream().anyMatch(tagMatch)) {
                        results.add(new FunctionMatch(f.getName(),
                            f.getEntryPoint().toString(), tags));
                        if (limit > 0 && results.size() >= limit) {
                            truncated = true;
                            break;
                        }
                    }
                }
                break;
            }
            case ADDRESS: {
                Address addr = ctx.parseAddress(query);
                if (addr == null) {
                    return RpcResponse.error("Invalid or missing address: " + query);
                }
                Function f = ctx.program().getFunctionManager().getFunctionContaining(addr);
                if (f == null) {
                    f = ctx.program().getFunctionManager().getFunctionAt(addr);
                }
                if (f != null) {
                    results.add(matchedWithTags(f));
                }
                break;
            }
            case ALL: {
                // "All" = name OR tag OR address. Name and tag use the
                // same StringQuery predicate (substring/regex per
                // --regex, case per --ignoreCase). Address is a single
                // lookup at parseAddress(query) — if it parses, we
                // include the function it resolves to.
                Predicate<String> nameMatch = StringQuery.contains(req);
                Predicate<String> tagMatch = StringQuery.contains(req);
                Address probeAddr = ctx.parseAddress(query);
                Function addrHit = null;
                if (probeAddr != null) {
                    addrHit = ctx.program().getFunctionManager().getFunctionContaining(probeAddr);
                    if (addrHit == null) {
                        addrHit = ctx.program().getFunctionManager().getFunctionAt(probeAddr);
                    }
                }
                for (Function f : ctx.program().getFunctionManager().getFunctions(true)) {
                    ctx.monitor().checkCancelled();
                    String qualified = f.getName(true);
                    boolean hit = nameMatch.test(qualified)
                        || tagsOf(f).stream().anyMatch(tagMatch)
                        || (addrHit != null && addrHit.equals(f));
                    if (hit) {
                        results.add(matchedWithTags(f));
                        if (limit > 0 && results.size() >= limit) {
                            truncated = true;
                            break;
                        }
                    }
                }
                break;
            }
        }

        return new FindFunctionsResponse(results.size(), truncated, results);
    }

    /** Read-only. */
    @Override
    public boolean mutates() {
        return false;
    }

    private static List<String> tagsOf(Function f) {
        List<String> tags = new ArrayList<>();
        for (FunctionTag t : f.getTags()) {
            tags.add(t.getName());
        }
        Collections.sort(tags);
        return tags;
    }

    private static FunctionMatch matchedWithTags(Function f) {
        return new FunctionMatch(f.getName(), f.getEntryPoint().toString(), tagsOf(f));
    }

    /**
     * Which field(s) the query is matched against. {@link #ALL} is the
     * default (omitted {@code field}); it searches names AND tags AND
     * (when the query parses as an address) the address slot. The
     * other three are mutually-exclusive scopes; the CLI enforces this
     * with clap {@code conflicts_with} and the server enforces it by
     * rejecting unknown {@code field} values here.
     */
    private enum Field {
        ALL, NAME, TAG, ADDRESS;

        static Field parse(String raw) {
            if (raw == null || raw.isEmpty() || raw.equalsIgnoreCase("all")) {
                return ALL;
            }
            if (raw.equalsIgnoreCase("name")) {
                return NAME;
            }
            if (raw.equalsIgnoreCase("tag")) {
                return TAG;
            }
            if (raw.equalsIgnoreCase("address")) {
                return ADDRESS;
            }
            throw new IllegalArgumentException(
                "Invalid 'field' value '" + raw + "': expected one of all|name|tag|address.");
        }
    }
}