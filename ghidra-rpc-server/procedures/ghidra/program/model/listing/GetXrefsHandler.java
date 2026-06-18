package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure GetXrefs: list references TO a function, symbol, or memory address.
 *
 * <p>Request:
 * <pre>
 *   { "to": "&lt;spec&gt;", "type": "function|symbol|address", "includeOffcut": true, "limit": 0 }
 * </pre>
 *
 * <p>Target resolution:
 * <ul>
 *   <li>{@code address}: parse {@code to} as a hex/program address (the
 *       server's default address factory). Offcut targets are allowed
 *       because the result is what Ghidra's References window shows.
 *   <li>{@code function}: if {@code to} parses as an address, try
 *       {@code getFunctionAt} first; otherwise substring-match against the
 *       function table (case-sensitive, like {@code find-by-name} without
 *       regex). Multiple matches: the first wins (the result still reports
 *       the resolved address so the caller can verify).
 *   <li>{@code symbol}: exact match against {@link SymbolTable} labels,
 *       skipping external entries. (External refs to in-program locations
 *       are still returned as xrefs — see {@code isExternal} on the
 *       response, which is set when the resolved target itself was
 *       external.)
 * </ul>
 *
 * <p>Read-only (no checkout/check-in required for the program, matching
 * {@link FindFunctionsByNameHandler}). The result is sorted by the
 * underlying {@link ReferenceIterator} order (reference rank) — the caller
 * can sort client-side by {@code fromAddress} if address order is needed.
 */
public final class GetXrefsHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String to = RpcContext.reqStr(req, "to");
        String type = RpcContext.reqStr(req, "type").toLowerCase();
        if (to.isEmpty()) return RpcResponse.error("Missing 'to'.");
        if (type.isEmpty()) {
            return RpcResponse.error("Missing 'type' (function|symbol|address).");
        }
        if (!type.equals("function") && !type.equals("symbol") && !type.equals("address")) {
            return RpcResponse.error(
                "Invalid 'type' '" + type + "': must be function, symbol, or address.");
        }

        Address target = resolveTarget(ctx, to, type);
        if (target == null) {
            return RpcResponse.error("No " + type + " matched '" + to + "'.");
        }

        boolean includeOffcut = RpcContext.optBool(req, "includeOffcut", true);
        int limit = RpcContext.optInt(req, "limit", 0);

        FunctionManager fm = ctx.program().getFunctionManager();
        ReferenceManager rm = ctx.program().getReferenceManager();
        List<XrefMatch> refs = new ArrayList<>();
        boolean truncated = false;
        ReferenceIterator it = rm.getReferencesTo(target);
        while (it.hasNext()) {
            ctx.monitor().checkCancelled();
            Reference ref = it.next();
            if (!includeOffcut && ref.isOffsetReference()) continue;
            Address from = ref.getFromAddress();
            Function fromFn = fm.getFunctionContaining(from);
            refs.add(new XrefMatch(
                from.toString(),
                fromFn != null ? fromFn.getName() : null,
                ref.getReferenceType().getName(),
                ref.getOperandIndex(),
                ref.isExternalReference(),
                ref.isOffsetReference()
            ));
            if (limit > 0 && refs.size() >= limit) {
                truncated = true;
                break;
            }
        }
        return new GetXrefsResponse(
            new XrefTarget(type, to, target.toString()),
            refs.size(), truncated, refs);
    }

    /** Read-only. */
    @Override
    public boolean mutates() {
        return false;
    }

    private static Address resolveTarget(RpcContext ctx, String to, String type) {
        switch (type) {
            case "address":
                return ctx.parseAddress(to);

            case "function": {
                FunctionManager fm = ctx.program().getFunctionManager();
                Address a = ctx.parseAddress(to);
                if (a != null) {
                    Function f = fm.getFunctionAt(a);
                    if (f != null) return f.getEntryPoint();
                }
                // Substring match (case-sensitive) on the function table.
                // First match wins; the response carries the resolved
                // address so callers can detect collisions.
                for (Function f : fm.getFunctions(true)) {
                    if (f.getName().equals(to)) return f.getEntryPoint();
                }
                return null;
            }

            case "symbol": {
                SymbolTable st = ctx.program().getSymbolTable();
                for (Symbol s : st.getSymbolIterator()) {
                    if (s.isExternal()) continue;       // skip external-only entries
                    if (s.getName().equals(to)) return s.getAddress();
                }
                return null;
            }

            default:
                return null;
        }
    }
}
