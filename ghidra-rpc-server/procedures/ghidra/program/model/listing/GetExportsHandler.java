package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure GetExports: list in-program symbols flagged as external entry
 * points (what this binary exports to other modules). Mirrors the Ghidra
 * Exports window.
 *
 * <p>Request:
 * <pre>
 *   { "file": "&lt;path&gt;", "type": "all|function", "limit": 0 }
 * </pre>
 *
 * <p>Iterates {@link SymbolTable#getSymbolIterator()} in address order, keeping
 * the primary symbol at each address whose {@link Symbol#isExternalEntryPoint()}
 * is true. {@code type=function} keeps only rows backed by a
 * {@link Function}. {@code limit} caps result count and sets
 * {@code truncated} when hit.
 *
 * <p>The {@code address} is a real program address (never EXTERNAL space), so
 * callers can pipe it directly into {@code function disassemble
 * --address &lt;addr&gt;} or {@code xrefs --to &lt;addr&gt; --type address}.
 *
 * <p>Read-only — does not mutate the program or check anything back in.
 */
public final class GetExportsHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String typeRaw = RpcContext.optStr(req, "type");
        String type = (typeRaw == null || typeRaw.isEmpty()) ? "all" : typeRaw.toLowerCase();
        if (!type.equals("all") && !type.equals("function")) {
            return RpcResponse.error(
                "Invalid 'type' '" + type + "': must be all or function.");
        }
        boolean functionsOnly = type.equals("function");
        int limit = RpcContext.optInt(req, "limit", 0);

        SymbolTable st = ctx.program().getSymbolTable();
        FunctionManager fm = ctx.program().getFunctionManager();
        List<ExportMatch> results = new ArrayList<>();
        boolean truncated = false;

        SymbolIterator it = st.getSymbolIterator();
        while (it.hasNext()) {
            ctx.monitor().checkCancelled();
            Symbol s = it.next();
            if (!s.isExternalEntryPoint()) continue;
            if (!s.isPrimary()) continue;          // dedupe thunk-body sub-symbols
            Address addr = s.getAddress();
            if (addr == null) continue;            // defensive: no real address
            if (addr.isExternalAddress()) continue; // EXTERNAL space => that's an import, not an export
            Function f = fm.getFunctionAt(addr);
            boolean isFunc = f != null;
            if (functionsOnly && !isFunc) continue;
            results.add(new ExportMatch(
                s.getName(),
                addr.toString(),
                s.getSymbolType().toString(),
                isFunc,
                isFunc && f.isThunk()
            ));
            if (limit > 0 && results.size() >= limit) {
                truncated = true;
                break;
            }
        }

        return new GetExportsResponse(results.size(), truncated, results);
    }

    @Override
    public boolean mutates() {
        return false;
    }
}
