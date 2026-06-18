package procedures.ghidra.program.model.listing;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure SearchStrings: substring/regex search over the program's
 * {@code DEFINED} strings (any data whose type is an
 * {@code AbstractStringDataType} or an {@code ArrayStringable} array).
 *
 * <p>Read-only — same checkout policy as {@link FindFunctionsByName}.
 * {@code query} is OPTIONAL: when absent or empty the procedure returns
 * EVERY defined string in scope (a "list all"). Pass {@code regex:true} or
 * {@code ignoreCase:true} to change match semantics (see
 * {@link procedures.StringQuery}).
 *
 * <p>Scans the whole program by default; pass {@code addressSet:[{start,end?}]}
 * or {@code address} to restrict.
 */
public final class SearchStringsHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return DefinedStringScan.execute(ctx, req);
    }

    /** Searching does not change the program. */
    @Override
    public boolean mutates() {
        return false;
    }
}
