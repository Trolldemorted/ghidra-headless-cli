package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;
import procedures.StringQuery;

import ghidra.program.model.listing.Function;

/**
 * Procedure FindFunctionsByName: list all functions whose name matches {@code query}
 * (substring by default, regex when {@code regex} is true; see {@link StringQuery}).
 *
 * <p>Match and display use the function's QUALIFIED name — the parent
 * namespace chain joined with {@code "::"} plus the leaf
 * ({@link Function#getName(boolean) Function.getName(true)}). This is
 * the same string the decompiler prints (e.g.
 * {@code "GameScreen::MultiplayerScreen_ResetPlayerSessionState"}), so
 * {@code find-by-name}'s output agrees with {@code function decompile}.
 *
 * <p>Matching the qualified string (not just the leaf) means
 * {@code --query "Foo"} can find a function named {@code Foo} that lives
 * in any namespace, and {@code --query "GameScreen"} matches everything
 * in that namespace. The leaf characters are preserved literally, so
 * queries containing {@code "__"} (the doubled-underscore that Ghidra's
 * underlying rename can fabricate when its {@code "::"}-split fails; see
 * {@code SetFunctionNameCmdHandler} for the rejection that prevents
 * this) still match — there is no {@code __}→{@code ::} rewrite here.
 *
 * Read-only (like FlatDecompilerAPI/Disassemble): the file is checked out by dispatch per
 * policy but not checked in. Iterates the program's defined functions in address order;
 * an optional {@code limit} caps the result and sets {@code truncated}.
 */
public final class FindFunctionsByNameHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Predicate<String> matches = StringQuery.contains(req);
        int limit = RpcContext.optInt(req, "limit", 0);

        List<FunctionMatch> results = new ArrayList<>();
        boolean truncated = false;
        for (Function function : ctx.program().getFunctionManager().getFunctions(true)) {
            ctx.monitor().checkCancelled();
            // getName(true) -> "ns::ns::leaf". Matches both substring
            // queries against the leaf and against any namespace prefix,
            // and the leaf characters are returned verbatim (no __ -> ::
            // rewrite), so queries with "__" match literally.
            String qualified = function.getName(true);
            if (matches.test(qualified)) {
                results.add(new FunctionMatch(qualified,
                    function.getEntryPoint().toString(), null));
                if (limit > 0 && results.size() >= limit) {
                    truncated = true;
                    break;
                }
            }
        }
        return new FindFunctionsResponse(results.size(), truncated, results);
    }

    /** Searching does not change the program. */
    @Override
    public boolean mutates() {
        return false;
    }
}
