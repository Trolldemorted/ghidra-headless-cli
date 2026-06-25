package procedures.ghidra.app.cmd.function;

import java.util.Map;
import java.util.regex.Pattern;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

/**
 * Procedure SetVariableNameCmd: rename a variable {@code oldName}->{@code newName}
 * in a function.
 *
 * <h2>Routing</h2>
 *
 * <p>The choice of which path to take depends on whether {@code oldName}
 * looks like a Ghidra decompiler display name (e.g. {@code iVar1},
 * {@code puVar2}, {@code param_1}). The two paths differ in correctness
 * guarantees, not just speed:
 *
 * <ul>
 *   <li><b>Decompiler-pattern names</b> ({@code iVar1}, {@code puVar2},
 *       {@code param_1}, ...): the handler <b>always</b> goes through the
 *       decompiler's {@link LocalSymbolMap#getNameToSymbolMap()} to resolve
 *       the display name to its backing database symbol, then renames
 *       that symbol. The symbol-table fast path is intentionally
 *       <b>skipped</b>: a stored variable whose name happens to match a
 *       decompiler display name could be a different variable from what
 *       the decompiler's {@code iVar1} refers to, and renaming the wrong
 *       one would silently corrupt the program. The decompiler's
 *       {@link HighFunction} is the single source of truth for what the
 *       user means when they type a display name. This costs one decompile
 *       per request (~1–3 s), but the result is unambiguous.</li>
 *
 *   <li><b>Real stored / user-defined names</b> ({@code count},
 *       {@code my_counter}, {@code local_44}, {@code in_EAX}): direct
 *       rename via {@link SetVariableNameCmd}. Function-local names are
 *       unique so there is no ambiguity and no need to consult the
 *       decompiler.</li>
 * </ul>
 *
 * <h2>Refusal cases for decompiler-pattern names</h2>
 *
 * <p>The handler refuses to rename when:
 *
 * <ul>
 *   <li>The decompiler does not complete, returns no
 *       {@link HighFunction}, or the display name is not in
 *       {@link LocalSymbolMap#getNameToSymbolMap()}.</li>
 *   <li>The corresponding {@link HighSymbol} has no backing database
 *       {@link Symbol} (typical for pure display-only register temps like
 *       {@code puVar1}). We do <b>not</b> fall back to
 *       {@code VariableStorage.equals()} matching: a parameter and a local
 *       register temp can share a register storage, and picking the wrong
 *       one would silently rename the wrong variable. The user must
 *       create a stored variable first (e.g.
 *       {@code function variable add-register --register EAX --name my_reg})
 *       and then rename it by its stored name.</li>
 * </ul>
 *
 * <p>On refusal the error message includes a "did you mean" listing of the
 * function's actual stored variables (capped at 20).
 */
public final class SetVariableNameCmdHandler implements RpcProcedure {

    /**
     * Matches Ghidra's decompiler display-naming convention for the names
     * that show up as the C output's identifiers (parameters, register
     * temps, stack locals):
     * <ul>
     *   <li>{@code param_1}, {@code param_2}, ... — unnamed parameters</li>
     *   <li>{@code iVar1}, {@code uVar1}, {@code lVar1}, {@code bVar1},
     *       {@code cVar1}, {@code sVar1}, {@code qVar1}, {@code fVar1},
     *       {@code dVar1}, {@code flVar1}, {@code puVar2}, {@code piVar2},
     *       {@code pbVar2}, {@code pcVar2}, {@code psVar2}, {@code plVar2},
     *       {@code pulVar2}, {@code pqVar2}, {@code pfVar2}, {@code pdVar2},
     *       {@code pflVar2}, ... — typed stack/heap locals (no underscore)</li>
     *   <li>{@code p_Var1}, {@code i_Var1}, ... — typed register-based
     *       locals (with underscore between the type prefix and {@code Var})</li>
     * </ul>
     *
     * <p>Permissive on purpose: false positives route through the
     * read-only decompiler lookup and fall through to a clear diagnostic
     * on miss. We do <b>not</b> want a near-miss pattern to silently hit
     * the fast path and rename the wrong variable.
     */
    private static final Pattern DECOMPILER_NAME =
        Pattern.compile("^(param_\\d+|[a-z_]+Var\\d+)$");

    /** Cap on the "did you mean" listing appended to a final-miss error. */
    private static final int DIAGNOSTIC_LIMIT = 20;

    /** Per-function decompile budget for the display→stored lookup. */
    private static final int DECOMPILER_TIMEOUT_SECS = 60;

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address funcEntry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String oldName = RpcContext.reqStr(req, "oldName");
        String newName = RpcContext.reqStr(req, "newName");
        SourceType source = ctx.sourceType(RpcContext.optStr(req, "source"));

        // Resolve the function up front so the diagnostic and the decompiler
        // agree on the target. requireFunctionAt throws on miss, which
        // dispatch converts to an error response.
        Function f = ctx.requireFunctionAt(funcEntry);

        if (DECOMPILER_NAME.matcher(oldName).matches()) {
            // Decompiler-style name. ALWAYS go through the decompiler.
            // The symbol-table fast path is intentionally skipped: a
            // stored variable whose name happens to match the display
            // name could be a different variable from what the
            // decompiler's HighFunction is referring to.
            return decompilerRename(f, funcEntry, oldName, newName, source, ctx);
        }

        // Stored / user-defined name. Function-local names are unique so
        // the symbol table is the unambiguous authority.
        Command<Program> rename = new SetVariableNameCmd(
            funcEntry, oldName, newName, source);
        return ctx.applyCommand(rename);
    }

    /**
     * Rename via the decompiler's display→stored mapping.
     *
     * <p>Opens a {@link DecompInterface}, decompiles the function, and asks
     * {@link LocalSymbolMap#getNameToSymbolMap()} for the display name. If
     * the corresponding {@link HighSymbol} has a backing database
     * {@link Symbol}, that symbol's stored name is used for the rename.
     * Otherwise the handler refuses with a diagnostic — there is no
     * authoritative target.
     */
    private RpcResponse decompilerRename(Function f, Address funcEntry,
            String oldName, String newName, SourceType source, RpcContext ctx) throws Exception {
        String storedName = null;
        String decompError = null;
        String displayOnlyHint = null;
        DecompInterface di = ctx.openedDecompiler();
        try {
            DecompileResults results = di.decompileFunction(
                f, DECOMPILER_TIMEOUT_SECS, ctx.monitor());
            if (results == null || !results.decompileCompleted()) {
                decompError = "decompiler did not complete";
            }
            else {
                HighFunction hfunc = results.getHighFunction();
                if (hfunc == null) {
                    decompError = "no high function in decompiler results";
                }
                else {
                    LocalSymbolMap localMap = hfunc.getLocalSymbolMap();
                    Map<String, HighSymbol> nameMap = localMap.getNameToSymbolMap();
                    HighSymbol hs = nameMap.get(oldName);
                    if (hs == null) {
                        // Decompiler ran but does not know this name —
                        // could be a stale display name from a prior
                        // analysis, or a typo by the user.
                        decompError = "decompiler display name not in high-function symbol map";
                    }
                    else {
                        // Only the direct backing-symbol path is safe.
                        // A HighSymbol with no backing symbol is a
                        // decompiler invention (e.g. puVar1 for a
                        // register temp with no stored equivalent); we
                        // do NOT guess by storage matching, because a
                        // parameter and a local register temp can share
                        // a register storage and we would risk renaming
                        // the wrong variable.
                        Symbol sym = hs.getSymbol();
                        if (sym != null) {
                            storedName = sym.getName();
                        }
                        else {
                            // Display-only: no stored symbol to rename.
                            // Build a hint that tells the user which
                            // register/stack slot to claim via
                            // `function variable add-register` (for
                            // register temps) or `function variable
                            // add-stack` (for stack-only temps) — that
                            // creates a stored Variable at the same
                            // storage and the decompiler then uses the
                            // stored name as the display name.
                            decompError = "decompiler display-only name has no backing symbol";
                            displayOnlyHint = displayOnlyWorkaround(hs.getStorage());
                        }
                    }
                }
            }
        }
        catch (Exception e) {
            decompError = "decompiler error: " + e.getMessage();
        }
        finally {
            di.dispose();
        }

        if (storedName != null) {
            RpcResponse retry = ctx.applyCommand(
                new SetVariableNameCmd(funcEntry, storedName, newName, source));
            if (retry.success) {
                return retry;
            }
        }

        // Final miss — surface a diagnostic that lists the function's
        // actual stored variable names so the caller can see what IS there.
        String msg;
        if (storedName != null) {
            // decompiler mapped oldName -> storedName but the rename with
            // storedName still failed; include both for the caller.
            msg = "Variable not found: '" + oldName
                + "' (decompiler mapped to '" + storedName
                + "' but rename failed). ";
        }
        else {
            // Either the decompile itself failed, the display name is
            // not in the symbol map, or it has no backing symbol.
            msg = "Variable not found: '" + oldName + "' (" + decompError + "). ";
            if (displayOnlyHint != null) {
                msg += displayOnlyHint + " ";
            }
        }
        return RpcResponse.error(msg + diagnosticList(ctx, funcEntry));
    }

    /**
     * Build a one-line hint explaining how to give a name to a pure
     * display-only HighSymbol. Returns null if the storage is bad or
     * unassigned (no actionable hint).
     *
     * <p>The two-step workflow for these temps:
     * <ol>
     *   <li>Claim the register/storage with a stored variable
     *       (`function variable add-register` for register temps,
     *       `add-stack` for stack-only temps).</li>
     *   <li>Rename the stored variable by its stored name (the C output
     *       will then show the new name; running
     *       `analysis decompiler-parameter-id` afterwards makes the
     *       decompiler commit the stored name as the canonical display
     *       name for the HighSymbol).</li>
     * </ol>
     */
    private static String displayOnlyWorkaround(VariableStorage storage) {
        if (storage == null || storage.isBadStorage()
            || storage.isUnassignedStorage()) {
            return null;
        }
        String reg = registerName(storage);
        if (reg != null) {
            return "To rename this register temporary: 1) create a "
                + "stored register variable: `function variable "
                + "add-register --register " + reg + " --name <NAME>`; "
                + "2) rename it by its stored name: `function variable "
                + "set-name --old-name <NAME> --new-name <NEW>`. "
                + "The stored name shows in the GUI listing view; the "
                + "decompiler C output's display name may not change "
                + "because this HighSymbol has no database backing.";
        }
        if (storage.hasStackStorage()) {
            return "To rename this stack temporary: 1) create a "
                + "stored stack variable: `function variable "
                + "add-stack --stack-offset <OFFSET> --name <NAME>`; "
                + "2) rename it by its stored name: `function variable "
                + "set-name --old-name <NAME> --new-name <NEW>`.";
        }
        return null;
    }

    /**
     * Pull the register name out of a {@link VariableStorage} that is
     * known to be a register storage. Returns null if the storage has
     * no register varnodes or the printable form does not look like
     * {@code <REG>:<size>}.
     *
     * <p>Ghidra's {@link VariableStorage#toString()} for register
     * storage returns the form {@code <REG>:<size>} (e.g. {@code EAX:4}
     * on x86). We strip the {@code :<size>} suffix and return the
     * register name, which is the exact value {@code function variable
     * add-register --register} accepts.
     */
    private static String registerName(VariableStorage storage) {
        if (!storage.isRegisterStorage()) {
            return null;
        }
        String s = storage.toString();
        int colon = s.indexOf(':');
        if (colon > 0) {
            return s.substring(0, colon);
        }
        return s.isEmpty() ? null : s;
    }

    /**
     * Build a "did you mean" listing of the function's actual stored
     * variable names, capped at {@link #DIAGNOSTIC_LIMIT}. Names come
     * from {@link Function#getAllVariables()} — that returns parameters
     * + locals, covering both register and stack storage in one iterator.
     */
    private static String diagnosticList(RpcContext ctx, Address funcEntry) {
        try {
            Function f = ctx.program().getFunctionManager().getFunctionAt(funcEntry);
            if (f == null) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Variables in ").append(f.getName()).append(" at ").append(funcEntry)
                .append(": ");
            int n = 0;
            for (ghidra.program.model.listing.Variable v : f.getAllVariables()) {
                if (n > 0) {
                    sb.append(", ");
                }
                sb.append(v.getName());
                if (++n >= DIAGNOSTIC_LIMIT) {
                    sb.append(", ...");
                    break;
                }
            }
            return sb.toString();
        }
        catch (Exception e) {
            return "(could not list variables: " + e.getMessage() + ")";
        }
    }
}