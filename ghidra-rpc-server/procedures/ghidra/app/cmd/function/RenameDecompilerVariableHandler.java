package procedures.ghidra.app.cmd.function;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeException;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

/**
 * Procedure RenameDecompilerVariable: rename a decompiler-only local variable.
 *
 * <h2>What this does that {@code SetVariableNameCmd} cannot</h2>
 *
 * <p>{@code SetVariableNameCmd} (the CLI's {@code function variable
 * set-name}) requires a <b>stored</b> named variable: it looks the name up
 * in the function's database symbols. For register/SSA temps that only
 * exist in the decompiler view (typical {@code puVar1}, {@code iVar2},
 * {@code p_Var1}, {@code aiStack_*}) no stored variable exists, so
 * {@code set-name} errors with "Variable not found".
 *
 * <p>Ghidra's GUI <b>Rename Variable</b> (hotkey {@code L}) handles exactly
 * this case: it stores a dynamic-hash varnode override keyed by
 * {@code (function, pc, varnode hash)} via
 * {@link HighFunctionDBUtil#updateDBVariable} with the existing type and
 * a new name. The same call works for both backing-Symbol HighSymbols and
 * display-only HighSymbols. This procedure exposes that override on the
 * wire.
 *
 * <p>Mirrors {@code RetypeDecompilerVariable} (forgejo #95, shipped
 * 2026-07-18) — same identification paths, same splitOutMergeGroup
 * preflight, same dispatcher transaction. The only difference is the
 * {@code updateDBVariable} argument shape: rename passes the existing
 * type and the new name; retype passes the existing name and the new
 * type. Both persist the same way (dynamic-hash varnode override).
 *
 * <h2>Identification: two mutually-exclusive paths</h2>
 *
 * <ul>
 *   <li><b>{@code decompilerName}</b> — exact match in
 *       {@link LocalSymbolMap#getNameToSymbolMap()}. E.g. {@code pCVar2}.
 *       Misses return a diagnostic listing of the function's actual display
 *       names (capped at 20) so the caller can see what the decompiler
 *       actually produced.</li>
 *   <li><b>{@code pc} + {@code storage}</b> — picks the HighSymbol whose
 *       {@code getPCAddress().toString()} and {@code getStorage().toString()}
 *       match. Used when the caller knows where the temp first appears but
 *       not what the decompiler named it (or the name is unstable across
 *       decompiles).</li>
 * </ul>
 *
 * <p>One and only one path must be supplied. Missing both, or supplying
 * both, is an error. Storage is matched as Ghidra prints it
 * (e.g. {@code EAX:4}, {@code Stack[-0x4]}); see
 * {@link VariableStorage#toString()}.
 *
 * <h2>What runs</h2>
 *
 * <ol>
 *   <li>Open a {@link DecompInterface}, decompile the function.</li>
 *   <li>Resolve the target HighSymbol via the path above.</li>
 *   <li>If the HighSymbol's HighVariable has a representative Varnode,
 *       call {@link HighFunction#splitOutMergeGroup} (matches the GUI's
 *       {@code RenameLocalAction}) to give {@code updateDBVariable} a clean
 *       target.</li>
 *   <li>Call {@link HighFunctionDBUtil#updateDBVariable} with the supplied
 *       name and the existing symbol's data type, inside the
 *       dispatcher-owned transaction. The dispatcher checks the program
 *       in on success and rolls back on failure.</li>
 * </ol>
 *
 * <h2>Failure modes</h2>
 *
 * <ul>
 *   <li>Decompile did not complete.</li>
 *   <li>No HighFunction in the results.</li>
 *   <li>Display-name miss: error + keySet listing.</li>
 *   <li>pc+storage miss (zero or multiple candidates): error + listing.</li>
 *   <li>Storage is bad/unassigned: error (cannot store an override on a
 *       storage-less HighSymbol).</li>
 *   <li>{@link PcodeException} from splitOutMergeGroup: propagated.</li>
 *   <li>{@link ghidra.util.exception.InvalidInputException} or
 *       {@link ghidra.util.exception.DuplicateNameException} from
 *       updateDBVariable: propagated. A duplicate name usually means the
 *       caller picked a name already used by another local in the
 *       function — pick a distinct name.</li>
 * </ul>
 */
public final class RenameDecompilerVariableHandler implements RpcProcedure {

    /** Cap on the "did you mean" listing appended to a final-miss error. */
    private static final int DIAGNOSTIC_LIMIT = 20;

    /** Per-function decompile budget for the display→stored lookup. */
    private static final int DECOMPILER_TIMEOUT_SECS = 60;

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address funcEntry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        Function f = ctx.requireFunctionAt(funcEntry);

        String decompilerName = RpcContext.optStr(req, "decompilerName");
        String pcSpec = RpcContext.optStr(req, "pc");
        String storageSpec = RpcContext.optStr(req, "storage");

        boolean hasName = decompilerName != null && !decompilerName.isEmpty();
        boolean hasPc = pcSpec != null && !pcSpec.isEmpty();
        boolean hasStorage = storageSpec != null && !storageSpec.isEmpty();
        if (hasName && (hasPc || hasStorage)) {
            return RpcResponse.error(
                "'decompilerName' is mutually exclusive with 'pc'/'storage'; supply exactly one.");
        }
        if (!hasName && !(hasPc && hasStorage)) {
            return RpcResponse.error(
                "Supply exactly one of 'decompilerName' or both 'pc' and 'storage'.");
        }

        String newName = RpcContext.reqStr(req, "name");
        if (newName.isEmpty()) {
            return RpcResponse.error("'name' must be non-empty.");
        }
        SourceType source = ctx.sourceType(RpcContext.optStr(req, "source"));

        HighFunction hfunc;
        Map<String, HighSymbol> nameMap;
        DecompInterface di = ctx.openedDecompiler();
        try {
            DecompileResults results = di.decompileFunction(f, DECOMPILER_TIMEOUT_SECS, ctx.monitor());
            if (results == null || !results.decompileCompleted()) {
                return RpcResponse.error("Decompiler did not complete for " + f.getName() + ".");
            }
            hfunc = results.getHighFunction();
            if (hfunc == null) {
                return RpcResponse.error("No high function in decompiler results for " + f.getName() + ".");
            }
            LocalSymbolMap localMap = hfunc.getLocalSymbolMap();
            nameMap = localMap.getNameToSymbolMap();
        } finally {
            di.dispose();
        }

        HighSymbol target;
        if (hasName) {
            target = nameMap.get(decompilerName);
            if (target == null) {
                return RpcResponse.error(
                    "decompiler name '" + decompilerName + "' not found in " + f.getName()
                    + " at " + funcEntry + ". " + nameCandidates(nameMap));
            }
        } else {
            target = resolveByPcAndStorage(nameMap, pcSpec, storageSpec);
            if (target == null) {
                return RpcResponse.error(
                    "no HighSymbol in " + f.getName() + " at " + funcEntry
                    + " matches pc='" + pcSpec + "' storage='" + storageSpec + "'. "
                    + pcCandidates(nameMap));
            }
        }

        VariableStorage storage = target.getStorage();
        if (storage == null || storage.isBadStorage() || storage.isUnassignedStorage()) {
            return RpcResponse.error(
                "HighSymbol '" + target.getName() + "' has no usable storage; cannot override.");
        }

        // Match the GUI: split the HighVariable out of its merge group so
        // updateDBVariable targets a single symbol. PcodeException is the
        // documented throw and we propagate it as an error.
        HighSymbol toWrite = target;
        HighVariable hv = target.getHighVariable();
        if (hv != null) {
            Varnode rep = hv.getRepresentative();
            if (rep != null) {
                try {
                    HighVariable split = hfunc.splitOutMergeGroup(hv, rep);
                    if (split != null && split.getSymbol() != null) {
                        toWrite = split.getSymbol();
                    }
                } catch (PcodeException pe) {
                    return RpcResponse.error(
                        "splitOutMergeGroup failed for '" + target.getName() + "': "
                        + pe.getMessage());
                }
            }
        }

        // Persist. The dispatcher owns the transaction; runWrite no-ops
        // its inner start/end but still propagates exceptions so the
        // dispatcher's commit-vs-rollback decision sees them.
        //
        // updateDBVariable takes (symbol, name, dataType, source); for
        // rename we pass the EXISTING type and the NEW name. The existing
        // type is what `target.getDataType()` returns at the moment of the
        // call — at this point `toWrite` may differ from `target` (the
        // splitOutMergeGroup swap), so read the type from `toWrite` to
        // preserve whatever the GUI would have written.
        final HighSymbol writeFinal = toWrite;
        final DataType existingType = toWrite.getDataType();
        final String nameFinal = newName;
        final SourceType sourceFinal = source;
        final String targetName = target.getName();
        try {
            ctx.runWrite("Rename Decompiler Variable", () -> {
                HighFunctionDBUtil.updateDBVariable(writeFinal, nameFinal, existingType, sourceFinal);
            });
        } catch (Exception e) {
            return RpcResponse.error(
                "updateDBVariable failed for '" + targetName + "' -> '" + newName + "': "
                + e.getMessage());
        }

        return RpcResponse.ok();
    }

    /**
     * Scan {@code nameMap} for a HighSymbol whose storage and pcAddress
     * match the supplied strings. Returns the first match, or null if
     * none. Ambiguity is surfaced separately by the caller via
     * {@link #pcCandidates}.
     */
    private static HighSymbol resolveByPcAndStorage(
            Map<String, HighSymbol> nameMap, String pcSpec, String storageSpec) {
        for (HighSymbol hs : nameMap.values()) {
            VariableStorage s = hs.getStorage();
            if (s == null) {
                continue;
            }
            if (!storageSpec.equals(s.toString())) {
                continue;
            }
            Address pc = hs.getPCAddress();
            if (pc == null) {
                continue;
            }
            if (pcSpec.equalsIgnoreCase(pc.toString())
                    || pcSpec.equalsIgnoreCase("0x" + pc.toString())) {
                return hs;
            }
        }
        return null;
    }

    /**
     * Build a "did you mean" listing of the function's decompiler display
     * names, capped at {@link #DIAGNOSTIC_LIMIT}. Used on the
     * {@code decompilerName}-miss path.
     */
    private static String nameCandidates(Map<String, HighSymbol> nameMap) {
        List<String> names = new ArrayList<>(nameMap.keySet());
        java.util.Collections.sort(names);
        StringBuilder sb = new StringBuilder();
        sb.append("Decompiler display names: ");
        int n = 0;
        for (String name : names) {
            if (n > 0) {
                sb.append(", ");
            }
            sb.append(name);
            if (++n >= DIAGNOSTIC_LIMIT) {
                sb.append(", ...");
                break;
            }
        }
        return sb.toString();
    }

    /**
     * Build a "did you mean" listing of (pc, storage, displayName) triples
     * for the function, capped at {@link #DIAGNOSTIC_LIMIT}. Used on the
     * pc+storage-miss path so the caller can see what IS there.
     */
    private static String pcCandidates(Map<String, HighSymbol> nameMap) {
        List<String> lines = new ArrayList<>();
        for (Map.Entry<String, HighSymbol> e : nameMap.entrySet()) {
            VariableStorage s = e.getValue().getStorage();
            Address pc = e.getValue().getPCAddress();
            if (s == null || pc == null) {
                continue;
            }
            lines.add(e.getKey() + " @ " + pc + " storage=" + s);
        }
        java.util.Collections.sort(lines);
        StringBuilder sb = new StringBuilder();
        sb.append("Candidates: ");
        int n = 0;
        for (String line : lines) {
            if (n > 0) {
                sb.append("; ");
            }
            sb.append(line);
            if (++n >= DIAGNOSTIC_LIMIT) {
                sb.append("; ...");
                break;
            }
        }
        return sb.toString();
    }

    @Override
    public boolean mutates() {
        return true;
    }
}
