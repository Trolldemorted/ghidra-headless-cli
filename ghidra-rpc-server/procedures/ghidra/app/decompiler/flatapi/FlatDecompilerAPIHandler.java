package procedures.ghidra.app.decompiler.flatapi;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Symbol;

/**
 * Procedure FlatDecompilerAPI: decompile the function at {@code address} to C source
 * via Ghidra's {@link FlatDecompilerAPI} and return the text.
 *
 * Read-only: decompilation never modifies the program, so {@link #mutates()} is false
 * and the file is not checked in (it is still checked out by dispatch, per policy).
 */
public final class FlatDecompilerAPIHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        // `address` accepts either a hex address or an exact function name
        // (resolved via RpcContext.requireFunction). Names take one extra
        // lookup pass but let callers pipe `--function main` without having
        // to resolve the address first.
        Function function;
        String spec = RpcContext.reqStr(req, "address");
        try {
            function = ctx.requireFunction(spec);
        } catch (IllegalArgumentException e) {
            // requireFunction throws when no function exists at the address
            // AND no exact-name match is found. The user is typically here
            // because they discovered the address as a label like
            // `LAB_00438360` (vtable slot, thunked-call target, indirect
            // call ref) and tried to decompile it. The bare message
            // "No function matched '0x00438360' (by address or name)."
            // leaves them stuck: it tells them WHAT'S WRONG but not WHAT'S
            // THERE or HOW TO FIX IT.
            //
            // Diagnose the address: look for a primary symbol (the LAB_xxx
            // label), the listing CodeUnit (an Instruction already
            // disassembled, a Data unit, or undefined bytes), and report
            // what we found with a copy-pasteable `function create`
            // command.
            throw new IllegalArgumentException(diagnoseMissingFunction(ctx, spec, e.getMessage()));
        }
        int timeoutSecs = RpcContext.optInt(req, "timeoutSecs", 0);

        // FlatDecompilerAPI lazily opens a DecompInterface; dispose() releases it.
        FlatProgramAPI flat = new FlatProgramAPI(ctx.program(), ctx.monitor());
        FlatDecompilerAPI api = new FlatDecompilerAPI(flat);
        try {
            String c = (timeoutSecs > 0)
                ? api.decompile(function, timeoutSecs)
                : api.decompile(function);
            return new DecompileResponse(function.getName(),
                function.getEntryPoint().toString(), c);
        } finally {
            api.dispose();
        }
    }

    /**
     * Build a rich error explaining why there is no decompilable function at
     * {@code spec}. The message includes:
     * <ul>
     *   <li>the original "no function matched" wording (preserved verbatim
     *       so existing scripts/log scrapers don't break),</li>
     *   <li>what IS at the address — a primary symbol name like {@code LAB_00438360}
     *       (label exists but no function body), an Instruction (code is
     *       disassembled but no function wraps it), a Data unit, or just
     *       undefined bytes (raw code, never disassembled),</li>
     *   <li>a copy-pasteable fix: {@code function create --address <addr>},
     *       which runs {@code CreateFunctionCmd} and lets the analyzer
     *       discover the body. For undefined bytes we suggest a disassemble
     *       first so the analyzer has instructions to work with.</li>
     * </ul>
     */
    private static String diagnoseMissingFunction(RpcContext ctx, String spec, String originalMsg) {
        Address addr;
        try {
            addr = ctx.requireAddress(spec);
        } catch (IllegalArgumentException badAddr) {
            // Not even a parseable address — return the original message;
            // there's nothing more to add.
            return originalMsg;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(originalMsg);
        sb.append(" Nothing decompilable exists at ").append(addr).append(".");
        // 1) Primary symbol (the LAB_xxx label that brought the user here).
        Symbol primary = ctx.program().getSymbolTable().getPrimarySymbol(addr);
        String primaryName = primary == null ? null : primary.getName();
        if (primaryName != null) {
            sb.append(" There IS a label there: '").append(primaryName)
              .append("' (primary symbol at ").append(addr).append(").");
        }
        // 2) Listing code unit — disassembled Instruction, Data, or undefined.
        CodeUnit cu = ctx.program().getListing().getCodeUnitContaining(addr);
        if (cu == null) {
            sb.append(" No code unit covers the address either — the bytes are unmapped.");
        }
        else if (cu instanceof Instruction) {
            sb.append(" An Instruction is disassembled at that address but no Function wraps it "
                + "(Ghidra's decompiler requires a Function with an entry point to produce C).");
        }
        else if (cu instanceof ghidra.program.model.listing.Data) {
            sb.append(" A Data unit (not code) is defined at that address.");
        }
        else {
            // Undefined bytes — bytes exist but never disassembled. Tell the
            // user how to get instructions here first.
            sb.append(" The bytes at that address are undefined (not yet disassembled).");
        }
        // 3) Fix.
        sb.append(" Fix: create a function at ").append(addr)
          .append(" so the analyzer wraps the body:");
        sb.append("\n  function create --file /<file> --address ").append(addr);
        if (primaryName != null && primaryName.startsWith("LAB_")) {
            sb.append("\nOptionally rename the entry point after creation:");
            sb.append("\n  function rename --file /<file> --address ").append(addr)
              .append(" --name <descriptive_name>");
        }
        if (cu == null) {
            sb.append("\nIf the bytes are unmapped, add a memory block first (memory create), then disassemble, then create the function.");
        }
        else if (!(cu instanceof Instruction)) {
            // Undefined or Data — needs disassembly first so CreateFunctionCmd
            // can compute a body.
            sb.append("\nIf the bytes are not yet instructions, disassemble first:");
            sb.append("\n  function disassemble --file /<file> --address ").append(addr);
        }
        return sb.toString();
    }

    /** Decompilation does not change the program, so no check-in is required. */
    @Override
    public boolean mutates() {
        return false;
    }

    /** Success response carrying the decompiled C source (serialized by gson). */
    static final class DecompileResponse extends RpcResponse {
        final String function;
        final String address;
        final String decompilation;

        DecompileResponse(String function, String address, String decompilation) {
            this.success = true;
            this.function = function;
            this.address = address;
            this.decompilation = decompilation;
        }
    }
}
