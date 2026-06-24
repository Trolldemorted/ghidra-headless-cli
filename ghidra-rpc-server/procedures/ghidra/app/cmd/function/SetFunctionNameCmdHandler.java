package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.program.model.address.Address;

/**
 * Procedure SetFunctionNameCmd: rename the function whose entry point is
 * {@code address}. The new name MUST be a bare leaf — this command does
 * NOT move the function across namespaces.
 *
 * <p><b>Namespace rejection.</b> A {@code name} containing {@code "::"} is
 * rejected with a clear error. Ghidra's
 * {@link ghidra.app.cmd.function.SetFunctionNameCmd#applyTo} delegates
 * straight to {@code Function.setName(name, source)}, which silently
 * fabricates garbage leaves when the {@code "::"}-prefixed parent path
 * does not exist relative to the function's CURRENT namespace:
 * <ul>
 *   <li>if the function is in {@code GameScreen} and the caller passes
 *       {@code MultiplayerScreen::MultiplayerScreen_X}, Ghidra treats
 *       {@code "::"} as a parent-hint, fails to resolve
 *       {@code MultiplayerScreen} under {@code GameScreen}, and falls
 *       back to a literal mangled leaf — producing
 *       {@code MultiplayerScreen__MultiplayerScreen_X} (the prefix is
 *       doubled onto the existing leaf to avoid a collision).</li>
 *   <li>the same input against a function in the GLOBAL namespace
 *       behaves differently again (it does not double, and may create
 *       a new namespace).</li>
 * </ul>
 * Behaviour depending on the function's current namespace is exactly
 * what makes the silent fabrication dangerous — bulk renames report
 * {@code success} while producing garbage. To prevent that, this
 * handler rejects any {@code "::"} in {@code name} up front and points
 * the caller at {@code FunctionSetNamespace} for the explicit move.
 *
 * <p><b>No-op guard.</b> Ghidra's
 * {@link ghidra.app.cmd.function.SetFunctionNameCmd#applyTo} returns
 * {@code true} immediately when
 * {@code Listing.getFunctionAt(entry)} is {@code null} (verified by
 * disassembling {@code SetFunctionNameCmd.class} in
 * {@code Base.jar} for Ghidra 12.1.2 — bytecode at offset 31-36 is
 * {@code ifnonnull 37; iconst_1; ireturn}). The caller would see
 * {@code success: true} but nothing was renamed — the program is not
 * dirty, no function is created, no symbol is renamed. The user has
 * no way to tell the call was a no-op without doing a follow-up
 * {@code find --query X --name}.
 *
 * <p>This handler detects that case up front and surfaces a clear
 * error pointing at {@code CreateFunctionCmd} (which can create the
 * function with the desired name in one call) or
 * {@code CreateFunctionCmd} followed by a fresh
 * {@code SetFunctionNameCmd}. This mirrors the silent-no-op guard
 * added to {@code CreateFunctionCmdHandler}.
 */
public final class SetFunctionNameCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String name = RpcContext.reqStr(req, "name");
        // Reject "::" up front — silently mangling "Foo::Bar" into "Foo__Bar"
        // (or worse, doubling it onto the existing leaf) is the bug this
        // guard exists to prevent. Use FunctionSetNamespace for namespace moves.
        if (name.contains("::")) {
            return RpcResponse.error(
                "--name takes a bare leaf and must not contain '::'. "
                + "Got '" + name + "'. "
                + "To change a function's namespace, use `function set-namespace` "
                + "(--namespace PATH --name LEAF); to set a class association "
                + "specifically, use `function set-class-association`.");
        }
        if (ctx.program().getFunctionManager().getFunctionAt(entry) == null) {
            return RpcResponse.error(
                "No function at " + entry + "; SetFunctionNameCmd cannot rename what does not exist. "
                + "Use `function create --address " + entry + " --name " + name
                + "` to create the function with this name in one call, "
                + "or call `function create` first and then `function set-name`.");
        }
        return ctx.applyCommand(
            new SetFunctionNameCmd(entry, name, ctx.sourceType(RpcContext.optStr(req, "source"))));
    }
}
