package procedures;

import com.google.gson.JsonObject;

/**
 * One RPC procedure handler.
 *
 * The {@code "procedure"} string selects a handler. Handlers that wrap a Ghidra
 * function command live in {@code procedures.ghidra.app.cmd.function} (mirroring
 * Ghidra's package) and are
 * named {@code <GhidraCmd>Handler} (e.g. procedure {@code "SetFunctionNameCmd"} ->
 * {@code procedures.ghidra.app.cmd.function.SetFunctionNameCmdHandler}).
 *
 * Implementations must be stateless and reusable: the server instantiates each
 * handler once (no-arg ctor) and may call {@link #execute} from many client threads.
 * Program access is serialized for the handler by {@link RpcContext#dispatch} (a
 * single lock), so one {@code execute} call has exclusive program access.
 */
public interface RpcProcedure {

    /**
     * Handle a single request line. Throwing turns into an {@code error} response.
     *
     * @param request parsed JSON for this line (includes "procedure")
     * @param ctx     program access + resolver/command helpers
     */
    RpcResponse execute(JsonObject request, RpcContext ctx) throws Exception;

    /**
     * Whether a successful call mutated the program and must therefore be checked in.
     * All {@code ghidra.app.cmd.function} commands mutate, so this defaults to true;
     * the framework checks the file in immediately after a successful mutating call
     * and fails the call if the push fails.
     */
    default boolean mutates() {
        return true;
    }
}
