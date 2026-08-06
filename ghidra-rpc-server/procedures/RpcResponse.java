package procedures;

/**
 * Generic RPC response POJO, serialized to JSON by gson.
 *
 * gson omits null fields by default, so:
 *   ok()        -> {"success":true}
 *   error(msg)  -> {"success":false,"error":"msg"}
 *
 * Procedures that need to return extra data can subclass this (added fields are
 * serialized alongside {@code success}), keeping the success/error contract uniform.
 */
public class RpcResponse {

    public boolean success;
    public String error;
    /**
     * Non-fatal observation about a successful operation. Carried alongside
     * {@code success:true} so the dispatcher still commits and checkins the
     * underlying write, while the caller learns that something looked off.
     * Used by {@code UpdateFunctionCommandHandler}'s post-apply verifier
     * when {@code Function.updateFunction} succeeds at the Ghidra layer but
     * the live function object disagrees with the request — see the 2026-08-06
     * #391 incident. Adding {@code warning} as a separate field (rather than
     * a non-success response) keeps the dispatcher's success-as-commit-gate
     * contract intact: a warning is advisory, not transactional.
     */
    public String warning;

    public RpcResponse() { }

    public static RpcResponse ok() {
        RpcResponse r = new RpcResponse();
        r.success = true;
        return r;
    }

    public static RpcResponse error(String message) {
        RpcResponse r = new RpcResponse();
        r.success = false;
        r.error = message;
        return r;
    }
}
