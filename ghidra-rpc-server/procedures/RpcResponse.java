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
