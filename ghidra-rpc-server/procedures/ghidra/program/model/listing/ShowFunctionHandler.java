package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;

/**
 * Procedure ShowFunction: read back a function's stored signature directly
 * from the {@link Function} object — no decompile path involved.
 *
 * <p>Adds the missing readback verb that complements
 * {@code UpdateFunctionCommand}. The 2026-08-06 #391 incident showed
 * {@code function update} intermittently reporting {@code success} while
 * partial state was visible on the next decompile. Without a
 * decompile-free readback there was no way to tell whether the partial
 * state was a server-side partial application or a stale decompile cache
 * (see notes/rpc-server.md). This handler makes that distinction cheap
 * and side-effect-free.
 *
 * <p>Wire shape (gson serializes the response subclass verbatim):
 * <pre>
 *   {
 *     success:           true,
 *     name:              string,
 *     entryPoint:        string (hex, e.g. "0x00402490"),
 *     callingConvention: string,
 *     returnType:        string (data-type name),
 *     stackPurge:        int,
 *     stackFrameSize:    int,
 *     parameters: [
 *       {name, dataType, ordinal, storage},
 *       ...
 *     ],
 *     hasVarArgs: bool,
 *     noReturn:   bool,
 *     hasRepeatableComment: bool,
 *   }
 * </pre>
 *
 * <p>Sources read straight from the {@code Function} object:
 * <ul>
 *   <li>{@link Function#getName()}, {@link Function#getEntryPoint()}</li>
 *   <li>{@link Function#getCallingConventionName()}</li>
 *   <li>{@link Function#getReturnType()}</li>
 *   <li>{@link Function#getStackPurgeSize()},
 *       {@link Function#getStackFrame()}.{@code getFrameSize()}</li>
 *   <li>{@link Function#getParameter(int)} for each
 *       {@code i < getParameterCount()}. Auto-this is included — the wire
 *       reflects what Ghidra stored, not the formal-list view.</li>
 *   <li>{@link Function#hasVarArgs()},
 *       {@link Function#hasNoReturn()},
 *       {@link Function#getRepeatableComment()}</li>
 * </ul>
 *
 * <p>Project-level: no checkout, no dispatcher transaction (mutates=false).
 * Reading is a no-op on the repository's checkout state.
 */
public final class ShowFunctionHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        Function f = ctx.program().getFunctionManager().getFunctionAt(entry);
        if (f == null) {
            return RpcResponse.error("No function at " + entry + ".");
        }
        return new ShowFunctionResponse(f);
    }

    @Override
    public boolean needsProgram() {
        return true;
    }

    @Override
    public boolean mutates() {
        return false;
    }

    /** Single concrete response — one per call. */
    public static final class ShowFunctionResponse extends RpcResponse {
        public String name;
        public String entryPoint;
        public String callingConvention;
        public String returnType;
        public long stackPurge;
        public long stackFrameSize;
        public List<ParamView> parameters;
        public boolean hasVarArgs;
        public boolean noReturn;
        public boolean hasRepeatableComment;

        public ShowFunctionResponse() {
            // for gson
        }

        ShowFunctionResponse(Function f) {
            this.success = true;
            this.name = f.getName();
            this.entryPoint = f.getEntryPoint().toString();
            this.callingConvention = f.getCallingConventionName();
            DataType ret = f.getReturnType();
            this.returnType = (ret == null) ? "void" : ret.getName();
            this.stackPurge = f.getStackPurgeSize();
            this.stackFrameSize = f.getStackFrame() != null
                ? f.getStackFrame().getFrameSize() : 0;
            this.parameters = new ArrayList<>();
            for (int i = 0; i < f.getParameterCount(); i++) {
                Parameter p = f.getParameter(i);
                DataType pt = p.getDataType();
                VariableStorage vs = p.getVariableStorage();
                this.parameters.add(new ParamView(
                    p.getOrdinal(),
                    p.getName(),
                    (pt == null) ? "undefined" : pt.getName(),
                    (vs == null) ? "?" : vs.toString()));
            }
            this.hasVarArgs = f.hasVarArgs();
            this.noReturn = f.hasNoReturn();
            this.hasRepeatableComment = f.getRepeatableComment() != null
                && !f.getRepeatableComment().isEmpty();
        }
    }

    /** Read-only view of one parameter row. */
    public static final class ParamView {
        public int ordinal;
        public String name;
        public String dataType;
        public String storage;
        public ParamView() { }

        ParamView(int ordinal, String name, String dataType, String storage) {
            this.ordinal = ordinal;
            this.name = name;
            this.dataType = dataType;
            this.storage = storage;
        }
    }
}