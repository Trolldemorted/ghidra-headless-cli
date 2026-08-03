package procedures.ghidra.app.cmd.function;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Build a {@link FunctionDefinitionDataType} from a source {@link Function}.
 *
 * <p>Equivalent in shape to Ghidra's
 * {@link ghidra.app.cmd.function.CreateFunctionDefinitionCmd} but:
 *
 * <ul>
 *   <li>Reads {@link Function#getCallingConventionName()} directly. Ghidra's
 *       signature accessor folds a hidden-{@code this} {@code __thiscall} into
 *       {@code "unknown"} (the prototype model can't match an implicit
 *       argument), and {@link
 *       ghidra.program.model.data.FunctionDefinitionDataType#setCallingConvention(String)
 *       setCallingConvention} rejects {@code "unknown"} via
 *       {@code CompilerSpec.isUnknownCallingConvention}. The Function-level
 *       accessor returns the real convention name regardless of hidden-{@code this}
 *       state, so this command preserves {@code __thiscall} (and every other
 *       convention) on the resulting funcdef.</li>
 *   <li>Returns the resolved {@link DataType} via {@link #getDataType()} so the
 *       RPC handler can surface the actual DTM path — including any
 *       {@code .conflict} suffix applied by
 *       {@link DataTypeConflictHandler#DEFAULT_HANDLER}.</li>
 *   <li>Treats missing functions, invalid convention names, and null DTM
 *       resolution as command failures ({@code setStatusMsg} + {@code return
 *       false}) rather than a silent true — see
 *       [[createfunctioncmd-silent-noop]] for the failure mode this avoids.</li>
 * </ul>
 *
 * <p>Pre-existing {@code CreateFunctionDefinitionCmd} is left in place; the
 * server handler now constructs this command instead.
 */
public final class CreateFunctionDefinitionFromSourceCmd
        extends BackgroundCommand<Program> {

    private final Address entry;
    private DataType dataType;

    public CreateFunctionDefinitionFromSourceCmd(Address entry) {
        super("CreateFunctionDefinitionFromSource",
            true, // hasProgress
            true, // canCancel
            true); // isModal
        this.entry = entry;
        this.dataType = null;
    }

    /** Resolved {@link DataType} (post-{@code dtm.resolve}); {@code null} until {@link #applyTo} succeeds. */
    public DataType getDataType() {
        return dataType;
    }

    @Override
    public boolean applyTo(Program program, TaskMonitor monitor) {
        dataType = null;

        Function function = program.getFunctionManager().getFunctionAt(entry);
        if (function == null) {
            setStatusMsg("No function at " + entry + ".");
            return false;
        }

        FunctionSignature signature = function.getSignature(true);
        DataTypeManager dtm = program.getDataTypeManager();

        FunctionDefinitionDataType definition;
        try {
            definition = new FunctionDefinitionDataType(
                CategoryPath.ROOT,
                function.getName(),
                dtm);
            definition.setReturnType(signature.getReturnType());
            definition.setArguments(signature.getArguments());
            definition.setVarArgs(signature.hasVarArgs());
            definition.setNoReturn(signature.hasNoReturn());
            String comment = signature.getComment();
            if (comment != null && !comment.isEmpty()) {
                definition.setComment(comment);
            }

            // Function.getCallingConventionName is the authoritative source.
            // Empty/null => "unknown" so setCallingConvention doesn't reject
            // the empty case (matches Ghidra's own null-as-unknown behavior).
            String convention = function.getCallingConventionName();
            if (convention == null || convention.isEmpty()) {
                convention = "unknown";
            }
            definition.setCallingConvention(convention);
        } catch (InvalidInputException e) {
            setStatusMsg("Invalid calling convention: " + e.getMessage());
            return false;
        } catch (Exception e) {
            setStatusMsg("Failed to build function definition: " + e.getMessage());
            return false;
        }

        try {
            dataType = dtm.resolve(definition, DataTypeConflictHandler.DEFAULT_HANDLER);
        } catch (Exception e) {
            setStatusMsg("Failed to resolve into DTM: " + e.getMessage());
            return false;
        }

        if (dataType == null) {
            setStatusMsg("DTM resolution returned null.");
            return false;
        }
        return true;
    }
}
