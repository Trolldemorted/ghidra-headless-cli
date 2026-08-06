package procedures.ghidra.app.cmd.function;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Parameter;
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
 *   <li>Preserves the auto-{@code this} parameter. Ghidra's
 *       {@link FunctionSignature#getArguments()} returns the formal arg list
 *       with auto-{@code this} stripped; building the def via
 *       {@code new FunctionDefinitionDataType(FunctionSignature)} therefore
 *       silently drops {@code this} on any {@code __thiscall} source. Applying
 *       such a def to a vtable slot then renders call sites with shifted
 *       parameters (the {@code this} slot eats the first formal arg). This
 *       command enumerates parameters via {@link Function#getParameter(int)}
 *       and converts each to a {@link ParameterDefinitionImpl}, renaming the
 *       auto-this entry to {@code "this"} so the resulting funcdef has the
 *       correct shape. See the 2026-08-06 bug report: typing a slot with a
 *       def missing {@code this} is worse than leaving the slot {@code void *}.</li>
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

            // Build the arg list. signature.getArguments() excludes auto-this,
            // so on a __thiscall source we must prepend a leading 'this'
            // ParameterImpl of the source's this-data-type. Detection:
            // function.getParameter(i).isAutoParameter() &&
            //   .getAutoParameterType() == AutoParameterType.THIS.
            ParameterDefinition[] args = buildArgsPreservingThis(function, program);
            definition.setArguments(args);

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

    /**
     * Build a {@link ParameterDefinition} array for the funcdef, preserving
     * the source's auto-{@code this} parameter.
     *
     * <p>Strategy: enumerate the source function's parameters via
     * {@link Function#getParameter(int)} (which DOES include auto-this) and
     * convert each to a {@link ParameterDefinition}. For auto-this we wrap in
     * a fresh {@link ParameterImpl} named {@code "this"} with the source's
     * this-data-type (a pointer-to-class; same shape Ghidra uses elsewhere
     * for the auto slot). For ordinary params we wrap the existing
     * {@link Parameter} via {@code new ParameterImpl(existing, program)} —
     * the copy-constructor carries name, type, storage, ordinal, and
     * source-type, so user-renamed params survive the round trip.
     *
     * <p>If the source's auto-this is somehow not exposed via
     * {@code getParameter(i)} (defensive — observed only on synthetic
     * functions), fall back to {@code signature.getArguments()} verbatim.
     */
    private static ParameterDefinition[] buildArgsPreservingThis(
            Function function, Program program) throws InvalidInputException {

        Parameter[] sourceParams = new Parameter[function.getParameterCount()];
        for (int i = 0; i < sourceParams.length; i++) {
            sourceParams[i] = function.getParameter(i);
        }

        boolean foundThis = false;
        for (Parameter p : sourceParams) {
            if (p.isAutoParameter() && p.getAutoParameterType() == AutoParameterType.THIS) {
                foundThis = true;
                break;
            }
        }

        if (!foundThis) {
            // Source has no auto-this; signature.getArguments() is the truth.
            return function.getSignature(true).getArguments();
        }

        ParameterDefinition[] out = new ParameterDefinition[sourceParams.length];
        for (int i = 0; i < sourceParams.length; i++) {
            Parameter p = sourceParams[i];
            // setArguments wants ParameterDefinition (the data-side contract).
            // ParameterImpl implements the program-side Parameter interface,
            // not ParameterDefinition, so we build ParameterDefinitionImpl
            // directly. The funcdef stores name + type + comment; storage and
            // ordinal are reconstructed by the funcdef itself.
            String name = p.getName();
            if (p.isAutoParameter() && p.getAutoParameterType() == AutoParameterType.THIS) {
                name = "this";
            }
            out[i] = new ParameterDefinitionImpl(name, p.getDataType(), p.getComment());
        }
        return out;
    }
}
