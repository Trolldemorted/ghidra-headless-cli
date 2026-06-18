package procedures.ghidra.program.model.data;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;

/**
 * A {@link DataTypeConflictHandler} that throws on every name clash — never
 * silently renames, replaces, or merges. Used by {@link CreateDataTypeHandler}
 * because the project's policy is to never auto-resolve: a caller that asks
 * for "/MyType" and there's already a "/MyType" should see an error, not
 * have their struct renamed to "/MyType.conflict".
 *
 * Returns from {@link #resolveConflict} are deliberately impossible — the
 * throw ensures we never return one.
 */
final class StrictConflictHandler extends DataTypeConflictHandler {
    @Override
    public ConflictResult resolveConflict(DataType existingDt, DataType newDt) {
        throw new IllegalStateException("Data type '" + existingDt.getName()
            + "' already exists in " + existingDt.getCategoryPath().getName());
    }

    @Override
    public boolean shouldUpdate(DataType existingDt, DataType newDt) {
        return false; // never update; the caller must explicitly delete and recreate
    }

    @Override
    public DataTypeConflictHandler getSubsequentHandler() {
        return this;
    }
}
