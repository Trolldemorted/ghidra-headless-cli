package procedures.ghidra.framework.model;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.framework.model.DomainFile;

/**
 * Procedure FileMetadata: return a project file's attributes and stored metadata.
 *
 * Project-level and read-only: it resolves the {@code "file"} path to a {@link DomainFile}
 * via {@link RpcContext#requireDomainFile} WITHOUT opening or checking out the program, so
 * {@link #needsProgram()} is false (dispatch does no checkout) and {@link #mutates()} is
 * false. The stored {@code metadata} map ({@link DomainFile#getMetadata()}) is persisted
 * alongside the file (for programs: Executable Format, Language ID, Compiler, Created-With
 * version, …) and is read without instantiating the domain object.
 */
public final class FileMetadataHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        DomainFile df = ctx.requireDomainFile(RpcContext.reqStr(req, "file"));

        long size;
        try {
            size = df.length();
        } catch (IOException e) {
            size = -1; // size unavailable (e.g. not yet checked out / IO error)
        }

        Map<String, String> metadata = df.getMetadata();
        if (metadata == null) {
            metadata = Collections.emptyMap();
        }

        return new FileMetadataResponse(df, size, metadata);
    }

    @Override
    public boolean needsProgram() {
        return false; // resolves the DomainFile itself; no program open/checkout
    }

    @Override
    public boolean mutates() {
        return false;
    }

    /** A project file's attributes plus its stored metadata map. */
    static final class FileMetadataResponse extends RpcResponse {
        final String name;
        final String path;
        final String contentType;
        final int version;
        final boolean versioned;
        final boolean checkedOut;
        final boolean readOnly;
        final long lastModified;
        final String fileID;
        final long size;
        final Map<String, String> metadata;

        FileMetadataResponse(DomainFile df, long size, Map<String, String> metadata) {
            this.success = true;
            this.name = df.getName();
            this.path = df.getPathname();
            this.contentType = df.getContentType();
            this.version = df.getVersion();
            this.versioned = df.isVersioned();
            this.checkedOut = df.isCheckedOut();
            this.readOnly = df.isReadOnly();
            this.lastModified = df.getLastModifiedTime();
            this.fileID = df.getFileID();
            this.size = size;
            this.metadata = metadata;
        }
    }
}
