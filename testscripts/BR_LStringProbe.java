// BR_LStringProbe.java - read-only probe. Wrapper launches analyzeHeadless
// against Battle%20Realms (-readOnly), which opens a TransientProjectData
// keyed at "Battle Realms(read-only)" (NOT "P3"). The script's
// `state.getProject()` gives us that transient project, and we can find
// Battle_Realms_F.exe in its root folder.
//
// Dump:
//  - every DataType named "L_String" (kind/size/sourceArchive)
//  - DTM getDataType by (rootCat, name) - what `datatype show --path /L_String` does
//  - DataTypeParser.parse("L_String") and parse("/L_String") - what
//    `--fields --type L_String` / `--fields --type /L_String` resolve
//
// Run with:
//   GHIDRA_PROJECT='Battle%20Realms' GHIDRA_READONLY=1 \
//   /workdir/ghidra-rpc-server/ghidra-headless.sh
//@category Examples.Headless

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import java.util.Iterator;

public class BR_LStringProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            println("[BR] no project in GhidraState");
            return;
        }
        println("[BR] project=" + project.getName() +
                " projectLocator=" + project.getProjectLocator());

        // List root files so we can see the canonical program name.
        ghidra.framework.model.DomainFolder rootFolder =
            project.getProjectData().getRootFolder();
        DomainFile[] roots = rootFolder.getFiles();
        println("[BR] files in / (" + roots.length + "):");
        for (DomainFile f : roots) {
            println("[BR]   " + f.getPathname() + " v" + f.getVersion() +
                    " readOnly=" + f.isReadOnly() + " checkedOut=" + f.isCheckedOut());
        }
        DomainFile df = rootFolder.getFile("Battle_Realms_F.exe");
        if (df == null) {
            println("[BR] Battle_Realms_F.exe not found at /");
            return;
        }
        // Open the program. Second arg false = no upgrade-to-checkout;
        // third arg false = don't block other consumers.
        ghidra.program.model.listing.Program program =
            (ghidra.program.model.listing.Program) df.getDomainObject(this, false, false, monitor);
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            println("[BR] program=" + program.getName() +
                    " DTM count=" + dtm.getDataTypeCount(true));

            // Dump every type named L_String.
            println("[BR] --- all types named L_String ---");
            int i = 0;
            Iterator<DataType> it = dtm.getAllDataTypes();
            while (it.hasNext()) {
                DataType dt = it.next();
                if ("L_String".equals(dt.getName())) {
                    i++;
                    println("[BR]   [" + i + "] path=" + dt.getCategoryPath() +
                            "/" + dt.getName() +
                            " kind=" + dt.getClass().getSimpleName() +
                            " size=" + dt.getLength() +
                            " sourceArchive=" + (dt.getSourceArchive() == null ? "null" :
                                dt.getSourceArchive().getName()));
                }
            }
            println("[BR] total L_String entries: " + i);

            // Path-based lookup (what `datatype show --path /L_String` uses).
            CategoryPath root = new CategoryPath("/");
            DataType byPath = dtm.getDataType(root, "L_String");
            println("[BR] dtm.getDataType(/, L_String) = " +
                    (byPath == null ? "null" :
                        "kind=" + byPath.getClass().getSimpleName() +
                        " size=" + byPath.getLength() +
                        " sourceArchive=" + (byPath.getSourceArchive() == null ? "null" :
                            byPath.getSourceArchive().getName())));

            // /Demangler/L_String — the actual location.
            CategoryPath demang = new CategoryPath("/Demangler");
            DataType byPathDemang = dtm.getDataType(demang, "L_String");
            println("[BR] dtm.getDataType(/Demangler, L_String) = " +
                    (byPathDemang == null ? "null" :
                        "kind=" + byPathDemang.getClass().getSimpleName() +
                        " size=" + byPathDemang.getLength() +
                        " sourceArchive=" + (byPathDemang.getSourceArchive() == null ? "null" :
                            byPathDemang.getSourceArchive().getName())));

            // byDataTypePath-style: full /Demangler/L_String string.
            DataType byFullPath = dtm.getDataType("/Demangler/L_String");
            println("[BR] dtm.getDataType(/Demangler/L_String) = " +
                    (byFullPath == null ? "null" :
                        "kind=" + byFullPath.getClass().getSimpleName() +
                        " size=" + byFullPath.getLength() +
                        " sourceArchive=" + (byFullPath.getSourceArchive() == null ? "null" :
                            byFullPath.getSourceArchive().getName())));

            // Also try byDataTypePath with bare "L_String".
            DataType byNameOnly = dtm.getDataType("L_String");
            println("[BR] dtm.getDataType(L_String) = " +
                    (byNameOnly == null ? "null" :
                        "kind=" + byNameOnly.getClass().getSimpleName() +
                        " size=" + byNameOnly.getLength() +
                        " sourceArchive=" + (byNameOnly.getSourceArchive() == null ? "null" :
                            byNameOnly.getSourceArchive().getName())));

            // List EVERY L_String across ALL categories (same as getAllDataTypes
            // but grouped).
            println("[BR] --- every L_String by category ---");
            java.util.Map<String, java.util.List<String>> byCat = new java.util.LinkedHashMap<>();
            Iterator<DataType> it2 = dtm.getAllDataTypes();
            while (it2.hasNext()) {
                DataType dt = it2.next();
                if ("L_String".equals(dt.getName())) {
                    byCat.computeIfAbsent(dt.getCategoryPath().getPath(),
                        k -> new java.util.ArrayList<>()).add(dt.getName());
                }
            }
            for (java.util.Map.Entry<String, java.util.List<String>> e : byCat.entrySet()) {
                println("[BR]   " + e.getKey() + ": " + e.getValue().size() + " L_String");
            }

            // DataTypeParser lookup (what --fields --type uses).
            try {
                DataTypeParser parser = new DataTypeParser(
                        dtm, dtm, null, AllowedDataTypes.ALL);
                DataType parsed = parser.parse("L_String");
                println("[BR] DataTypeParser.parse(L_String) = " +
                        (parsed == null ? "null" :
                            "kind=" + parsed.getClass().getSimpleName() +
                            " size=" + parsed.getLength() +
                            " sourceArchive=" + (parsed.getSourceArchive() == null ? "null" :
                                parsed.getSourceArchive().getName())));
            } catch (Throwable t) {
                println("[BR] DataTypeParser.parse threw: " +
                        t.getClass().getSimpleName() + ": " + t.getMessage());
            }

            // Also try with /L_String (with leading slash, mirroring RpcContext normalization).
            try {
                DataTypeParser parser = new DataTypeParser(
                        dtm, dtm, null, AllowedDataTypes.ALL);
                DataType parsed = parser.parse("/L_String");
                println("[BR] DataTypeParser.parse(/L_String) = " +
                        (parsed == null ? "null" :
                            "kind=" + parsed.getClass().getSimpleName() +
                            " size=" + parsed.getLength() +
                            " sourceArchive=" + (parsed.getSourceArchive() == null ? "null" :
                                parsed.getSourceArchive().getName())));
            } catch (Throwable t) {
                println("[BR] DataTypeParser.parse(/L_String) threw: " +
                        t.getClass().getSimpleName() + ": " + t.getMessage());
            }

            // CParser-equivalent lookup: dtm.findDataTypes(name) is the call
            // CParser.getType() makes when its local maps miss. This is what
            // `struct Foo { L_String x; };` resolves through (via CParser).
            println("[BR] --- CParser-equivalent: dtm.findDataTypes(\"L_String\") ---");
            java.util.ArrayList<DataType> hits = new java.util.ArrayList<>();
            dtm.findDataTypes("L_String", hits);
            for (int h = 0; h < hits.size(); h++) {
                DataType h0 = hits.get(h);
                println("[BR]   hit[" + h + "] path=" + h0.getCategoryPath() +
                        "/" + h0.getName() +
                        " kind=" + h0.getClass().getSimpleName() +
                        " size=" + h0.getLength() +
                        " sourceArchive=" + (h0.getSourceArchive() == null ? "null" :
                            h0.getSourceArchive().getName()));
            }
            if (hits.isEmpty()) {
                println("[BR]   (no hits — bare-name lookup would FAIL in CParser)");
            }

            // Same for /Demangler/L_String with full path - this should always resolve.
            println("[BR] --- CParser-equivalent: dtm.findDataTypes(\"/Demangler/L_String\") ---");
            java.util.ArrayList<DataType> hits2 = new java.util.ArrayList<>();
            dtm.findDataTypes("/Demangler/L_String", hits2);
            for (int h = 0; h < hits2.size(); h++) {
                DataType h0 = hits2.get(h);
                println("[BR]   hit[" + h + "] path=" + h0.getCategoryPath() +
                        "/" + h0.getName() +
                        " kind=" + h0.getClass().getSimpleName() +
                        " size=" + h0.getLength());
            }

            // The KEY question for the user's delete complaint:
            // is /Demangler/L_String a LOCAL program-DTM type or an UPSTREAM
            // archive-resolved stub? The delete handler's behavior hinges on
            // this — local types are deletable, archive stubs are immutable.
            DataType stub = dtm.getDataType("/Demangler/L_String");
            if (stub != null) {
                ghidra.program.model.data.SourceArchive arc = stub.getSourceArchive();
                println("[BR] --- delete-feasibility check on /Demangler/L_String ---");
                println("[BR]   sourceArchive.name=" + (arc == null ? "null" : arc.getName()));
                println("[BR]   sourceArchive.id=" +
                    (arc == null ? "null" : arc.getSourceArchiveID()));
                ghidra.util.UniversalID localId =
                    ghidra.program.model.data.DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID;
                ghidra.util.UniversalID builtInId =
                    ghidra.program.model.data.DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID;
                println("[BR]   isLocalProgramType=" +
                    (arc == null ? "true (null archive -> local)"
                        : arc.getSourceArchiveID().equals(localId) ? "true (id=LOCAL_ARCHIVE)" : "false"));
                println("[BR]   isBuiltIn=" +
                    (arc != null && arc.getSourceArchiveID().equals(builtInId)));
                println("[BR]   -> " +
                    (arc == null ? "deletable"
                        : arc.getSourceArchiveID().equals(localId) ? "deletable (local program DTM)"
                        : arc.getSourceArchiveID().equals(builtInId) ? "IMMUTABLE (built-in)"
                        : "?? UNKNOWN archive type, likely IMMUTABLE archive stub"));
            }

            // Also list every source archive open for this DTM so we can see
            // what's around.
            println("[BR] --- all open source archives ---");
            for (ghidra.program.model.data.SourceArchive sa : dtm.getSourceArchives()) {
                if (sa == null) continue;
                println("[BR]   " + sa.getName() +
                        " id=" + sa.getSourceArchiveID() +
                        " (local=" + sa.getSourceArchiveID().equals(
                            ghidra.program.model.data.DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID) + ")");
            }
        } finally {
            program.release(this);
        }
    }
}
