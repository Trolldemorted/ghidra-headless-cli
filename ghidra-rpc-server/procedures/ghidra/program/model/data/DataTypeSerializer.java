package procedures.ghidra.program.model.data;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;

/**
 * Render a {@link DataType} as a JSON-friendly shape.
 *
 * Top-level (struct/union/enum/typedef) returns a {@link JsonObject} with full
 * detail; nested uses (field types) are rendered as a C-syntax display name
 * (e.g. {@code "MyStruct *"}, {@code "int[4]"}) to avoid cycles. Built-in
 * primitives are detected by class and emit just the name.
 */
final class DataTypeSerializer {

    private final DataTypeManager dtm;

    DataTypeSerializer(DataTypeManager dtm) {
        this.dtm = dtm;
    }

    /** Serialize any data type as a flat object (used for {@code ShowDataType}). */
    JsonObject describe(DataType dt) {
        JsonObject o = new JsonObject();
        if (dt == null) {
            o.addProperty("kind", "null");
            return o;
        }
        String kind = kindOf(dt);
        o.addProperty("kind", kind);
        o.addProperty("name", dt.getName());
        o.addProperty("path", pathOf(dt));
        Category cat = dtm.getCategory(dt.getCategoryPath());
        o.addProperty("category", cat == null ? "/" : cat.getCategoryPathName());
        o.addProperty("size", dt.getLength());
        o.addProperty("source", sourceOf(dt));
        o.addProperty("sourceArchive", archiveOf(dt));
        if (dt.getDescription() != null && !dt.getDescription().isEmpty()) {
            o.addProperty("description", dt.getDescription());
        }
        if (dt instanceof Composite) {
            Composite c = (Composite) dt;
            o.add("fields", serializeCompositeFields(c));
            if (dt instanceof Structure) {
                o.addProperty("packed", ((Structure) dt).isPackingEnabled());
                o.addProperty("alignment", ((Structure) dt).getAlignment());
            }
        } else if (dt instanceof Enum) {
            Enum e = (Enum) dt;
            o.addProperty("signed", e.isSigned());
            o.add("entries", serializeEnumEntries(e));
        } else if (dt instanceof TypeDef) {
            TypeDef td = (TypeDef) dt;
            DataType base = td.getDataType();
            o.addProperty("base", base == null ? td.getName() : base.getDisplayName());
        } else if (dt instanceof Pointer) {
            Pointer p = (Pointer) dt;
            DataType inner = p.getDataType();
            o.addProperty("base", inner == null ? "void" : inner.getDisplayName());
        } else if (dt instanceof Array) {
            Array a = (Array) dt;
            o.addProperty("base", a.getDataType().getDisplayName());
            o.addProperty("count", a.getNumElements());
        } else if (dt instanceof FunctionDefinition) {
            FunctionDefinition fd = (FunctionDefinition) dt;
            o.addProperty("signature", fd.getPrototypeString());
        } else if (dt instanceof BitFieldDataType) {
            BitFieldDataType bf = (BitFieldDataType) dt;
            o.addProperty("base", bf.getDisplayName()); // bitfield naming includes size
            o.addProperty("bitOffset", bf.getBitOffset());
            o.addProperty("bitSize", bf.getBitSize());
        }
        return o;
    }

    /** Short label for {@code ListDataTypes}: name + path + category + kind + size. */
    JsonObject summarize(DataType dt) {
        JsonObject o = new JsonObject();
        o.addProperty("name", dt.getName());
        o.addProperty("path", pathOf(dt));
        Category cat = dtm.getCategory(dt.getCategoryPath());
        o.addProperty("category", cat == null ? "/" : cat.getCategoryPathName());
        o.addProperty("kind", kindOf(dt));
        o.addProperty("size", dt.getLength());
        o.addProperty("source", sourceOf(dt));
        o.addProperty("sourceArchive", archiveOf(dt));
        return o;
    }

    private JsonArray serializeCompositeFields(Composite c) {
        JsonArray arr = new JsonArray();
        int n = c.getNumComponents();
        for (int i = 0; i < n; i++) {
            DataTypeComponent comp = c.getComponent(i);
            if (comp == null) continue;
            DataType fdt = comp.getDataType();
            if (fdt == null) continue;
            JsonObject f = new JsonObject();
            f.addProperty("name", comp.getFieldName());
            f.addProperty("offset", comp.getOffset());
            f.addProperty("size", fdt.getLength());
            f.addProperty("type", fdt.getDisplayName());
            arr.add(f);
        }
        return arr;
    }

    private JsonArray serializeEnumEntries(Enum e) {
        JsonArray arr = new JsonArray();
        for (String name : e.getNames()) {
            long v = e.getValue(name);
            JsonObject entry = new JsonObject();
            entry.addProperty("name", name);
            entry.addProperty("value", v);
            arr.add(entry);
        }
        return arr;
    }

    /** Path string ({@code /Category/Sub/Name}); empty when the type has no category. */
    static String pathOf(DataType dt) {
        String p = dt.getCategoryPath().getName();
        return (p == null || p.isEmpty()) ? "/" + dt.getName() : p + "/" + dt.getName();
    }

    /** One of: struct, union, enum, typedef, pointer, array, functiondef, primitive. */
    static String kindOf(DataType dt) {
        if (dt instanceof Structure) return "struct";
        if (dt instanceof Union) return "union";
        if (dt instanceof Enum) return "enum";
        if (dt instanceof TypeDef) return "typedef";
        if (dt instanceof Pointer) return "pointer";
        if (dt instanceof Array) return "array";
        if (dt instanceof FunctionDefinition) return "functiondef";
        if (dt instanceof BitFieldDataType) return "bitfield";
        return "primitive";
    }

    /** Coarse source: USER, BUILTIN, or the archive's name. */
    private static String sourceOf(DataType dt) {
        SourceArchive arc = dt.getSourceArchive();
        if (arc == null) return "USER";
        String n = arc.getName();
        if (n == null) return "USER";
        if (n.equalsIgnoreCase("BuiltIns") || n.equalsIgnoreCase("ANSI_C")
                || n.equalsIgnoreCase("windows_vs")) {
            return "BUILTIN";
        }
        return "ARCHIVE";
    }

    /** Source archive name (or null when the type is user-defined). */
    private static String archiveOf(DataType dt) {
        SourceArchive arc = dt.getSourceArchive();
        if (arc == null) return null;
        String n = arc.getName();
        if (n == null || n.equalsIgnoreCase("BuiltIns") || n.equalsIgnoreCase("ANSI_C")
                || n.equalsIgnoreCase("windows_vs")) {
            return null;
        }
        return n;
    }
}