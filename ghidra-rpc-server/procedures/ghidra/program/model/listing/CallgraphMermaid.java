package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Renders a {@link CallgraphWalker.Result} as a Mermaid {@code flowchart}.
 * For {@code direction="called"} the root is at the top and the graph flows
 * downward ({@code graph TD}); for {@code direction="calling"} the root is
 * at the bottom and callers are drawn above it ({@code graph BT}). External
 * / leaf nodes get a tinted classDef so they stand out at a glance.
 */
final class CallgraphMermaid {

    private CallgraphMermaid() { }

    static String render(List<CallgraphNode> nodes, List<CallgraphEdge> edges, String direction) {
        String header = direction.equals("calling") ? "graph BT" : "graph TD";
        StringBuilder sb = new StringBuilder();
        sb.append(header).append('\n');

        // Preserve the BFS-discovery order so the Mermaid source is stable
        // (and so parents naturally appear before their children). Nodes are
        // identified by address: two functions may share a name. The id is
        // the readable name where that is unique, name + address otherwise.
        Map<String, String> idByAddress = new LinkedHashMap<>();
        Set<String> usedIds = new HashSet<>();
        for (CallgraphNode n : nodes) {
            if (idByAddress.containsKey(n.address)) {
                continue;
            }
            String id = sanitizeId(n.name);
            if (!usedIds.add(id)) {
                id = sanitizeId(n.name + "_" + n.address);
                usedIds.add(id);
            }
            idByAddress.put(n.address, id);
            String label = n.isExternal ? n.name : (n.name + " @" + n.address);
            sb.append("  ").append(id).append("[\"").append(escapeLabel(label)).append("\"]\n");
        }
        for (CallgraphEdge edge : edges) {
            String fromId = idByAddress.get(edge.fromAddress);
            String toId = idByAddress.get(edge.toAddress);
            if (fromId == null || toId == null) {
                continue;
            }
            sb.append("  ").append(fromId).append(" --> ").append(toId).append('\n');
        }
        // ClassDef for external / leaf-style nodes. Mermaid syntax is
        // `class id1,id2 className` (one class name after the whole list).
        List<String> external = new ArrayList<>();
        for (CallgraphNode n : nodes) {
            if (n.isExternal) {
                external.add(idByAddress.get(n.address));
            }
        }
        if (!external.isEmpty()) {
            sb.append("  classDef leaf fill:#fef,stroke:#333\n");
            sb.append("  class ").append(String.join(",", external)).append(" leaf\n");
        }
        return sb.toString();
    }

    private static String sanitizeId(String name) {
        // Mermaid IDs must be valid identifiers. Replace anything that
        // isn't [A-Za-z0-9_] with '_'. Prepend "n_" to guarantee a letter
        // start.
        StringBuilder sb = new StringBuilder(name.length() + 2);
        sb.append("n_");
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            sb.append(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
                ? c : '_');
        }
        return sb.toString();
    }

    private static String escapeLabel(String label) {
        // Labels live between [" ... "] and are rendered as HTML, so a
        // demangled name like `operator<<` or `vector<int>` needs escaping,
        // not just the quote that would end the label.
        StringBuilder sb = new StringBuilder(label.length() + 8);
        for (int i = 0; i < label.length(); i++) {
            char c = label.charAt(i);
            if (c == '&') {
                sb.append("&amp;");
            } else if (c == '<') {
                sb.append("&lt;");
            } else if (c == '>') {
                sb.append("&gt;");
            } else if (c == '"') {
                sb.append("&quot;");
            } else if (c == '\n') {
                sb.append("<br/>");
            } else {
                sb.append(c < 0x20 ? ' ' : c);
            }
        }
        return sb.toString();
    }
}
