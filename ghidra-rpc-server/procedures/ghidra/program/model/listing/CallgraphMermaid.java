package procedures.ghidra.program.model.listing;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Renders a {@link CallgraphWalker.Result} as a Mermaid {@code flowchart}.
 * For {@code direction="called"} the root is at the top and the graph flows
 * downward ({@code graph TD}); for {@code direction="calling"} the root is
 * at the bottom and callers are drawn above it ({@code graph BT}). External
 * / leaf nodes get a tinted classDef so they stand out at a glance.
 */
final class CallgraphMermaid {

    private CallgraphMermaid() {}

    static String render(List<CallgraphNode> nodes, List<CallgraphEdge> edges, String direction) {
        String header = direction.equals("calling") ? "graph BT" : "graph TD";
        StringBuilder sb = new StringBuilder();
        sb.append(header).append('\n');

        // Preserve the BFS-discovery order so the Mermaid source is stable
        // (and so parents naturally appear before their children).
        Map<String, String> idByName = new LinkedHashMap<>();
        for (CallgraphNode n : nodes) {
            idByName.putIfAbsent(n.name, sanitizeId(n.name));
        }
        for (Map.Entry<String, String> e : idByName.entrySet()) {
            CallgraphNode node = findNode(nodes, e.getKey());
            String label = node.isExternal ? e.getKey() : (e.getKey() + " @" + node.address);
            sb.append("  ").append(e.getValue()).append("[\"").append(escapeLabel(label)).append("\"]\n");
        }
        for (CallgraphEdge edge : edges) {
            String fromId = idByName.get(edge.from);
            String toId = idByName.get(edge.to);
            if (fromId == null || toId == null) {
                continue;
            }
            sb.append("  ").append(fromId).append(" --> ").append(toId).append('\n');
        }
        // ClassDef for external / leaf-style nodes.
        boolean anyExternal = false;
        for (CallgraphNode n : nodes) {
            if (n.isExternal) {
                anyExternal = true;
                break;
            }
        }
        if (anyExternal) {
            sb.append("  classDef leaf fill:#fef,stroke:#333\n");
            sb.append("  class ");
            boolean first = true;
            for (CallgraphNode n : nodes) {
                if (!n.isExternal) continue;
                if (!first) sb.append(',');
                sb.append(idByName.get(n.name)).append(" leaf");
                first = false;
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    private static CallgraphNode findNode(List<CallgraphNode> nodes, String name) {
        for (CallgraphNode n : nodes) {
            if (n.name.equals(name)) {
                return n;
            }
        }
        return null;
    }

    private static String sanitizeId(String name) {
        // Mermaid IDs must be valid identifiers. Replace anything that
        // isn't [A-Za-z0-9_] with '_'. Prepend "n_" to guarantee a letter
        // start.
        StringBuilder sb = new StringBuilder(name.length() + 2);
        sb.append("n_");
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            sb.append((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
                ? c : '_');
        }
        return sb.toString();
    }

    private static String escapeLabel(String label) {
        // Mermaid labels live between [" ... "] — escape the two terminators
        // we care about: " and \n.
        return label.replace("\"", "&quot;").replace("\n", "<br/>");
    }
}
