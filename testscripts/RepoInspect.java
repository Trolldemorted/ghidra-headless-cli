// RepoInspect.java - dump shared-repo server-side state: our permission level,
// every item, its latest version, and any outstanding checkouts (who holds them).
//@category Examples.Headless
import ghidra.app.script.GhidraScript;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.PasswordClientAuthenticator;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.remote.User;
import ghidra.framework.store.ItemCheckoutStatus;

import java.util.ArrayDeque;
import java.util.Deque;

public class RepoInspect extends GhidraScript {
    @Override
    public void run() throws Exception {
        String host = env("GHIDRA_HOST", "ghidra.stronk.pw");
        int port = Integer.parseInt(env("GHIDRA_PORT", "13100"));
        String user = env("GHIDRA_USER", "claude");
        String pass = env("GHIDRA_PASSWORD", "");
        String repo = env("GHIDRA_PROJECT", "P3");

        ClientUtil.setClientAuthenticator(new PasswordClientAuthenticator(user, pass));
        RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port, true);
        println("[Repo] connected=" + server.isConnected());

        RepositoryAdapter r = server.getRepository(repo);
        r.connect();
        User me = r.getUser();
        println("[Repo] me=" + me.getName() + " write=" + me.hasWritePermission()
                + " admin=" + me.isAdmin() + " readOnly=" + me.isReadOnly());
        println("[Repo] serverUsers=" + String.join(",", r.getServerUserList()));

        Deque<String> stack = new ArrayDeque<>();
        stack.push("/");
        while (!stack.isEmpty()) {
            String folder = stack.pop();
            for (String sub : r.getSubfolderList(folder)) {
                stack.push(folder.equals("/") ? "/" + sub : folder + "/" + sub);
            }
            for (RepositoryItem it : r.getItemList(folder)) {
                StringBuilder sb = new StringBuilder();
                sb.append("[Item] ").append(it.getPathName())
                  .append("  type=").append(it.getContentType())
                  .append("  v").append(it.getVersion());
                ItemCheckoutStatus[] cos = r.getCheckouts(folder, it.getName());
                if (cos != null && cos.length > 0) {
                    sb.append("  CHECKOUTS=");
                    for (ItemCheckoutStatus c : cos) {
                        sb.append(c.getUser()).append("(v").append(c.getCheckoutVersion())
                          .append(",").append(c.getCheckoutType()).append(") ");
                    }
                } else {
                    sb.append("  checkouts=none");
                }
                println(sb.toString());
            }
        }
    }

    private String env(String k, String d) { String v = System.getenv(k); return (v == null || v.isEmpty()) ? d : v; }
}
