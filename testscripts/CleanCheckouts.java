// CleanCheckouts.java - terminate OUR OWN stale checkouts in the shared repo.
// Transient (ghidra://) headless runs can orphan a server-side checkout if a run
// fails mid-commit; that leftover blocks the exclusive checkout a later -commit
// needs. This clears only checkouts owned by GHIDRA_USER. Never touches others'.
//@category Examples.Headless
import ghidra.app.script.GhidraScript;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.PasswordClientAuthenticator;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.store.ItemCheckoutStatus;

import java.util.ArrayDeque;
import java.util.Deque;

public class CleanCheckouts extends GhidraScript {
    @Override
    public void run() throws Exception {
        String host = env("GHIDRA_HOST", "ghidra.stronk.pw");
        int port = Integer.parseInt(env("GHIDRA_PORT", "13100"));
        String user = env("GHIDRA_USER", "claude");
        String pass = env("GHIDRA_PASSWORD", "");
        String repo = env("GHIDRA_PROJECT", "P3");

        ClientUtil.setClientAuthenticator(new PasswordClientAuthenticator(user, pass));
        RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port, true);
        RepositoryAdapter r = server.getRepository(repo);
        r.connect();
        println("[Clean] connected as " + user + " to repo " + repo);

        Deque<String> stack = new ArrayDeque<>();
        stack.push("/");
        int killed = 0;
        while (!stack.isEmpty()) {
            String folder = stack.pop();
            for (String sub : r.getSubfolderList(folder)) {
                stack.push(folder.equals("/") ? "/" + sub : folder + "/" + sub);
            }
            for (RepositoryItem it : r.getItemList(folder)) {
                for (ItemCheckoutStatus c : r.getCheckouts(folder, it.getName())) {
                    if (user.equals(c.getUser())) {
                        println("[Clean] terminating checkout id=" + c.getCheckoutId()
                                + " on " + it.getPathName() + " (v" + c.getCheckoutVersion() + ")");
                        r.terminateCheckout(folder, it.getName(), c.getCheckoutId(), true);
                        killed++;
                    } else {
                        println("[Clean] leaving checkout of OTHER user " + c.getUser()
                                + " on " + it.getPathName());
                    }
                }
            }
        }
        println("[Clean] terminated " + killed + " checkout(s)");
    }

    private String env(String k, String d) { String v = System.getenv(k); return (v == null || v.isEmpty()) ? d : v; }
}
