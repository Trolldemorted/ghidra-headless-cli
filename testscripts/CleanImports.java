// CleanImports.java - delete every item under a repo folder (default /imports),
// terminating any checkouts WE hold first. Folder from GHIDRA_CLEAN_FOLDER.
//@category Examples.Headless
import ghidra.app.script.GhidraScript;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.PasswordClientAuthenticator;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.store.ItemCheckoutStatus;

public class CleanImports extends GhidraScript {
    @Override
    public void run() throws Exception {
        String host = env("GHIDRA_HOST", "ghidra.stronk.pw");
        int port = Integer.parseInt(env("GHIDRA_PORT", "13100"));
        String user = env("GHIDRA_USER", "claude");
        String pass = env("GHIDRA_PASSWORD", "");
        String repo = env("GHIDRA_PROJECT", "P3");
        String folder = env("GHIDRA_CLEAN_FOLDER", "/imports");

        ClientUtil.setClientAuthenticator(new PasswordClientAuthenticator(user, pass));
        RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port, true);
        RepositoryAdapter r = server.getRepository(repo);
        r.connect();

        RepositoryItem[] items = r.getItemList(folder);
        if (items == null || items.length == 0) {
            println("[Clean] " + folder + " empty / not found");
            return;
        }
        for (RepositoryItem it : items) {
            for (ItemCheckoutStatus c : r.getCheckouts(folder, it.getName())) {
                if (user.equals(c.getUser())) {
                    r.terminateCheckout(folder, it.getName(), c.getCheckoutId(), true);
                }
            }
            r.deleteItem(folder, it.getName(), -1); // -1 = all versions
            println("[Clean] deleted " + folder + "/" + it.getName());
        }
    }

    private String env(String k, String d) { String v = System.getenv(k); return (v == null || v.isEmpty()) ? d : v; }
}
