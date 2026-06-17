// DeleteTestProgram.java - remove a throwaway test program from the shared repo.
// Connects directly to the Ghidra Server, terminates any checkouts WE hold on the
// target, then deletes all of its versions. Target name from GHIDRA_DELETE_NAME.
//@category Examples.Headless
import ghidra.app.script.GhidraScript;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.PasswordClientAuthenticator;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.store.ItemCheckoutStatus;

public class DeleteTestProgram extends GhidraScript {
    @Override
    public void run() throws Exception {
        String host = env("GHIDRA_HOST", "ghidra.stronk.pw");
        int port = Integer.parseInt(env("GHIDRA_PORT", "13100"));
        String user = env("GHIDRA_USER", "claude");
        String pass = env("GHIDRA_PASSWORD", "");
        String repo = env("GHIDRA_PROJECT", "P3");
        String name = env("GHIDRA_DELETE_NAME", "rpc_test_true");

        ClientUtil.setClientAuthenticator(new PasswordClientAuthenticator(user, pass));
        RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port, true);
        RepositoryAdapter r = server.getRepository(repo);
        r.connect();

        boolean found = false;
        for (RepositoryItem it : r.getItemList("/")) {
            if (it.getName().equals(name)) {
                found = true;
                for (ItemCheckoutStatus c : r.getCheckouts("/", name)) {
                    if (user.equals(c.getUser())) {
                        println("[Del] terminating checkout id=" + c.getCheckoutId() + " on /" + name);
                        r.terminateCheckout("/", name, c.getCheckoutId(), true);
                    }
                }
                r.deleteItem("/", name, -1); // -1 = all versions
                println("[Del] deleted /" + name);
            }
        }
        if (!found) {
            println("[Del] /" + name + " not found (already gone)");
        }
    }

    private String env(String k, String d) { String v = System.getenv(k); return (v == null || v.isEmpty()) ? d : v; }
}
