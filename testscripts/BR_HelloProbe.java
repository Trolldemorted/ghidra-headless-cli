// BR_HelloProbe.java - minimal "does the URL+auth work at all" probe.
// Just connects to the repo via ClientUtil and prints status. Used to
// isolate whether the URL parser / auth is the failure point, separate
// from any actual program-open logic.
//
// Run with:
//   GHIDRA_PROJECT='Battle%20Realms' GHIDRA_READONLY=1 \
//   /workdir/ghidra-rpc-server/ghidra-headless.sh
//@category Examples.Headless

import ghidra.app.script.GhidraScript;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.PasswordClientAuthenticator;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;

public class BR_HelloProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        String host = env("BR_HOST", "ghidra.stronk.pw");
        int port = Integer.parseInt(env("BR_PORT", "13100"));
        String user = env("BR_USER", "claude");
        String pass = env("BR_PASSWORD", "");
        String repoName = env("BR_PROJECT", "Battle Realms");

        println("[HELLO] script is alive; connecting to " + host + ":" + port);
        ClientUtil.setClientAuthenticator(new PasswordClientAuthenticator(user, pass));
        RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port, true);
        println("[HELLO] serverConnected=" + server.isConnected());
        println("[HELLO] repos=" + String.join(",", server.getRepositoryNames()));
        RepositoryAdapter repo = server.getRepository(repoName);
        repo.connect();
        println("[HELLO] repoConnected=" + repo.isConnected() +
                " name=" + repo.getName());
        println("[HELLO] user=" + repo.getUser().getName() +
                " write=" + repo.getUser().hasWritePermission() +
                " readOnly=" + repo.getUser().isReadOnly());
        println("[HELLO] items in / =" + repo.getItemList("/").length);
    }

    private String env(String k, String d) { String v = System.getenv(k); return (v == null || v.isEmpty()) ? d : v; }
}
