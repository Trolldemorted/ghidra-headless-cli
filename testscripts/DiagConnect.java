// DiagConnect.java - programmatic Ghidra Server connection diagnostic.
// Installs a PasswordClientAuthenticator from env vars and reports the real connect result.
//@category Examples.Headless
import ghidra.app.script.GhidraScript;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.PasswordClientAuthenticator;
import ghidra.framework.client.RepositoryServerAdapter;

public class DiagConnect extends GhidraScript {
    @Override
    public void run() throws Exception {
        String host = env("GHIDRA_HOST", "ghidra.stronk.pw");
        int port = Integer.parseInt(env("GHIDRA_PORT", "13100"));
        String user = env("GHIDRA_USER", "claude");
        String pass = env("GHIDRA_PASSWORD", "");
        println("[Diag] host=" + host + " port=" + port + " user=" + user + " passLen=" + pass.length());

        ClientUtil.setClientAuthenticator(new PasswordClientAuthenticator(user, pass));
        RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port, true);

        println("[Diag] isConnected=" + server.isConnected());
        Throwable err = server.getLastConnectError();
        println("[Diag] lastConnectError=" + (err == null ? "<none>" : err.toString()));
        if (server.isConnected()) {
            try { println("[Diag] anonymousAllowed=" + server.anonymousAccessAllowed()); } catch (Exception e) { println("[Diag] anon? " + e); }
            try {
                String[] repos = server.getRepositoryNames();
                println("[Diag] repositories(" + repos.length + "): " + String.join(", ", repos));
            } catch (Exception e) { println("[Diag] getRepositoryNames failed: " + e); }
        }
    }

    private String env(String k, String dflt) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? dflt : v;
    }
}
