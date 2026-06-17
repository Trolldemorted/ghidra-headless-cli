// DiagConnect2.java - verbose auth-callback diagnostic.
// Logs every callback the server requests so we can tell a bad password from a
// "must change password" (expired) first-login flow.
//@category Examples.Headless
import ghidra.app.script.GhidraScript;
import ghidra.framework.client.ClientAuthenticator;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.remote.AnonymousCallback;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import java.awt.Component;
import java.net.Authenticator;

public class DiagConnect2 extends GhidraScript {
    static String USER, PASS;

    @Override
    public void run() throws Exception {
        String host = env("GHIDRA_HOST", "ghidra.stronk.pw");
        int port = Integer.parseInt(env("GHIDRA_PORT", "13100"));
        USER = env("GHIDRA_USER", "claude");
        PASS = env("GHIDRA_PASSWORD", "");
        println("[Diag2] connecting host=" + host + " user=" + USER + " passLen=" + PASS.length());
        ClientUtil.setClientAuthenticator(new Logging());
        RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port, true);
        println("[Diag2] isConnected=" + server.isConnected());
        Throwable err = server.getLastConnectError();
        println("[Diag2] lastConnectError=" + (err == null ? "<none>" : err.toString()));
    }

    private String env(String k, String d) { String v = System.getenv(k); return (v == null || v.isEmpty()) ? d : v; }

    class Logging implements ClientAuthenticator {
        public Authenticator getAuthenticator() { return null; }
        public boolean isSSHKeyAvailable() { return false; }
        public boolean processSSHSignatureCallbacks(String a, NameCallback b, ghidra.framework.remote.SSHSignatureCallback c) { return false; }
        public boolean promptForReconnect(Component a, String b) { return false; }
        public char[] getKeyStorePassword(String a, boolean b) { return null; }
        public char[] getNewPassword(Component a, String serverInfo, String user) {
            println("[Diag2] !!! getNewPassword CALLED (server requires password change) serverInfo=" + serverInfo + " user=" + user);
            return PASS.toCharArray();
        }
        public boolean processPasswordCallbacks(String title, String serverType, String serverName,
                boolean anonymousAllowed, NameCallback nameCb, PasswordCallback passCb,
                ChoiceCallback choiceCb, AnonymousCallback anonCb, String loginError) {
            println("[Diag2] processPasswordCallbacks: title=" + title + " serverType=" + serverType
                    + " serverName=" + serverName + " anonAllowed=" + anonymousAllowed
                    + " nameCb=" + (nameCb != null) + " passCb=" + (passCb != null)
                    + " choiceCb=" + (choiceCb != null) + " anonCb=" + (anonCb != null)
                    + " loginError=" + loginError);
            if (nameCb != null) nameCb.setName(USER);
            if (passCb != null) passCb.setPassword(PASS.toCharArray());
            return true;
        }
    }
}
