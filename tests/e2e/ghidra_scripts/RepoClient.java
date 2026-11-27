// RepoClient.java - the "second client" of the shared-repository e2e tests.
//
// An independent Ghidra client, logged in to the test Ghidra Server as a
// different user than the RPC server, used to (a) set the test repository up
// and (b) read server-side truth: version histories, checkouts and program
// content as stored in the repository. It also acts as "another user" that
// terminates the RPC server's checkouts or checks in its own versions.
//
// It runs as a -preScript of analyzeHeadless on a throwaway LOCAL project and
// talks to the Ghidra Server only through the client API (ClientUtil /
// RepositoryAdapter for repository-level calls, a ghidra:// URL query for
// program content), so it shares nothing with the RPC server under test.
//
// Protocol: one JSON request line per TCP connection on 127.0.0.1, one JSON
// reply line ({"success":true,...} or {"success":false,"error":...}).
//
// Environment:
//   E2E_GHIDRA_HOST / E2E_GHIDRA_PORT   Ghidra Server
//   E2E_CLIENT_USER / E2E_CLIENT_PASSWORD  login
//   E2E_CLIENT_PORT                     port to listen on
//
//@category E2E
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.PasswordClientAuthenticator;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.protocol.ghidra.GhidraURLQuery;
import ghidra.framework.protocol.ghidra.GhidraURLResultHandlerAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.remote.User;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class RepoClient extends GhidraScript {

    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private String host;
    private int port;

    @Override
    public void run() throws Exception {
        host = env("E2E_GHIDRA_HOST");
        port = Integer.parseInt(env("E2E_GHIDRA_PORT"));
        String user = env("E2E_CLIENT_USER");
        ClientUtil.setClientAuthenticator(
            new PasswordClientAuthenticator(user, env("E2E_CLIENT_PASSWORD")));
        int listen = Integer.parseInt(env("E2E_CLIENT_PORT"));
        try (ServerSocket ss = new ServerSocket()) {
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress("127.0.0.1", listen));
            Msg.info(this, "RepoClient ready on 127.0.0.1:" + listen + " as " + user);
            while (true) {
                try (Socket s = ss.accept()) {
                    BufferedReader in = new BufferedReader(
                        new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                    String line = in.readLine();
                    if (line == null) {
                        continue;
                    }
                    JsonObject req = JsonParser.parseString(line).getAsJsonObject();
                    String op = req.get("op").getAsString();
                    JsonObject reply;
                    try {
                        reply = handle(op, req);
                        reply.addProperty("success", true);
                    } catch (Throwable t) {
                        Msg.error(this, "RepoClient " + op + " failed", t);
                        reply = new JsonObject();
                        reply.addProperty("success", false);
                        reply.addProperty("error", t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                    OutputStream out = s.getOutputStream();
                    out.write((gson.toJson(reply) + "\n").getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    if ("quit".equals(op)) {
                        return;
                    }
                } catch (IOException e) {
                    Msg.warn(this, "RepoClient connection error: " + e.getMessage());
                }
            }
        }
    }

    private JsonObject handle(String op, JsonObject req) throws Exception {
        switch (op) {
            case "ping":
            case "quit":
                return new JsonObject();
            case "createRepo":
                return createRepo(str(req, "repo"));
            case "setAccess":
                return setAccess(req);
            case "getAccess":
                return getAccess(str(req, "repo"));
            case "items":
                return items(str(req, "repo"));
            case "versions":
                return versions(str(req, "repo"), str(req, "path"));
            case "checkouts":
                return checkouts(str(req, "repo"), str(req, "path"));
            case "terminate":
                return terminate(req);
            case "deleteItem":
                return deleteItem(str(req, "repo"), str(req, "path"));
            case "read":
                return read(req);
            case "editLabel":
                return editLabel(req);
            default:
                throw new IllegalArgumentException("unknown op " + op);
        }
    }

    // ---- repository-level calls ------------------------------------------------

    private RepositoryServerAdapter server() throws IOException {
        // forceConnect=true re-establishes the shared adapter after a Ghidra
        // Server restart; ClientUtil caches one adapter per host:port.
        RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port, true);
        if (!server.isConnected()) {
            server.connect();
        }
        if (!server.isConnected()) {
            throw new IOException("not connected to " + host + ":" + port);
        }
        return server;
    }

    private RepositoryAdapter repo(String name) throws IOException {
        RepositoryAdapter repo = server().getRepository(name);
        if (repo == null) {
            throw new IOException("no repository " + name);
        }
        if (!repo.isConnected()) {
            repo.connect();
        }
        return repo;
    }

    private JsonObject createRepo(String name) throws Exception {
        RepositoryServerAdapter server = server();
        boolean created = false;
        if (!Arrays.asList(server.getRepositoryNames()).contains(name)) {
            server.createRepository(name);
            created = true;
        }
        JsonObject o = new JsonObject();
        o.addProperty("created", created);
        return o;
    }

    private JsonObject setAccess(JsonObject req) throws IOException {
        List<User> users = new ArrayList<>();
        for (Map.Entry<String, JsonElement> e : req.getAsJsonObject("users").entrySet()) {
            String perm = e.getValue().getAsString();
            int type = "ADMIN".equals(perm) ? User.ADMIN
                : "WRITE".equals(perm) ? User.WRITE : User.READ_ONLY;
            users.add(new User(e.getKey(), type));
        }
        repo(str(req, "repo")).setUserList(users.toArray(new User[0]), false);
        return getAccess(str(req, "repo"));
    }

    private JsonObject getAccess(String repoName) throws IOException {
        JsonObject users = new JsonObject();
        for (User u : repo(repoName).getUserList()) {
            int t = u.getPermissionType();
            users.addProperty(u.getName(), t == User.ADMIN ? "ADMIN" : t == User.WRITE ? "WRITE" : "READ_ONLY");
        }
        JsonObject o = new JsonObject();
        o.add("users", users);
        return o;
    }

    private JsonObject items(String repoName) throws IOException {
        RepositoryAdapter repo = repo(repoName);
        JsonArray files = new JsonArray();
        ArrayDeque<String> todo = new ArrayDeque<>();
        todo.push("/");
        while (!todo.isEmpty()) {
            String folder = todo.pop();
            for (String sub : repo.getSubfolderList(folder)) {
                todo.push(join(folder, sub));
            }
            for (RepositoryItem item : repo.getItemList(folder)) {
                JsonObject f = new JsonObject();
                f.addProperty("path", join(folder, item.getName()));
                f.addProperty("version", item.getVersion());
                files.add(f);
            }
        }
        JsonObject o = new JsonObject();
        o.add("files", files);
        return o;
    }

    private JsonObject versions(String repoName, String path) throws IOException {
        RepositoryAdapter repo = repo(repoName);
        JsonObject o = new JsonObject();
        RepositoryItem item = repo.getItem(parent(path), leaf(path));
        o.addProperty("exists", item != null);
        JsonArray list = new JsonArray();
        if (item != null) {
            for (Version v : repo.getVersions(parent(path), leaf(path))) {
                JsonObject j = new JsonObject();
                j.addProperty("version", v.getVersion());
                j.addProperty("user", v.getUser());
                j.addProperty("comment", v.getComment());
                list.add(j);
            }
        }
        o.add("versions", list);
        return o;
    }

    private JsonObject checkouts(String repoName, String path) throws IOException {
        RepositoryAdapter repo = repo(repoName);
        JsonArray list = new JsonArray();
        if (repo.getItem(parent(path), leaf(path)) != null) {
            for (ItemCheckoutStatus c : repo.getCheckouts(parent(path), leaf(path))) {
                JsonObject j = new JsonObject();
                j.addProperty("id", c.getCheckoutId());
                j.addProperty("user", c.getUser());
                j.addProperty("version", c.getCheckoutVersion());
                j.addProperty("type", String.valueOf(c.getCheckoutType()));
                j.addProperty("project", c.getProjectPath());
                list.add(j);
            }
        }
        JsonObject o = new JsonObject();
        o.add("checkouts", list);
        return o;
    }

    private JsonObject terminate(JsonObject req) throws IOException {
        String path = str(req, "path");
        String onlyUser = req.has("user") ? req.get("user").getAsString() : null;
        RepositoryAdapter repo = repo(str(req, "repo"));
        int n = 0;
        for (ItemCheckoutStatus c : repo.getCheckouts(parent(path), leaf(path))) {
            if (onlyUser == null || onlyUser.equals(c.getUser())) {
                repo.terminateCheckout(parent(path), leaf(path), c.getCheckoutId(), true);
                n++;
            }
        }
        JsonObject o = new JsonObject();
        o.addProperty("terminated", n);
        return o;
    }

    /** Delete a file with all its versions (this client's user must be allowed to). */
    private JsonObject deleteItem(String repoName, String path) throws IOException {
        RepositoryAdapter repo = repo(repoName);
        repo.deleteItem(parent(path), leaf(path), -1);
        JsonObject o = new JsonObject();
        o.addProperty("exists", repo.getItem(parent(path), leaf(path)) != null);
        return o;
    }

    // ---- program content (through a transient project for the repository) ------

    private interface FileWork {
        void run(DomainFile df) throws Exception;
    }

    private void withFile(String repoName, String path, boolean readOnly, FileWork work)
            throws Exception {
        URL url = GhidraURL.getFolderURL(GhidraURL.makeURL(host, port, repoName, parent(path)));
        Exception[] failure = {null};
        boolean[] ran = {false};
        GhidraURLQuery.queryRepositoryUrl(url, readOnly, new GhidraURLResultHandlerAdapter(true) {
            @Override
            public void processResult(DomainFolder folder, URL u, TaskMonitor m) {
                ran[0] = true;
                try {
                    DomainFile df = folder.getFile(leaf(path));
                    if (df == null) {
                        throw new IllegalArgumentException("no file " + path + " in repository");
                    }
                    work.run(df);
                } catch (Exception e) {
                    failure[0] = e;
                }
            }
        }, GhidraURLQuery.LinkFileControl.NO_FOLLOW, monitor);
        if (failure[0] != null) {
            throw failure[0];
        }
        if (!ran[0]) {
            throw new IOException("repository folder query did not run for " + url);
        }
    }

    private JsonObject read(JsonObject req) throws Exception {
        int version = req.has("version") ? req.get("version").getAsInt() : DomainFile.DEFAULT_VERSION;
        JsonObject o = new JsonObject();
        withFile(str(req, "repo"), str(req, "path"), true, df -> {
            Program p = (Program) df.getReadOnlyDomainObject(this, version, monitor);
            try {
                o.addProperty("version", version == DomainFile.DEFAULT_VERSION
                    ? df.getLatestVersion() : version);
                if (req.has("address")) {
                    Address a = p.getAddressFactory().getAddress(str(req, "address"));
                    JsonArray labels = new JsonArray();
                    for (Symbol sym : p.getSymbolTable().getSymbols(a)) {
                        labels.add(sym.getName());
                    }
                    o.add("labels", labels);
                    o.addProperty("eol", p.getListing().getComment(CommentType.EOL, a));
                    o.addProperty("pre", p.getListing().getComment(CommentType.PRE, a));
                    o.addProperty("plate", p.getListing().getComment(CommentType.PLATE, a));
                }
                if (req.has("dataTypes")) {
                    JsonObject types = new JsonObject();
                    for (JsonElement e : req.getAsJsonArray("dataTypes")) {
                        String t = e.getAsString();
                        types.addProperty(t, p.getDataTypeManager().getDataType(t) != null);
                    }
                    o.add("dataTypes", types);
                }
            } finally {
                p.release(this);
            }
        });
        return o;
    }

    /** Check out as this client's user, add a label, check in (not kept checked out). */
    private JsonObject editLabel(JsonObject req) throws Exception {
        JsonObject o = new JsonObject();
        String comment = req.has("comment") ? str(req, "comment") : "RepoClient edit";
        withFile(str(req, "repo"), str(req, "path"), false, df -> {
            if (!df.checkout(true, monitor)) {
                throw new IOException("exclusive checkout of " + df.getPathname()
                    + " refused (checked out elsewhere)");
            }
            Program p = (Program) df.getDomainObject(this, true, false, monitor);
            try {
                int tx = p.startTransaction("RepoClient label");
                boolean ok = false;
                try {
                    Address a = p.getAddressFactory().getAddress(str(req, "address"));
                    p.getSymbolTable().createLabel(a, str(req, "label"), SourceType.USER_DEFINED);
                    ok = true;
                } finally {
                    p.endTransaction(tx, ok);
                }
                p.save(comment, monitor);
            } finally {
                p.release(this);
            }
            df.checkin(new DefaultCheckinHandler(comment, false, false), monitor);
            o.addProperty("version", df.getLatestVersion());
        });
        return o;
    }

    // ---- helpers -----------------------------------------------------------------

    private static String parent(String path) {
        int slash = path.lastIndexOf('/');
        return slash <= 0 ? "/" : path.substring(0, slash);
    }

    private static String leaf(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }

    private static String join(String folder, String name) {
        return folder.equals("/") ? "/" + name : folder + "/" + name;
    }

    private static String str(JsonObject req, String key) {
        if (!req.has(key) || req.get(key).isJsonNull()) {
            throw new IllegalArgumentException("missing '" + key + "'");
        }
        return req.get(key).getAsString();
    }

    private static String env(String key) {
        String v = System.getenv(key);
        if (v == null || v.isEmpty()) {
            throw new IllegalStateException("environment variable " + key + " is not set");
        }
        return v;
    }
}
