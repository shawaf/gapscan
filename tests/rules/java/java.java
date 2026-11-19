import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import java.util.zip.*;
import javax.crypto.Cipher;
import javax.net.ssl.*;
import javax.servlet.http.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.*;

public class Cases {

    // --- sqli-string-built ---------------------------------------------------------------------------
    void sqlCases(Connection c, Statement st, String name, int id) throws Exception {
        // ruleid: gapscan.java.sqli-string-built
        st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        // ruleid: gapscan.java.sqli-string-built
        st.executeUpdate(String.format("DELETE FROM t WHERE id = %d", id));
        // ruleid: gapscan.java.sqli-string-built
        c.prepareStatement("SELECT * FROM users WHERE name = '" + name + "'");
        // ok: gapscan.java.sqli-string-built
        PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE name = ?");
        // ok: gapscan.java.sqli-string-built
        st.executeQuery("SELECT * FROM users " + "WHERE active = 1");
    }

    // --- command-injection -----------------------------------------------------------------------------
    void commandCases(String host) throws Exception {
        // ruleid: gapscan.java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
        // ruleid: gapscan.java.command-injection
        new ProcessBuilder("sh", "-c", "ping " + host);
        // ok: gapscan.java.command-injection
        Runtime.getRuntime().exec("uptime");
        // ok: gapscan.java.command-injection
        new ProcessBuilder("ping", "-c", "1", host);
    }

    // --- weak-hash --------------------------------------------------------------------------------------
    void hashCases() throws Exception {
        // ruleid: gapscan.java.weak-hash
        MessageDigest.getInstance("MD5");
        // ruleid: gapscan.java.weak-hash
        MessageDigest.getInstance("SHA-1");
        // ok: gapscan.java.weak-hash
        MessageDigest.getInstance("SHA-256");
    }

    // --- weak-cipher ---------------------------------------------------------------------------------------
    void cipherCases() throws Exception {
        // ruleid: gapscan.java.weak-cipher
        Cipher.getInstance("DES/CBC/PKCS5Padding");
        // ruleid: gapscan.java.weak-cipher
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ruleid: gapscan.java.weak-cipher
        Cipher.getInstance("AES");
        // ok: gapscan.java.weak-cipher
        Cipher.getInstance("AES/GCM/NoPadding");
        // ok: gapscan.java.weak-cipher
        Cipher.getInstance("AES/GCM/NOPADDING");
        // ok: gapscan.java.weak-cipher
        Cipher.getInstance("aes/cbc/pkcs5padding");
    }

    // --- tls-verification-disabled ----------------------------------------------------------------------------
    class TrustAll implements X509TrustManager {
        // ruleid: gapscan.java.tls-verification-disabled
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}

        // ruleid: gapscan.java.tls-verification-disabled
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}

        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
    }

    class Strict implements X509TrustManager {
        // ok: gapscan.java.tls-verification-disabled
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            validate(chain);
        }

        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            validate(chain);
        }

        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }

        void validate(java.security.cert.X509Certificate[] chain) {}
    }

    void tlsCases() throws Exception {
        // ruleid: gapscan.java.tls-verification-disabled
        HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
        // ruleid: gapscan.java.tls-verification-disabled
        SSLContext.getInstance("TLSv1");
        // ok: gapscan.java.tls-verification-disabled
        SSLContext.getInstance("TLSv1.3");
    }

    // --- xxe-parser-not-hardened ---------------------------------------------------------------------------------
    void xxeCases() throws Exception {
        // ruleid: gapscan.java.xxe-parser-not-hardened
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder();
    }

    void xxeSafe() throws Exception {
        // ok: gapscan.java.xxe-parser-not-hardened
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.newDocumentBuilder();
    }

    // --- unsafe-deserialization ------------------------------------------------------------------------------------
    void deserializeCases(InputStream in) throws Exception {
        // ruleid: gapscan.java.unsafe-deserialization
        ObjectInputStream ois = new ObjectInputStream(in);
        Object o = ois.readObject();
    }

    // --- hardcoded-secret ------------------------------------------------------------------------------------------
    // ruleid: gapscan.java.hardcoded-secret
    private static final String PASSWORD = "hunter2hunter2";
    // ruleid: gapscan.java.hardcoded-secret
    String apiKey = "sk_live_51HxxxxxxxxxxxxxxxxYYY";
    // ok: gapscan.java.hardcoded-secret
    String password2 = System.getenv("DB_PASSWORD");
    // ok: gapscan.java.hardcoded-secret
    String token = "";
    // ok: gapscan.java.hardcoded-secret
    String secret = "changeme";
    // ok: gapscan.java.hardcoded-secret
    String PASSWORD_FIELD = "password";

    // --- insecure-random-token -----------------------------------------------------------------------------------------
    void randomCases() {
        // ruleid: gapscan.java.insecure-random-token, gapscan.java.weak-random-generator
        int resetToken = new Random().nextInt();
        // ruleid: gapscan.java.insecure-random-token, gapscan.java.weak-random-generator
        double otp = Math.random();
        // ok: gapscan.java.insecure-random-token
        // ruleid: gapscan.java.weak-random-generator
        int roll = new Random().nextInt(6);
    }

    // --- csrf-protection-off ---------------------------------------------------------------------------------------------
    void csrfCases(HttpSecurity http) throws Exception {
        // ruleid: gapscan.java.csrf-protection-off
        http.csrf().disable();
        // ok: gapscan.java.csrf-protection-off
        http.csrf().csrfTokenRepository(repo());
    }

    // --- cookie-flags-off -----------------------------------------------------------------------------------------------------
    void cookieCases(Cookie c) {
        // ruleid: gapscan.java.cookie-flags-off
        c.setSecure(false);
        // ruleid: gapscan.java.cookie-flags-off
        c.setHttpOnly(false);
        // ok: gapscan.java.cookie-flags-off
        c.setSecure(true);
        // ok: gapscan.java.cookie-flags-off
        c.setHttpOnly(true);
    }

    // --- cors-allow-all -----------------------------------------------------------------------------------------------------------
    void corsCases(HttpServletResponse res, CorsRegistry reg) {
        // ruleid: gapscan.java.cors-allow-all
        res.setHeader("Access-Control-Allow-Origin", "*");
        // ruleid: gapscan.java.cors-allow-all
        reg.addMapping("/**").allowedOrigins("*");
        // ok: gapscan.java.cors-allow-all
        reg.addMapping("/**").allowedOrigins("https://app.example.com");
    }

    // --- zip-slip -------------------------------------------------------------------------------------------------------------------
    void zipCases(ZipInputStream zis, File dest) throws Exception {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            // ruleid: gapscan.java.zip-slip
            File out = new File(dest, entry.getName());
            out.createNewFile();
        }
    }

    void zipSafe(ZipInputStream zis, File dest) throws Exception {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            // ok: gapscan.java.zip-slip
            File out = new File(dest, entry.getName());
            if (!out.getCanonicalPath().startsWith(dest.getCanonicalPath())) {
                throw new SecurityException("bad entry");
            }
            out.createNewFile();
        }
    }

    // =================== taint rules =========================================================================================
    void taintSql(HttpServletRequest req, Statement st) throws Exception {
        String id = req.getParameter("id");
        String q = "SELECT * FROM users WHERE id = " + id;
        // ruleid: gapscan.java.taint-sqli
        st.executeQuery(q);
        int safe = Integer.parseInt(req.getParameter("id"));
        String q2 = "SELECT * FROM users WHERE id = " + safe;
        // ok: gapscan.java.taint-sqli
        st.executeQuery(q2);
    }

    String taintSpring(@RequestParam("id") String id, Statement st) throws Exception {
        String q = "SELECT * FROM users WHERE id = " + id;
        // ruleid: gapscan.java.taint-sqli
        st.executeQuery(q);
        return "ok";
    }

    void taintCommand(HttpServletRequest req) throws Exception {
        String cmd = "ping -c 1 " + req.getParameter("host");
        // ruleid: gapscan.java.command-injection, gapscan.java.taint-command-injection
        Runtime.getRuntime().exec(cmd);
    }

    void taintPath(HttpServletRequest req) throws Exception {
        String name = req.getParameter("file");
        // ruleid: gapscan.java.taint-path-traversal
        new FileInputStream("/srv/files/" + name);
    }

    void taintPathSafe(HttpServletRequest req) throws Exception {
        String name = FilenameUtils.getName(req.getParameter("file"));
        // ok: gapscan.java.taint-path-traversal
        new FileInputStream("/srv/files/" + name);
    }

    void taintSsrf(HttpServletRequest req) throws Exception {
        String target = req.getParameter("url");
        // ruleid: gapscan.java.taint-ssrf
        new URL(target).openConnection();
        // ok: gapscan.java.taint-ssrf
        new URL("https://api.example.com/status").openConnection();
    }

    void taintRedirect(HttpServletRequest req, HttpServletResponse res) throws Exception {
        String next = req.getParameter("next");
        // ruleid: gapscan.java.taint-open-redirect
        res.sendRedirect(next);
        // ok: gapscan.java.taint-open-redirect
        res.sendRedirect("/home");
    }

    void taintXss(HttpServletRequest req, HttpServletResponse res) throws Exception {
        String name = req.getParameter("name");
        // ruleid: gapscan.java.taint-xss
        res.getWriter().println("<h1>Hello " + name + "</h1>");
        // ok: gapscan.java.taint-xss
        res.getWriter().println("<h1>Hello " + HtmlUtils.htmlEscape(name) + "</h1>");
    }

    void taintExpression(HttpServletRequest req, ExpressionParser parser) throws Exception {
        String expr = req.getParameter("expr");
        // ruleid: gapscan.java.taint-expression-injection
        parser.parseExpression(expr);
    }

    // --- fully qualified names (no import) must match too ------------------------------------------------------------
    void qualifiedCases() throws Exception {
        // ruleid: gapscan.java.weak-cipher
        javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
        // ruleid: gapscan.java.weak-hash
        java.security.MessageDigest.getInstance("MD5");
        // ok: gapscan.java.weak-hash
        java.security.MessageDigest.getInstance("SHA-512");
    }

    // --- round 1 additions ---------------------------------------------------------------------------------------------
    void hashProviderCases() throws Exception {
        // ruleid: gapscan.java.weak-hash
        java.security.MessageDigest.getInstance("SHA1", "SUN");
        // ruleid: gapscan.java.weak-hash
        java.security.MessageDigest.getInstance("md5");
        // ok: gapscan.java.weak-hash
        java.security.MessageDigest.getInstance("SHA-256", "SUN");
    }

    void keyCases(byte[] k) throws Exception {
        // ruleid: gapscan.java.weak-cipher
        javax.crypto.KeyGenerator.getInstance("DES");
        // ruleid: gapscan.java.weak-cipher
        new javax.crypto.spec.SecretKeySpec(k, "DESede");
        // ok: gapscan.java.weak-cipher
        javax.crypto.KeyGenerator.getInstance("AES");
        // ok: gapscan.java.weak-cipher
        new javax.crypto.spec.SecretKeySpec(k, "AES");
    }

    void randomGeneratorCases() {
        // ruleid: gapscan.java.weak-random-generator
        double qualified = java.lang.Math.random();
        // ruleid: gapscan.java.weak-random-generator
        Random r = new Random();
        // ruleid: gapscan.java.weak-random-generator
        double d = Math.random();
        // ok: gapscan.java.weak-random-generator
        SecureRandom sr = new SecureRandom();
    }

    void ldapCases(javax.naming.directory.DirContext ctx, String user) throws Exception {
        // ruleid: gapscan.java.ldap-filter-string-built
        ctx.search("ou=people", "(uid=" + user + ")", null);
        // ok: gapscan.java.ldap-filter-string-built
        ctx.search("ou=people", "(uid={0})", new Object[] {user}, null);
    }

    void xpathCases(javax.xml.xpath.XPath xp, String name) throws Exception {
        // ruleid: gapscan.java.xpath-string-built
        xp.evaluate("//user[@name='" + name + "']", doc);
        // ok: gapscan.java.xpath-string-built
        xp.evaluate("//user[@name=$name]", doc);
    }

    void taintLdap(HttpServletRequest req, javax.naming.directory.DirContext ctx) throws Exception {
        String f = "(uid=" + req.getParameter("u") + ")";
        // ruleid: gapscan.java.taint-ldap-injection
        ctx.search("ou=people", f, null);
        // ok: gapscan.java.taint-ldap-injection
        ctx.search("ou=people", "(uid=admin)", null);
    }

    void taintXpath(HttpServletRequest req, javax.xml.xpath.XPath xp) throws Exception {
        String e = "//user[@name='" + req.getParameter("n") + "']";
        // ruleid: gapscan.java.taint-xpath-injection
        xp.evaluate(e, doc);
        // ok: gapscan.java.taint-xpath-injection
        xp.evaluate("//user", doc);
    }

    void taintTrust(HttpServletRequest req) throws Exception {
        String key = req.getParameter("k");
        // ruleid: gapscan.java.taint-trust-boundary
        req.getSession().setAttribute(key, "value");
        // ok: gapscan.java.taint-trust-boundary
        req.getSession().setAttribute("userid", "fixed");
    }

    void taintCookie(HttpServletRequest req, Statement st) throws Exception {
        Cookie[] cookies = req.getCookies();
        String v = cookies[0].getValue();
        String q = "SELECT * FROM t WHERE c = '" + v + "'";
        // ruleid: gapscan.java.taint-sqli
        st.executeQuery(q);
    }

    void taintEnvironment(HttpServletRequest req) throws Exception {
        String[] args = {"/bin/ls"};
        String[] env = {req.getHeader("X-Path")};
        Runtime r = Runtime.getRuntime();
        // ruleid: gapscan.java.taint-command-injection
        r.exec(args, env);
    }
}
