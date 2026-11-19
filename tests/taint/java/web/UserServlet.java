package web;

import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import javax.servlet.http.*;
import svc.*;

public class UserServlet extends HttpServlet {
    private Repo repo;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        repo.byName(name); // cross-file source -> Repo.java sql sink
        repo.byNameSafe(name);
        repo.byId(Integer.parseInt(request.getParameter("id"))); // SAFE-FLOW
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String cmd = request.getHeader("X-Cmd");
        repo.run(Util.clean(cmd)); // cross-file: trim does not sanitize
        repo.run("ls -l");
        repo.run(Util.constant());
    }

    void files(HttpServletRequest request) throws Exception {
        String f = request.getParameter("file");
        File a = new File("/var/data/" + f); // VULN:path
        File b = new File("/var/data/" + Util.sanitize(f)); // SAFE
        FileInputStream in = new FileInputStream(a); // VULN:path
        File c = new File("/var/data/fixed.txt"); // SAFE
    }

    void echo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String q = request.getParameter("q");
        response.getWriter().println(q); // VULN:xss
        response.getWriter().println(Util.wrap(q)); // VULN:xss
        response.getWriter().println(org.apache.commons.lang.StringEscapeUtils.escapeHtml(q)); // SAFE
        response.getWriter().println("hello"); // SAFE
    }

    void fetch(HttpServletRequest request) throws Exception {
        String u = request.getParameter("url");
        URL url = new URL(u); // VULN:ssrf
        URL ok = new URL("https://example.com/api"); // SAFE
    }

    void redirect(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendRedirect(request.getParameter("next")); // VULN:redirect
        response.sendRedirect("/home"); // SAFE
    }

    void viaField(HttpServletRequest request) throws Exception {
        Holder h = new Holder(request.getParameter("v"));
        repo.byName(h.get());
    }

    void viaCollection(HttpServletRequest request) throws Exception {
        List<String> xs = new ArrayList<>();
        xs.add(request.getParameter("a"));
        repo.byName(Util.firstOf(xs));
        List<String> ys = new ArrayList<>();
        ys.add("constant");
        repo.byNameSafe(Util.firstOf(ys));
    }

    void overwritten(HttpServletRequest request) throws Exception {
        String p = request.getParameter("p"); // SAFE-FLOW
        p = "constant";
        repo.run(p);
    }

    void loop(HttpServletRequest request) throws Exception {
        String[] vals = request.getParameterValues("v");
        for (String v : vals) {
            repo.run(v);
        }
    }

    void xpath(HttpServletRequest request) throws Exception {
        javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
        String expr = "//user[name='" + request.getParameter("n") + "']";
        xp.evaluate(expr, new Object()); // VULN:xpath
    }
}
