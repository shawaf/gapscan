package svc;

import java.sql.*;

public class Repo {
    private final Connection conn;
    public Repo(Connection c) { this.conn = c; }

    public ResultSet byName(String name) throws Exception {
        Statement st = conn.createStatement();
        String q = "SELECT * FROM users WHERE name = '" + name + "'";
        return st.executeQuery(q); // VULN:sql
    }

    public ResultSet byId(int id) throws Exception {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE id = " + id); // SAFE
    }

    public ResultSet byNameSafe(String name) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?"); // SAFE
        ps.setString(1, name);
        return ps.executeQuery(); // SAFE
    }

    public void run(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd); // VULN:cmd
    }
}
