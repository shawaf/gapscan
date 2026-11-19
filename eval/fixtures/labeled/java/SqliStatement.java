import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqliStatement {
    public ResultSet find(Connection conn, HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT id, email FROM users WHERE name = '" + name + "'");
    }
}
