import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;

public class SqliPrepared {
    public ResultSet find(Connection conn, HttpServletRequest request) throws Exception {
        PreparedStatement stmt = conn.prepareStatement("SELECT id, email FROM users WHERE name = ?");
        stmt.setString(1, request.getParameter("name"));
        return stmt.executeQuery();
    }
}
