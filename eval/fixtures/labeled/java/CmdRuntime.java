import javax.servlet.http.HttpServletRequest;

public class CmdRuntime {
    public Process lookup(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        return Runtime.getRuntime().exec("nslookup " + host);
    }
}
