import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

public class HttpsDefault {
    public int status(String host) throws Exception {
        URL url = new URL("https://" + host + "/health");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        return conn.getResponseCode();
    }
}
