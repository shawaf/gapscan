import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;

public class HostnameAll {
    public void install() {
        HostnameVerifier allowAll = (hostname, session) -> true;
        HttpsURLConnection.setDefaultHostnameVerifier(allowAll);
    }
}
