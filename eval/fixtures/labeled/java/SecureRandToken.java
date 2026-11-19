import java.security.SecureRandom;

public class SecureRandToken {
    public String resetToken() {
        SecureRandom random = new SecureRandom();
        return Long.toHexString(random.nextLong());
    }
}
