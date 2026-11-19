import java.util.Random;

public class WeakRandToken {
    public String resetToken() {
        Random random = new Random();
        return Long.toHexString(random.nextLong());
    }
}
