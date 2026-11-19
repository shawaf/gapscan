import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CryptoDes {
    public byte[] encrypt(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
        return cipher.doFinal(data);
    }
}
