package cn.zimi.encrypt.util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/**
 * @Description:
 * @Author: eason
 * @Date: 2024/5/23 9:43
 */
public class AESUtils {
    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";

    private static SecretKey decodeKey(String encodedKey) {
        byte[] keyBytes = hexStringToByteArray(encodedKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * 生成一个随机的AES密钥，并返回十六进制编码的字符串表示形式
     *
     * @return 十六进制编码的密钥
     * @throws NoSuchAlgorithmException 异常
     */
    public static String generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // 可以选择128, 192, 256位
        SecretKey secretKey = keyGen.generateKey();
        return bytesToHex(secretKey.getEncoded());
    }

    /**
     * 使用AES/ECB/PKCS5Padding对明文进行加密
     *
     * @param data 明文数据
     * @param key  密钥
     * @return 加密数据
     * @throws Exception 异常
     */
    public static String encrypt(String data, String key) throws Exception {
        SecretKey secretKey = decodeKey(key);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return bytesToHex(encryptedBytes);
    }

    /**
     * 使用AES/ECB/PKCS5Padding对密文进行解密
     *
     * @param data 加密数据
     * @param key  密钥
     * @return 明文数据
     * @throws Exception 异常
     */
    public static String decrypt(String data, String key) throws Exception {
        SecretKey secretKey = decodeKey(key);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(hexStringToByteArray(data));
        return new String(decryptedBytes);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
