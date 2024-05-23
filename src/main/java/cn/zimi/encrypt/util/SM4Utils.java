package cn.zimi.encrypt.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

/**
 * @Description:
 * @Author: eason
 * @Date: 2024/5/23 9:38
 */
public class SM4Utils {
    private static final String ALGORITHM = "SM4/CBC/PKCS7Padding";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成随机SM4密钥
     *
     * @return 密钥
     */
    public static String generateRandomKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("SM4");
            keyGen.init(128, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("【SM4】生成随机密钥失败", e);
        }
    }


    /**
     * 使用SM4/CBC/PKCS7Padding对明文进行加密
     *
     * @param data 明文数据
     * @param key  密钥
     * @return 加密数据
     */
    public static String encrypt(String data, String key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec secretKey = getSecretKey(generateKey(key));

            // 生成随机 IV
            byte[] iv = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

            // 将 IV 和加密数据一起编码成 Base64 字符串
            byte[] combined = new byte[iv.length + encryptedData.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encryptedData, 0, combined, iv.length, encryptedData.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new RuntimeException("【SM4】加密错误", e);
        }
    }

    /**
     * 使用SM4/CBC/PKCS7Padding对密文进行解密
     *
     * @param data 加密数据
     * @param key  密钥
     * @return 明文数据
     */
    public static String decrypt(String data, String key) {
        try {
            byte[] combined = Base64.getDecoder().decode(data);
            byte[] iv = Arrays.copyOfRange(combined, 0, 16);
            byte[] encryptedData = Arrays.copyOfRange(combined, 16, combined.length);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec secretKey = getSecretKey(generateKey(key));
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] decryptedData = cipher.doFinal(encryptedData);

            return new String(decryptedData, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("【SM4】解密错误", e);
        }
    }

    private static byte[] generateKey(final String key) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            byte[] keyBuf = sha.digest(key.getBytes(StandardCharsets.UTF_8));
            return Arrays.copyOfRange(keyBuf, 0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("【SM4】生成密钥失败", e);
        }
    }

    private static SecretKeySpec getSecretKey(byte[] key) {
        return new SecretKeySpec(key, "SM4");
    }

}
