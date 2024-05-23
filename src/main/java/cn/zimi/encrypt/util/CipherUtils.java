package cn.zimi.encrypt.util;

import cn.hutool.core.codec.Base64Decoder;
import cn.hutool.crypto.KeyUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.digest.BCrypt;
import cn.hutool.crypto.digest.HMac;

import javax.crypto.SecretKey;
import java.util.Base64;

/**
 * @Description:
 * @Author: eason
 * @Date: 2024/5/23 10:12
 */
public class CipherUtils {

    private CipherUtils() {
    }

    /**
     * 生成一个随机密钥的HMac实例，并返回Base64编码的密钥字符串
     *
     * @return Base64编码的密钥字符串
     */
    public static String generateRandomHMac() {
        SecretKey secretKey = KeyUtil.generateKey("HmacSHA256");
        byte[] keyBytes = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    /**
     * 使用sha256hmac进行hash
     *
     * @param base64Str base64字符串
     * @param key       密钥
     * @return hash后的字符串，base64编码
     */
    public static String sha256hmacBase64(String base64Str, String key) {
        return generateHMac(key).digestBase64(Base64Decoder.decodeStr(base64Str), false);
    }

    /**
     * 使用sha256hmac进行hash
     *
     * @param str 明文
     * @param key 密钥
     * @return hash后的字符串，base64编码
     */
    public static String sha256hmac(String str, String key) {
        return generateHMac(key).digestBase64(str, false);
    }

    /**
     * 使用bcrypt进行hash
     *
     * @param str 明文
     * @return hash后的字符串
     */
    public static String bcrypt(String str) {
        return BCrypt.hashpw(str);
    }

    /**
     * 使用bcrypt进行hash
     *
     * @param base64Str base64字符串
     * @return hash后的字符串
     */
    public static String bcryptBase64(String base64Str) {
        return BCrypt.hashpw(Base64Decoder.decodeStr(base64Str));
    }

    /**
     * 使用sha256hmac进行密码验证
     *
     * @param str  明文
     * @param hash hash后的字符串
     * @return 是否匹配
     */
    public static boolean sha256hmacVerify(String str, String hash, String key) {
        String computedHash = sha256hmac(str, key);
        return computedHash.equals(hash);
    }

    /**
     * 使用sha256hmac进行密码验证
     *
     * @param base64Str base64字符串
     * @param hash      hash后的字符串
     * @return 是否匹配
     */
    public static boolean sha256hmacVerifyBase64(String base64Str, String hash, String key) {
        String computedHash = sha256hmacBase64(base64Str, key);
        return computedHash.equals(hash);
    }

    /**
     * 验证密码
     *
     * @param str  明文
     * @param hash hash后的字符串
     * @return 是否匹配
     */
    public static boolean bcryptVerify(String str, String hash) {
        return BCrypt.checkpw(str, hash);
    }

    /**
     * 验证密码
     *
     * @param base64Str base64字符串
     * @param hash      hash后的字符串
     * @return 是否匹配
     */
    public static boolean bcryptVerifyBase64(String base64Str, String hash) {
        return BCrypt.checkpw(Base64Decoder.decodeStr(base64Str), hash);
    }

    /**
     * 使用指定密钥生成HMac实例
     *
     * @param key 密钥字符串
     * @return HMac实例
     */
    private static HMac generateHMac(String key) {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        return SecureUtil.hmacSha256(keyBytes);
    }
}
