import cn.zimi.encrypt.util.AESUtils;

import java.security.NoSuchAlgorithmException;

/**
 * @Description:
 * @Author: eason
 * @Date: 2024/5/23 10:18
 */
public class AESTest {

    public static void main(String[] args) {
        String key;
        try {
            key = AESUtils.generateKey();
            System.out.println("密钥: " + key + "\n");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("密钥生成失败！");
            throw new RuntimeException(e);
        }
        String text = "{待加密数据，unencrypted！+-*/}";
        String encryptStr;
        try {
            encryptStr = AESUtils.encrypt(text, key);
            System.out.println("密文: " + encryptStr + "\n");
        } catch (Exception e) {
            System.err.println("加密失败！");
            throw new RuntimeException(e);
        }
        String decryptStr;
        try {
            decryptStr = AESUtils.decrypt(encryptStr, key);
            System.out.println("明文: " + decryptStr + "\n");
        } catch (Exception e) {
            System.err.println("解密失败！");
            throw new RuntimeException(e);
        }
    }

}
