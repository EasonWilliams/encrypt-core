import cn.zimi.encrypt.util.SM4Utils;

/**
 * @Description:
 * @Author: eason
 * @Date: 2024/5/23 10:19
 */
public class SM4Test {

    public static void main(String[] args) {
        String key = SM4Utils.generateRandomKey();
        System.out.println("密钥: " + key + "\n");
        String text = "{待加密数据，unencrypted！+-*/}";
        String encryptStr = SM4Utils.encrypt(text, key);
        System.out.println("密文: " + encryptStr + "\n");
        String decryptStr = SM4Utils.decrypt(encryptStr, key);
        System.out.println("明文: " + decryptStr + "\n");
    }

}
