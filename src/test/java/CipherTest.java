import cn.hutool.core.codec.Base64;
import cn.zimi.encrypt.util.CipherUtils;

/**
 * @Description:
 * @Author: eason
 * @Date: 2024/5/23 11:02
 */
public class CipherTest {

    public static void main(String[] args) {
        String sha265hmacKey = CipherUtils.generateRandomHMac();
        String pwd = "{待加密数据，unencrypted！+-*/}";
        String base64Pwd = Base64.encode(pwd);
        String sha265macBase64Hash = CipherUtils.sha256hmacBase64(base64Pwd, sha265hmacKey);
        System.out.println("sha265macBase64Hash: " + sha265macBase64Hash);
        System.out.println("明文密码验证: " + CipherUtils.sha256hmacVerify(pwd, sha265macBase64Hash, sha265hmacKey));
        System.out.println("base64密码验证: " + CipherUtils.sha256hmacVerifyBase64(base64Pwd, sha265macBase64Hash, sha265hmacKey) + "\n");
        String sha265macHash = CipherUtils.sha256hmac(pwd, sha265hmacKey);
        System.out.println("sha265macHash: " + sha265macBase64Hash);
        System.out.println("明文密码验证: " + CipherUtils.sha256hmacVerify(pwd, sha265macHash, sha265hmacKey));
        System.out.println("base64密码验证: " + CipherUtils.sha256hmacVerifyBase64(base64Pwd, sha265macHash, sha265hmacKey) + "\n");
        String bcryptBase64Hash = CipherUtils.bcryptBase64(base64Pwd);
        System.out.println("bcryptBase64Hash: " + bcryptBase64Hash);
        System.out.println("明文密码验证: " + CipherUtils.bcryptVerify(pwd, bcryptBase64Hash));
        System.out.println("base64密码验证: " + CipherUtils.bcryptVerifyBase64(base64Pwd, bcryptBase64Hash) + "\n");
        String bcryptHash = CipherUtils.bcrypt(pwd);
        System.out.println("bcryptHash: " + bcryptHash);
        System.out.println("明文密码验证: " + CipherUtils.bcryptVerify(pwd, bcryptBase64Hash));
        System.out.println("base64密码验证: " + CipherUtils.bcryptVerifyBase64(base64Pwd, bcryptBase64Hash));
    }

}
