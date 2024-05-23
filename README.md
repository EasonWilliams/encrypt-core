# 加密工具包，内含AES/ECB/PKCS5Padding、SM4/CBC/PKCS7Padding、SHA265HMAC、BCRYPT加密算法。

## AES/ECB/PKCS5Padding

### 示例:

```java
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
```

## SM4/CBC/PKCS7Padding

### 示例:

```java
public static void main(String[] args) {
        String key = SM4Utils.generateRandomKey();
        System.out.println("密钥: " + key + "\n");
        String text = "{待加密数据，unencrypted！+-*/}";
        String encryptStr = SM4Utils.encrypt(text, key);
        System.out.println("密文: " + encryptStr + "\n");
        String decryptStr = SM4Utils.decrypt(encryptStr, key);
        System.out.println("明文: " + decryptStr + "\n");
    }
```

## SHA265HMAC

### 示例:

```java
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
    }
```

## BCRYPT

### 示例:

```java
public static void main(String[] args) {
        String pwd = "{待加密数据，unencrypted！+-*/}";
        String base64Pwd = Base64.encode(pwd);
        String bcryptBase64Hash = CipherUtils.bcryptBase64(base64Pwd);
        System.out.println("bcryptBase64Hash: " + bcryptBase64Hash);
        System.out.println("明文密码验证: " + CipherUtils.bcryptVerify(pwd, bcryptBase64Hash));
        System.out.println("base64密码验证: " + CipherUtils.bcryptVerifyBase64(base64Pwd, bcryptBase64Hash) + "\n");
        String bcryptHash = CipherUtils.bcrypt(pwd);
        System.out.println("bcryptHash: " + bcryptHash);
        System.out.println("明文密码验证: " + CipherUtils.bcryptVerify(pwd, bcryptBase64Hash));
        System.out.println("base64密码验证: " + CipherUtils.bcryptVerifyBase64(base64Pwd, bcryptBase64Hash));
    }
```

