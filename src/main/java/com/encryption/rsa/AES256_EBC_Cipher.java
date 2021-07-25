package com.encryption.rsa;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

public class AES256_EBC_Cipher {

    static final String CIPHER_NAME = "AES/ECB/PKCS5Padding";

    public static void main(String[] args) throws Exception{
        // 原文
        String message = "Hello world! encrypted using AES!";
        System.out.println("Message: " + message);
        // 256 位秘钥= 32 bytes Key:
        byte[] key = "1234567890abcdef1234567890abcdef".getBytes(StandardCharsets.UTF_8);
        // 加密：
        byte[] data = message.getBytes(StandardCharsets.UTF_8);
        byte[] encrypt = AES_CBC_Cipher.encrypt(key, data);
        System.out.println("Encrypted data: " + Base64.getEncoder().encodeToString(encrypt));
        // 解密：
        byte[] decrypt = AES_CBC_Cipher.decrypt(key, encrypt);
        System.out.println("Decrypted data: " + new String(decrypt, StandardCharsets.UTF_8));
    }

}
