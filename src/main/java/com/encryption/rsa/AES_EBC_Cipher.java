package com.encryption.rsa;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

public class AES_EBC_Cipher {

    static final String CIPHER_NAME = "AES/ECB/PKCS5Padding";

    /**
     * 加密
     *
     * @param key：秘钥
     * @param input：原文
     */
    public static byte[] encrypt(byte[] key, byte[] input) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(input);
    }

    /**
     * 解密
     *
     * @param key：秘钥
     * @param input：加密的输入
     */
    public static byte[] decrypt(byte[] key, byte[] input) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(input);
    }

    public static void main(String[] args) throws Exception {
        // 原文
        String message = "Hello world! encrypted using AES!";
        System.out.println("Message: " + message);
        // 128 位密钥 = 16 bytes Key:
        byte[] key = "1234567890abcdef".getBytes(StandardCharsets.UTF_8);
        // 加密：
        byte[] data = message.getBytes(StandardCharsets.UTF_8);
        byte[] encrypt = encrypt(key, data);
        System.out.println("Encrypted data: " + Base64.getEncoder().encodeToString(encrypt));

        // 字节数组可通过 Base64 转码后存储，也可存储 blob 字段
        String encode = Base64.getEncoder().encodeToString(encrypt);
        byte[] decode = Base64.getDecoder().decode(encode);
        // 解密：
        byte[] decrypt = decrypt(key, decode);
        System.out.println("Decrypted data: " + new String(decrypt, StandardCharsets.UTF_8));
    }
}
