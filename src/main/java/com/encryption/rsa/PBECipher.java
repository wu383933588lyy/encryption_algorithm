package com.encryption.rsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

public class PBECipher {

    static final String CIPHER_NAME = "PBEwithSHA1and128bitAES-CBC-BC";

    public static byte[] encrypt(String password,byte[] salt,byte[] input)throws Exception{
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CIPHER_NAME);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, 1000);
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE,secretKey,parameterSpec);
        return cipher.doFinal(input);
    }

    public static byte[] decrypt(String password,byte[] salt,byte[] input)throws Exception{
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CIPHER_NAME);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, 1000);
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        cipher.init(Cipher.DECRYPT_MODE,secretKey,parameterSpec);
        return cipher.doFinal(input);
    }

    public static void main(String[] args) throws Exception{
        // 把 BouncyCastle 作为 Provider 添加到 java.security
        Security.addProvider(new BouncyCastleProvider());
        // 原文：
        String message = "Hello world! encrypted using PBE!";
        // 加密口令
        String password = "hello12345";
        // 16 bytes 随机 Salt
        byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
        System.out.printf("salt: %032x\n",new BigInteger(1,salt));
        // 加密
        byte[] data = message.getBytes(StandardCharsets.UTF_8);
        byte[] encrypt = encrypt(password, salt, data);
        System.out.println("encrypted: "+ Base64.getEncoder().encodeToString(encrypt));
        // 解密
        byte[] decrypt = decrypt(password, salt, encrypt);
        System.out.println(new String(decrypt,StandardCharsets.UTF_8));
    }

}
