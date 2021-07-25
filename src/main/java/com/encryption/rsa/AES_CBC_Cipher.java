package com.encryption.rsa;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class AES_CBC_Cipher {

    static final String CIPHER_NAME = "AES/CBC/PKCS5Padding";

    /**
     * 加密
     *
     * @param key：秘钥
     * @param input：原文
     */
    public static  byte[] encrypt(byte[] key,byte[] input)throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        // CBC 模式需要生成一个 16 bytes 的 initialization vector :
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] iv = random.generateSeed(16);
        IvParameterSpec ivps = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE,keySpec,ivps);
        byte[] data = cipher.doFinal(input);
        // iv 不需要保密，将 iv 和 密文一起返回
        return join(iv,data);
    }

    /**
     * 解密
     *
     * @param key：秘钥
     * @param input：加密的输入
     */
    public static byte[] decrypt(byte[] key,byte[] input)throws GeneralSecurityException{
        // 把 input 分割成 iv 和 密文
        byte[] iv = new byte[16];
        byte[] data = new byte[input.length - 16];
        System.arraycopy(input,0,iv,0,16);
        System.arraycopy(input,16,data,0,data.length);
        // 解密：
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivps = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE,keySpec,ivps);
        return cipher.doFinal(data);
    }

    private static byte[] join(byte[] iv, byte[] data) {
        byte[] bytes = new byte[iv.length + data.length];
        System.arraycopy(iv,0,bytes,0,iv.length);
        System.arraycopy(data,0,bytes,iv.length,data.length);
        return bytes;
    }

}
