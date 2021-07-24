package com.encryption.encode;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Hmac {

    /**
     * Hmac 加密
     * @param hmacAlgorithm ： 加密算法名词
     * @param skey：随机 Key
     * @param input ： 原始输入字节
     */
    public static byte[] hmac(String hmacAlgorithm, SecretKey skey,byte[] input) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(hmacAlgorithm);
        mac.init(skey);
        mac.update(input);
        return mac.doFinal();
    }

    public static void main(String[] args)throws Exception {
        String algorithm = "HMacSHA1";
        // 原始数据
        String data = "hello world";
        // 随机生成一个 Key
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        SecretKey skey = keyGen.generateKey();
        // 打印 key
        byte[] key = skey.getEncoded();
        System.out.println(new BigInteger(1, key).toString(16));
        // 使用 Key 计算
        byte[] result = hmac(algorithm, skey, data.getBytes(StandardCharsets.UTF_8));
        System.out.println(new BigInteger(1, result).toString(16));
    }
}
