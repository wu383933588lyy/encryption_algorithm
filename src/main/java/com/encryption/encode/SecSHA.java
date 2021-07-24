package com.encryption.encode;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SecSHA {

    public static byte[] toMD5(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(input);
        return md.digest();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String s = "SHA-1摘要算法测试";
        byte[] r = toMD5(s.getBytes(StandardCharsets.UTF_8));
        System.out.println(String.format("%040x",new BigInteger(1,r)));
    }
}
