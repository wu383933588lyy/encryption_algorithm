package com.encryption.encode;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5 {

    public static byte[] toMD5(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(input);
        return md.digest();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String s = "MD5摘要算法测试";
        byte[] r = toMD5(s.getBytes(StandardCharsets.UTF_8));
        System.out.println(String.format("%032x",new BigInteger(1,r)));
    }
}
