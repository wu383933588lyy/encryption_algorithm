package com.encryption.encode;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class MD5Salt {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String passwd = "helloworld";
        String salt = "Random salt";
        byte[] r = MD5.toMD5((salt + passwd).getBytes(StandardCharsets.UTF_8));
        System.out.printf("%032x%n", new BigInteger(1, r));
    }
}
