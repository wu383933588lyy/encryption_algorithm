package com.encryption.encode;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SecBase64 {

    public static void main(String[] args) {
        String original = "Hello\u00ff编码测试";
        String b64 = Base64.getEncoder().encodeToString(original.getBytes(StandardCharsets.UTF_8));
        System.out.println(b64);
        String ori = new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
        System.out.println(ori);
    }
}
