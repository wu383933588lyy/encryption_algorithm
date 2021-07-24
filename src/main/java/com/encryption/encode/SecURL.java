package com.encryption.encode;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * URL 编码解码
 */
public class SecURL {

    public static void main(String[] args) throws Exception{
        String original = "URL 参数";
        String encoded = URLEncoder.encode(original, String.valueOf(StandardCharsets.UTF_8));
        System.out.println(encoded); // URL+%E5%8F%82%E6%95%B0
        String ori = URLDecoder.decode(encoded, String.valueOf(StandardCharsets.UTF_8));
        System.out.println(ori); // URL 参数
    }
}
