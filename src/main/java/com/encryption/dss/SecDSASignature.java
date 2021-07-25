package com.encryption.dss;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SecDSASignature {

    PrivateKey sk;
    PublicKey pk;

    public SecDSASignature()throws GeneralSecurityException{
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA");
        kpGen.initialize(1024);
        KeyPair kp = kpGen.generateKeyPair();
        this.sk = kp.getPrivate();
        this.pk = kp.getPublic();
    }

    /**
     * 从以保存的字节中（例如读取文件）回复公钥、私钥
     */
    public SecDSASignature(byte[] pk, byte[] sk)throws GeneralSecurityException{
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(pk);
        this.pk = keyFactory.generatePublic(pkSpec);
        PKCS8EncodedKeySpec skSpec = new PKCS8EncodedKeySpec(sk);
        this.sk = keyFactory.generatePrivate(skSpec);
    }

    /**
     * 导出私钥字节
     */
    public byte[] getPrivateKey(){
        return this.sk.getEncoded();
    }

    /**
     * 导出公钥字节
     */
    public byte[] getPublicKey(){
        return this.pk.getEncoded();
    }

    /**
     * 签名
     */
    public byte[] sign(byte[] message)throws GeneralSecurityException{
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initSign(this.sk);
        signature.update(message);
        return signature.sign();
    }

    /**
     * 验证
     */
    public boolean verify(byte[] message,byte[] sign) throws GeneralSecurityException{
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initVerify(this.pk);
        signature.update(message);
        return signature.verify(sign);
    }

    public static void main(String[] args)throws GeneralSecurityException {
        byte[] message = "Hello, 使用 SHA1withDSA 算法进行数字签名！".getBytes(StandardCharsets.UTF_8);
        SecDSASignature signature = new SecDSASignature();
        byte[] sign = signature.sign(message);
        System.out.println("sign: "+ Base64.getEncoder().encodeToString(sign));
        boolean verify = signature.verify(message, sign);
        System.out.println("verify: "+ verify);
        // 用另一个公钥验证
        boolean verify2 = new SecDSASignature().verify(message, sign);
        System.out.println("verify with another public key: "+ verify2);
        // 修改原始信息
        message[0] = 100;
        boolean verify3 = signature.verify(message, sign);
        System.out.println("verify change message: "+ verify3);
    }
}
