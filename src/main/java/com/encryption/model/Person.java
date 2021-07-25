package com.encryption.model;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Person {
    public final String name;

    // 公钥
    public PublicKey publicKey;

    // 私钥
    private PrivateKey privateKey;

    // 用于加密的密钥
    private SecretKey secretKey;

    public Person(String name) {
        this.name = name;
    }

    /**
     * 生成本地 KeyPair
     */
    public void generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DH");
        kpGen.initialize(512);
        KeyPair keyPair = kpGen.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public void generateSecretKey(byte[] receivedPubKeyBytes) throws GeneralSecurityException {
        // 从 byte[] 回复 PublicKey
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receivedPubKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey receivedPublicKey = keyFactory.generatePublic(keySpec);
        // 生成本地密钥
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(this.privateKey); // 自己的  privateKey
        keyAgreement.doPhase(receivedPublicKey, true); // 收到对方的 publicKey
        // 生成 AES 密钥
        this.secretKey = keyAgreement.generateSecret("AES");
    }

    public void printKeys() {
        System.out.printf("Name: %s\n", this.name);
        System.out.printf("Private Key: %x\n", new BigInteger(1, this.privateKey.getEncoded()));
        System.out.printf("Public Key: %x\n", new BigInteger(1, this.publicKey.getEncoded()));
        System.out.printf("Secret Key: %x\n", new BigInteger(1, this.secretKey.getEncoded()));
    }

    /**
     * 消息加密并发送
     *
     * @param message
     */
    public String sendMessage(String message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
        byte[] data = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * 接受加密消息并解密
     *
     * @param message
     * @return
     */
    public String receiveMessage(String message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.secretKey);
        byte[] data = cipher.doFinal(Base64.getDecoder().decode(message));
        return new String(data, StandardCharsets.UTF_8);
    }
}
