package com.encryption.ca;


import javax.crypto.Cipher;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class X509 {

    // 私钥
    private final PrivateKey privateKey;

    // 证书（包含公钥等信息）
    public final X509Certificate certificate;

    public X509(KeyStore keyStore,String certName,String password)throws GeneralSecurityException {
        this.privateKey = (PrivateKey) keyStore.getKey(certName,password.toCharArray());
        this.certificate = (X509Certificate) keyStore.getCertificate(certName);
    }

    /**
     * 加密
     */
    public byte[] encrypt(byte[] message)throws GeneralSecurityException{
        Cipher cipher = Cipher.getInstance(this.privateKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE,this.privateKey);
        return cipher.doFinal(message);
    }

    /**
     * 解密
     */
    public byte[] decrypt(byte[] data)throws GeneralSecurityException{
        PublicKey publicKey = this.certificate.getPublicKey();
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE,publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 签名
     */
    public byte[] sign(byte[] message)throws GeneralSecurityException{
        Signature signature = Signature.getInstance(this.certificate.getSigAlgName());
        signature.initSign(this.privateKey);
        signature.update(message);
        return signature.sign();
    }

    /**
     * 验证签名
     */
    public boolean verify(byte[] message,byte[] sign)throws GeneralSecurityException{
        Signature signature = Signature.getInstance(this.certificate.getSigAlgName());
        signature.initVerify(this.certificate);
        signature.update(message);
        return signature.verify(sign);
    }

    static KeyStore loadKeyStore(String keyStoreFile, String password){
        try(InputStream inputStream = new BufferedInputStream(new FileInputStream(keyStoreFile))){
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(inputStream,password.toCharArray());
            return keyStore;
        }catch (GeneralSecurityException | IOException e){
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws Exception{
        byte[] message = "Hello, 使用 X.509 证书进行加密和签名！".getBytes(StandardCharsets.UTF_8);
        // 读取 KeyStore
        KeyStore keyStore = loadKeyStore("my.keystore", "456789");
        // 读取证书
        X509 x509 = new X509(keyStore, "mycert", "123456");
        // 加密
        byte[] encrypt = x509.encrypt(message);
        System.out.println("encrypted : "+ Base64.getEncoder().encodeToString(encrypt));
        // 解密
        byte[] decrypt = x509.decrypt(encrypt);
        System.out.println("decrypted: "+ new String(decrypt,StandardCharsets.UTF_8));
        // 签名
        byte[] sign = x509.sign(message);
        System.out.println("sign: "+ Base64.getEncoder().encodeToString(sign));
        // 验证签名
        boolean verify = x509.verify(message, sign);
        System.out.println("verify: "+ verify);
    }

}
