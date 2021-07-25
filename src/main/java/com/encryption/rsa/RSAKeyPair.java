package com.encryption.rsa;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAKeyPair {

    PrivateKey sk;

    PublicKey pk;

    /**
     *  生成 公钥、私钥对
     * @throws GeneralSecurityException
     */
    public RSAKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        KeyPair kp = kpGen.generateKeyPair();
        this.sk = kp.getPrivate();
        this.pk = kp.getPublic();
    }

    /**
     * 从以保存的字节中（例如读取文件）回复公钥、私钥
     */
    public RSAKeyPair(byte[] pk,byte[] sk)throws GeneralSecurityException{
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
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
     * 用公钥加密
     */
    public byte[] encrypt(byte[] message) throws GeneralSecurityException{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,this.pk);
        return cipher.doFinal(message);
    }

    /**
     * 用私钥解密
     */
    public byte[] decrypt(byte[] input)throws GeneralSecurityException{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,this.sk);
        return cipher.doFinal(input);
    }

    public static void main(String[] args) throws GeneralSecurityException{
        // 明文
        byte[] plain =  "Hello ，使用 RSA 非对称加密算法对数据进行加密！".getBytes(StandardCharsets.UTF_8);
        // 创建公钥、私钥对
        RSAKeyPair rsa = new RSAKeyPair();
        // 加密：
        byte[] encrypt = rsa.encrypt(plain);
        System.out.println("encrypted: "+ Base64.getEncoder().encodeToString(encrypt));
        // 解密：
        byte[] decrypt = rsa.decrypt(encrypt);
        System.out.println(new String(decrypt,StandardCharsets.UTF_8));
        // 保存公钥、私钥
        byte[] pk = rsa.getPublicKey();
        byte[] sk = rsa.getPrivateKey();
        System.out.println("pk: "+Base64.getEncoder().encodeToString(pk));
        System.out.println("sk: "+ Base64.getEncoder().encodeToString(sk));
        // 重新恢复公钥、私钥
        RSAKeyPair rsa2 = new RSAKeyPair(pk, sk);
        // 加密：
        byte[] encrypt2 = rsa2.encrypt(plain);
        System.out.println("encrypted2: "+ Base64.getEncoder().encodeToString(encrypt2));
        // 解密：
        byte[] decrypt2 = rsa2.decrypt(encrypt2);
        System.out.println(new String(decrypt2,StandardCharsets.UTF_8));

    }
}
