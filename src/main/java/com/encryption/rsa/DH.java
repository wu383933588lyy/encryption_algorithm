package com.encryption.rsa;


import com.encryption.model.Person;

import java.security.GeneralSecurityException;

public class DH {

    public static void main(String[] args)throws GeneralSecurityException {
        Person bob = new Person("Bob");
        Person alice = new Person("Alice");

        // 各自生成 KeyPair
        bob.generateKeyPair();
        alice.generateKeyPair();

        // 双方交换各自的 PublicKey
        // Bob 根据 Alice 的 PublicKey 生成自己的本地密钥：
        bob.generateSecretKey(alice.publicKey.getEncoded());
        // Alice 根据 Bob 的 PublicKey 生成自己的本地密钥：
        alice.generateSecretKey(bob.publicKey.getEncoded());

        // 检查双方的本地密钥是否相同
        bob.printKeys();
        alice.printKeys();

        // 如果双方的 SecretKey 相同，后续将使用 SecretKey 作为密钥进行 AES 加解密
        String msgBobToAlice = bob.sendMessage("Hello , Alice");
        System.out.println("Bob -> Alice: "+ msgBobToAlice);
        String aliceDecrypted = alice.receiveMessage(msgBobToAlice);
        System.out.println("Alice decrypted: "+ aliceDecrypted);
    }
}
