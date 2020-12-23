package com.github.qq120011676.cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.crypto.Cipher;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;

public class RSATest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        String phone = "wiy2vwObweOloABkRam5fp1Orb+HjUcD/e4Z4Jt1Msbj4vHE18U0xiyG42qAzkbbh8Zm5miQ9BXSQUWUUTJEYeeZHaSHvJr81sGAHYguj7In1TbJIOAQcr3dKGn6Zks43GsCbDR4PQYyv+7kFzSDxLAzJBlWtRVM9vFUxmEU6vI=";
        String privateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICXAIBAAKBgQDZCq1g6prssPfxEtgLC2mMjEpb7fm6c3p5rGvh0WLxN8Yn/0lV\n" +
                "gI3fw27NmxKkUbCYF8AOZnpwGj7rdSx+V/P/0nOKCnu2w0FT/r3F4mJd7RIIDKQy\n" +
                "b+8p6y4z1VZ+4gGsOb6kE2nz0MZGI23i7U3C49mNOUa0t8g1LlyYCuDj0wIDAQAB\n" +
                "AoGAQOdOfaLqfUlWe8LU1EivYZY6Tk9V1Inf4C7NfBPvcI7rNN7EgUsWIgoBQn7T\n" +
                "DkxXcMP5bNT8XDWdBzBdA9MtZY/+VmBhzMSSwQmhlfghqSKESeQFNMam5dyHOlYJ\n" +
                "1SY/XSNQz7aJbZg1gFuBbwqq8IipQvm4vtctewd4BhR8lBECQQDuj+D5X3NK6d5C\n" +
                "5UCa4xLbYweHyWf/wiHJweQwPPVO9DW2TBXPEKuvIsrRHf/SriyJd5eC2GIPuF25\n" +
                "jUesanu1AkEA6OgYy2gC6PknP7ebssWUUlMdW2fogpJ+uE6558TTAtXTEN0HPBq8\n" +
                "jLYMncOdPn5QeT003sxC7iAQB+gWISNmZwJAK+vtfbwnG+nG9AYFSP75n86xujxI\n" +
                "m3wAgIbkHkV63Jh1syR6926YTVxYfvvI9979cCnGiV6RX1eQWfM6+PF56QJANxWN\n" +
                "p6314jvrOHqobGOmbMITk2bD6v3S0qxr85DthyIjRT3BVEnOhkkYOsflDL67MbF0\n" +
                "K62Ltt4GbJhLg5LnyQJBAJstCDHQDQ6XaMYzfvXDz1hEl183H3wuX9YiWGTvbMZm\n" +
                "RoueQ8b+XEKIrE8pYmRPB4zA7rQuWq9RKGo+4tP4vAw=\n" +
                "-----END RSA PRIVATE KEY-----\n";
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        rsa.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
        byte[] utf8 = rsa.doFinal(Base64.getDecoder().decode(phone));
        String result = new String(utf8, StandardCharsets.UTF_8);
        System.out.println(result);
    }

    private static PrivateKey getPrivateKey(String privateKey) throws Exception {
        Reader privateKeyReader = new StringReader(privateKey);
        PEMParser privatePemParser = new PEMParser(privateKeyReader);
        Object privateObject = privatePemParser.readObject();
        if (privateObject instanceof PEMKeyPair) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) privateObject;
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            PrivateKey privKey = converter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
            return privKey;
        }
        return null;
    }
}
