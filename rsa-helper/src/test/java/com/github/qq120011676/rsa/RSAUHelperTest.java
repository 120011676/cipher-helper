package com.github.qq120011676.rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class RSAUHelperTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        String path = RSAUHelperTest.class.getResource("/").getPath() + "../../../resources/test/";
        String testPublicLocation = path + "test.pub";
        String testPrivateLocation = path + "test";
        String appPublicLocation = path + "app_public_key.pem";


        RSAUHelper rsauHelper = new RSAUHelper();
        rsauHelper.setRSAPublicKeyByPEM(appPublicLocation);
        rsauHelper.setRSAPrivateKeyByPEM(testPrivateLocation);
        String testPasswordPublicLocation = path + "test_password.pub";
        String testPasswordPrivateLocation = path + "test_password";
        String password = "123456";
        rsauHelper.setRSAPrivateKeyByPEM(testPasswordPrivateLocation, password);
        testPasswordPrivateLocation = path + "app_private_key.pem";
        rsauHelper.setRSAPrivateKeyByPEM(testPasswordPrivateLocation);
        StringBuilder content = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            content.append("中文");
        }
        System.out.println(content);
        String w = rsauHelper.encryptPublicByBase64(content.toString());
        String m = rsauHelper.decryptPrivateByBase64(w);
        System.out.println(content.toString().equals(m));
    }
}
