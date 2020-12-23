package com.github.qq120011676.rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class RSAHelperTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, NoSuchProviderException {
        String path = RSAHelperTest.class.getResource("/").getPath() + "../../../resources/test/";
        String testPublicLocation = path + "test.pub";
        String testPrivateLocation = path + "test";
        String appPublicLocation = path + "app_public_key.pem";


        RSAHelper rsaHelper = new RSAHelper();
        rsaHelper.setTransformation("RSA/ECB/OAEPPadding");
        rsaHelper.setProvider(null);
        rsaHelper.setRSAPublicKeyByPEM(appPublicLocation);
        rsaHelper.setRSAPrivateKeyByPEM(testPrivateLocation);
        String testPasswordPublicLocation = path + "test_password.pub";
        String testPasswordPrivateLocation = path + "test_password";
        String password = "123456";
        rsaHelper.setRSAPrivateKeyByPEM(testPasswordPrivateLocation, password);
        testPasswordPrivateLocation = path + "app_private_key.pem";
        rsaHelper.setRSAPrivateKeyByPEM(testPasswordPrivateLocation);
        StringBuilder content = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            content.append("中文");
        }
        System.out.println(content);
        String w = rsaHelper.encryptPublicByBase64(content.toString());
        String m = rsaHelper.decryptPrivateByBase64(w);
        System.out.println(content.toString().equals(m));
    }
}
