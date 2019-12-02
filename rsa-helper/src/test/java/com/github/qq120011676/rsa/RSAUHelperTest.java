package com.github.qq120011676.rsa;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class RSAUHelperTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
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

    }
}
