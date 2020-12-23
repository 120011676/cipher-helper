package com.github.qq120011676.rsa;

import com.github.qq120011676.cipher.RSAHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class JSRSATest {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, NoSuchProviderException {
        String message = "1";
        String m = "13+87jT2/mkYnu/vPgtVplA9pC6cKM+WFjdNJlLNY2YdvBhl9xDdZIvGLDlaYcMRc/yQlHrh1jn8+QEfHEReJU/L6x6E40BPjt0iYA/ocjz55c5AKWg7lo88SwePmpM1VsV9MOzehtD6As9m2M+YyknoNWQFaLsRg94Rxnl2gTRD8IAnofAqxdUPtH8sZwNSKUXK5N548tDW2FhGMHVwHvIWFLLwHDgffCtqaahQNR2lZ1emgoR9expB5v8MtTRdETkEiqofxhmowlUxEoWR0MHFOQd9wPzmxJ7exwbifCOPm+TS2aCLwiKej4VaaznsXHwAkm+5fL5SFmxu7UVC+w==";
        String path = RSAHelperTest.class.getResource("/").getPath() + "../../../resources/test/";
        String testPrivateLocation = path + "app_private_key.pem";
        RSAHelper rsauHelper = new RSAHelper();
//        rsauHelper.setTransformation("RSA/NONE/OAEPPadding");
//        rsauHelper.setProvider(null);
        rsauHelper.setRSAPrivateKeyByPEM(testPrivateLocation);
        String w = rsauHelper.decryptPrivateByBase64(m);
        System.out.println(w);
        System.out.println(message.equals(w));
    }
}
