package com.github.qq120011676.rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class JSRSATest {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        String message = "Hello, world!";
        String m = "2A+QgJVVq44e+6wdstX2K4FuKrFmKwNZVAyi2eooCM7vERuw8qONVohvB1Ci/znFLpw17KbnIBGHo0e3AVLeuNdH4iDzyg/NV4nCgpXE0F9pfKLGKlrnvIWQlGnchCAGDSeo5FwsRNrnzePYF43O1oKMn6xDb9BpngYgdb5oDRXK0JAW6emlpPQ/ZEvLyl6zOQF92GPVO1FkGsBJrFEQV79xJOwnLuKatdOVcixNBAoBIFGQmm4TGjT/k3m8t0Qn3k+iqoR+KlJcF79lJ37y+oA3+ervLErq1tS6/x+kyEMHY8OemFbMz3xLrKShwz+m/W+j6dLGHSNmf4+OTz2fAg==";
        String path = RSAUHelperTest.class.getResource("/").getPath() + "../../../resources/test/";
        String testPrivateLocation = path + "app_private_key.pem";
        RSAUHelper rsauHelper = new RSAUHelper();
        rsauHelper.setRSAPrivateKeyByPEM(testPrivateLocation);
        String w = rsauHelper.decryptPrivateByBase64(m);
        System.out.println(w);
        System.out.println(message.equals(w));
    }
}
