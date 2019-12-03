package com.github.qq120011676.rsa;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RSAUHelper {
    private RSAPublicKey rsaPublicKey;
    private RSAPrivateKey rsaPrivateKey;
    private String transformation = "RSA/NONE/OAEPWithSHA1AndMGF1Padding";
    private String provider = "BC";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public RSAUHelper(RSAPublicKey rsaPublicKey) {
        this.rsaPublicKey = rsaPublicKey;
    }

    public RSAUHelper(RSAPrivateKey rsaPrivateKey) {
        this.rsaPrivateKey = rsaPrivateKey;
    }

    public void setRSAPublicKeyByPEM(String fileName) throws IOException {
        PEMParser pemParser = new PEMParser(new FileReader(fileName));
        Object object = pemParser.readObject();
        SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) object;
        JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
        this.rsaPublicKey = (RSAPublicKey) jcaPEMKeyConverter.getPublicKey(subjectPublicKeyInfo);
    }

    public void setRSAPrivateKeyByPEM(String fileName) throws IOException {
        this.setRSAPrivateKeyByPEM(fileName, null);
    }

    public void setRSAPrivateKeyByPEM(String fileName, String password) throws IOException {
        PEMParser pemParser = new PEMParser(new FileReader(fileName));
        Object object = pemParser.readObject();
        JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair keyPair;
        if (object instanceof PEMEncryptedKeyPair) {
            PEMEncryptedKeyPair pemEncryptedKeyPair = (PEMEncryptedKeyPair) object;
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
            keyPair = jcaPEMKeyConverter.getKeyPair(pemEncryptedKeyPair.decryptKeyPair(decProv));
        } else {
            PEMKeyPair pemKeyPair = (PEMKeyPair) object;
            keyPair = jcaPEMKeyConverter.getKeyPair(pemKeyPair);
        }
        this.rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
    }

    public String encryptPublicByBase64(String content) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return Base64.getEncoder().encodeToString(this.encryptPublic(content.getBytes()));
    }

    public byte[] encryptPublic(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        Cipher cipher = this.createCipher();
        cipher.init(Cipher.ENCRYPT_MODE, this.rsaPublicKey);
        return cipher.doFinal(bytes);
    }

    public String decryptPrivateByBase64(String content) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return new String(this.decryptPrivate(Base64.getDecoder().decode(content)));
    }

    public byte[] decryptPrivate(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        Cipher cipher = this.createCipher();
        cipher.init(Cipher.DECRYPT_MODE, this.rsaPrivateKey);
        return cipher.doFinal(bytes);
    }

    public String encryptPrivateByBase64(String content) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return Base64.getEncoder().encodeToString(this.encryptPrivate(content.getBytes()));
    }

    public byte[] encryptPrivate(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        Cipher cipher = this.createCipher();
        cipher.init(Cipher.ENCRYPT_MODE, this.rsaPrivateKey);
        return cipher.doFinal(bytes);
    }

    public String decryptPublic(String content) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return new String(this.decryptPublic(Base64.getDecoder().decode(content)));
    }

    public byte[] decryptPublic(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        Cipher cipher = this.createCipher();
        cipher.init(Cipher.DECRYPT_MODE, this.rsaPublicKey);
        return cipher.doFinal(bytes);
    }

    private Cipher createCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        if (StringUtils.isNotBlank(this.provider)) {
            return Cipher.getInstance(this.transformation, this.provider);
        } else {
            return Cipher.getInstance(this.transformation);
        }
    }
}
