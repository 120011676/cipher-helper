package com.github.qq120011676.rsa;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RSAUHelper {
    private RSAPublicKey rsaPublicKey;
    private RSAPrivateKey rsaPrivateKey;

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

    public void setRSAPrivateKeyByPEM(String fileName) throws IOException, NoSuchAlgorithmException {
        this.setRSAPrivateKeyByPEM(fileName, null);
    }

    public void setRSAPrivateKeyByPEM(String fileName, String password) throws IOException, NoSuchAlgorithmException {
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
}
