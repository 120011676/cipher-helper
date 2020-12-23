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
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * RSA 加解密
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RSAHelper {
    private RSAPublicKey rsaPublicKey;
    private RSAPrivateKey rsaPrivateKey;
    private String transformation = "RSA/NONE/OAEPPadding";
    private String provider = "";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 构造方法公钥
     *
     * @param rsaPublicKey 公钥
     */
    public RSAHelper(RSAPublicKey rsaPublicKey) {
        this.rsaPublicKey = rsaPublicKey;
    }

    /**
     * 构造方法
     *
     * @param rsaPrivateKey 私钥
     */
    public RSAHelper(RSAPrivateKey rsaPrivateKey) {
        this.rsaPrivateKey = rsaPrivateKey;
    }

    /**
     * 设置公钥
     *
     * @param fileName 公钥
     * @throws IOException 异常
     */
    public void setRSAPublicKeyByPEM(String fileName) throws IOException {
        try (FileReader fileReader = new FileReader(fileName)) {
            this.setRSAPublicKeyByPEM(fileReader);
        }
    }

    /**
     * 设置公钥
     *
     * @param inputStream 公钥
     * @throws IOException 异常
     */
    public void setRSAPublicKeyByPEM(InputStream inputStream) throws IOException {
        try (InputStreamReader inputStreamReader = new InputStreamReader(inputStream)) {
            this.setRSAPublicKeyByPEM(inputStreamReader);
        }
    }

    /**
     * 设置公钥
     *
     * @param reader 公钥
     * @throws IOException 异常
     */
    public void setRSAPublicKeyByPEM(Reader reader) throws IOException {
        Object object;
        try (PEMParser pemParser = new PEMParser(reader)) {
            object = pemParser.readObject();
        }
        SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) object;
        JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
        this.rsaPublicKey = (RSAPublicKey) jcaPEMKeyConverter.getPublicKey(subjectPublicKeyInfo);
    }

    /**
     * 设置私钥
     *
     * @param fileName 私钥
     * @throws IOException 异常
     */
    public void setRSAPrivateKeyByPEM(String fileName) throws IOException {
        this.setRSAPrivateKeyByPEM(fileName, null);
    }

    /**
     * 设置私钥
     *
     * @param fileName 私钥
     * @param password 密码
     * @throws IOException 异常
     */
    public void setRSAPrivateKeyByPEM(String fileName, String password) throws IOException {
        this.setRSAPrivateKeyByPEM(new FileReader(fileName), password);
    }

    /**
     * 设置私钥
     *
     * @param inputStream 私钥
     * @throws IOException 异常
     */
    public void setRSAPrivateKeyByPEM(InputStream inputStream) throws IOException {
        this.setRSAPrivateKeyByPEM(inputStream, null);
    }

    /**
     * 设置私钥
     *
     * @param inputStream 私钥
     * @param password    密码
     * @throws IOException 异常
     */
    public void setRSAPrivateKeyByPEM(InputStream inputStream, String password) throws IOException {
        try (InputStreamReader inputStreamReader = new InputStreamReader(inputStream)) {
            this.setRSAPrivateKeyByPEM(inputStreamReader, password);
        }
    }

    /**
     * 设置私钥
     *
     * @param reader 私钥
     * @throws IOException 异常
     */
    public void setRSAPrivateKeyByPEM(Reader reader) throws IOException {
        this.setRSAPrivateKeyByPEM(reader, null);
    }

    /**
     * 设置私钥
     *
     * @param reader   私钥
     * @param password 私钥密码
     * @throws IOException 异常
     */
    public void setRSAPrivateKeyByPEM(Reader reader, String password) throws IOException {
        Object object;
        try (PEMParser pemParser = new PEMParser(reader)) {
            object = pemParser.readObject();
        }
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

    /**
     * base64公钥加密
     *
     * @param content 带加密字符
     * @return 加密后的字符
     * @throws NoSuchPaddingException    异常
     * @throws NoSuchAlgorithmException  异常
     * @throws InvalidKeyException       异常
     * @throws BadPaddingException       异常
     * @throws IllegalBlockSizeException 异常
     * @throws NoSuchProviderException   异常
     */
    public String encryptPublicByBase64(String content) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return Base64.getEncoder().encodeToString(this.encryptPublic(content.getBytes()));
    }

    /**
     * 公钥加密
     *
     * @param bytes 带加密字节
     * @return 加密后的字节
     * @throws NoSuchPaddingException    异常
     * @throws NoSuchAlgorithmException  异常
     * @throws InvalidKeyException       异常
     * @throws BadPaddingException       异常
     * @throws IllegalBlockSizeException 异常
     * @throws NoSuchProviderException   异常
     */
    public byte[] encryptPublic(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        Cipher cipher = this.createCipher();
        cipher.init(Cipher.ENCRYPT_MODE, this.rsaPublicKey);
        return cipher.doFinal(bytes);
    }

    /**
     * base64私钥解密
     *
     * @param content 带解密字符
     * @return 解密后的字符
     * @throws NoSuchPaddingException    异常
     * @throws NoSuchAlgorithmException  异常
     * @throws InvalidKeyException       异常
     * @throws BadPaddingException       异常
     * @throws IllegalBlockSizeException 异常
     * @throws NoSuchProviderException   异常
     */
    public String decryptPrivateByBase64(String content) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return new String(this.decryptPrivate(Base64.getDecoder().decode(content)));
    }

    /**
     * 私钥解密
     *
     * @param bytes 带解密字节
     * @return 解密后的字节
     * @throws NoSuchPaddingException    异常
     * @throws NoSuchAlgorithmException  异常
     * @throws InvalidKeyException       异常
     * @throws BadPaddingException       异常
     * @throws IllegalBlockSizeException 异常
     * @throws NoSuchProviderException   异常
     */
    public byte[] decryptPrivate(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        Cipher cipher = this.createCipher();
        cipher.init(Cipher.DECRYPT_MODE, this.rsaPrivateKey);
        return cipher.doFinal(bytes);
    }

    /**
     * base64私钥加密方法
     *
     * @param content 带加密的字符
     * @return 加密后的字符
     * @throws NoSuchPaddingException    异常
     * @throws NoSuchAlgorithmException  异常
     * @throws InvalidKeyException       异常
     * @throws BadPaddingException       异常
     * @throws IllegalBlockSizeException 异常
     * @throws NoSuchProviderException   异常
     */
    public String encryptPrivateByBase64(String content) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return Base64.getEncoder().encodeToString(this.encryptPrivate(content.getBytes()));
    }

    /**
     * 私钥加密方法
     *
     * @param bytes 带加密的字节
     * @return 加密后的字节
     * @throws NoSuchPaddingException    异常
     * @throws NoSuchAlgorithmException  异常
     * @throws InvalidKeyException       异常
     * @throws BadPaddingException       异常
     * @throws IllegalBlockSizeException 异常
     * @throws NoSuchProviderException   异常
     */
    public byte[] encryptPrivate(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        Cipher cipher = this.createCipher();
        cipher.init(Cipher.ENCRYPT_MODE, this.rsaPrivateKey);
        return cipher.doFinal(bytes);
    }

    /**
     * 公钥解密方法
     *
     * @param content 带解密的字符
     * @return 解密后的字符
     * @throws NoSuchPaddingException    异常
     * @throws NoSuchAlgorithmException  异常
     * @throws InvalidKeyException       异常
     * @throws BadPaddingException       异常
     * @throws IllegalBlockSizeException 异常
     * @throws NoSuchProviderException   异常
     */
    public String decryptPublic(String content) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return new String(this.decryptPublic(Base64.getDecoder().decode(content)));
    }

    /**
     * 公钥解密方法
     *
     * @param bytes 带解密字节
     * @return 解密后的字节
     * @throws NoSuchPaddingException    异常
     * @throws NoSuchAlgorithmException  异常
     * @throws InvalidKeyException       异常
     * @throws BadPaddingException       异常
     * @throws IllegalBlockSizeException 异常
     * @throws NoSuchProviderException   异常
     */
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
