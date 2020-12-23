package com.github.qq120011676.cipher;

import com.github.qq120011676.utils.CipherHelper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

/**
 * AES 加解密
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AesHelper {
    private static final String ALGORITHM = "AES";
    private String transformation = "AES/CFB/PKCS5Padding";

    /**
     * 加密
     *
     * @param data 带加密字节
     * @param key  秘钥
     * @param iv   向量
     * @return 加密后的字节
     * @throws NoSuchPaddingException             异常
     * @throws InvalidKeyException                异常
     * @throws NoSuchAlgorithmException           异常
     * @throws IllegalBlockSizeException          异常
     * @throws BadPaddingException                异常
     * @throws NoSuchProviderException            异常
     * @throws InvalidAlgorithmParameterException 异常
     */
    public byte[] encrypt(byte[] data, byte[] key, byte[] iv) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Cipher cipher = this.createCipher();
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALGORITHM), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    /**
     * 解密
     *
     * @param data 带解密字节
     * @param key  秘钥
     * @param iv   向量
     * @return 解密后的字节
     * @throws NoSuchPaddingException             异常
     * @throws InvalidKeyException                异常
     * @throws NoSuchAlgorithmException           异常
     * @throws IllegalBlockSizeException          异常
     * @throws BadPaddingException                异常
     * @throws NoSuchProviderException            异常
     * @throws InvalidAlgorithmParameterException 异常
     */
    public byte[] decrypt(byte[] data, byte[] key, byte[] iv) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Cipher cipher = this.createCipher();
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, ALGORITHM), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    /**
     * base加密
     *
     * @param data 带加密字符
     * @param key  秘钥
     * @param iv   向量
     * @return 加密后的字符
     * @throws NoSuchPaddingException             异常
     * @throws InvalidKeyException                异常
     * @throws NoSuchAlgorithmException           异常
     * @throws IllegalBlockSizeException          异常
     * @throws BadPaddingException                异常
     * @throws NoSuchProviderException            异常
     * @throws InvalidAlgorithmParameterException 异常
     */
    public String encryptByBase64(String data, String key, String iv) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return Base64.getEncoder().encodeToString(encrypt(data.getBytes(), key.getBytes(), iv.getBytes()));
    }

    /**
     * base64解密
     *
     * @param data 带解密字符
     * @param key  秘钥
     * @param iv   向量
     * @return 解密后的字符
     * @throws NoSuchPaddingException             异常
     * @throws InvalidKeyException                异常
     * @throws NoSuchAlgorithmException           异常
     * @throws IllegalBlockSizeException          异常
     * @throws BadPaddingException                异常
     * @throws NoSuchProviderException            异常
     * @throws InvalidAlgorithmParameterException 异常
     */
    public String decryptByBase64(String data, String key, String iv) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return new String(decrypt(Base64.getDecoder().decode(data), key.getBytes(), iv.getBytes()));
    }

    private Cipher createCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        return new CipherHelper().createCipher(this.transformation);
    }
}
