package com.github.qq120011676.rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * AES 加解密
 */
public class AesHelper {
    private static final String ALGORITHM = "AES";
    private static final String AES_CFB_PKCS_5_PADDING = "AES/CFB/PKCS5Padding";

    /**
     * 加密
     *
     * @param data 带加密字节
     * @param key  秘钥
     * @param iv   向量
     * @return 加密后的字节
     * @throws NoSuchPaddingException             异常
     * @throws NoSuchAlgorithmException           异常
     * @throws InvalidAlgorithmParameterException 异常
     * @throws InvalidKeyException                异常
     * @throws BadPaddingException                异常
     * @throws IllegalBlockSizeException          异常
     */
    public static byte[] encrypt(byte[] data, byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(AES_CFB_PKCS_5_PADDING);
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
     * @throws NoSuchAlgorithmException           异常
     * @throws InvalidAlgorithmParameterException 异常
     * @throws InvalidKeyException                异常
     * @throws BadPaddingException                异常
     * @throws IllegalBlockSizeException          异常
     */
    public static byte[] decrypt(byte[] data, byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(AES_CFB_PKCS_5_PADDING);
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
     * @throws NoSuchAlgorithmException           异常
     * @throws InvalidAlgorithmParameterException 异常
     * @throws InvalidKeyException                异常
     * @throws BadPaddingException                异常
     * @throws IllegalBlockSizeException          异常
     */
    public static String encryptByBase64(String data, String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
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
     * @throws NoSuchAlgorithmException           异常
     * @throws InvalidAlgorithmParameterException 异常
     * @throws InvalidKeyException                异常
     * @throws BadPaddingException                异常
     * @throws IllegalBlockSizeException          异常
     */
    public static String decryptByBase64(String data, String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return new String(decrypt(Base64.getDecoder().decode(data), key.getBytes(), iv.getBytes()));
    }
}
