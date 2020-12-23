package com.github.qq120011676.utils;

import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Cipher帮助类
 */
public class CipherHelper {
    /**
     * 创建加解密对象
     *
     * @param transformation 加解密方式
     * @param provider       供应商
     * @return 加解密对象
     * @throws NoSuchPaddingException   异常
     * @throws NoSuchAlgorithmException 异常
     * @throws NoSuchProviderException  异常
     */
    public Cipher createCipher(String transformation, String provider) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        if (StringUtils.isNotBlank(provider)) {
            return Cipher.getInstance(transformation, provider);
        } else {
            return Cipher.getInstance(transformation);
        }
    }

    /**
     * 创建加解密对象
     *
     * @param transformation 加解密方式
     * @return 加解密对象
     * @throws NoSuchPaddingException   异常
     * @throws NoSuchAlgorithmException 异常
     * @throws NoSuchProviderException  异常
     */
    public Cipher createCipher(String transformation) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        return createCipher(transformation, null);
    }
}
