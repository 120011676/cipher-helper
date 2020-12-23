package com.github.qq120011676.cipher.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 自动注入RSAHelper配置类
 */
@Data
@ConfigurationProperties(prefix = "cipher.aes")
public class AESHelperProperties {
    private String transformation = "AES/CFB/PKCS5Padding";
}
