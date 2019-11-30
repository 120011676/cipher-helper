package com.github.qq120011676.rsa.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "rsa")
public class RSAUHelperProperties {
    private String publicKeyLocation = "rsa/app.pub";
    private String privateKeyLocation = "rsa/app";

}
