package com.github.qq120011676.rsa.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "rsa")
public class RSAHelperProperties {
    private String publicKeyLocation = "rsa/app-public.pem";
    private String privateKeyLocation = "rsa/app-private.pem";
    private String privateKeyPassword;
    private String transformation = "RSA/NONE/OAEPPadding";
    private String provider;
}
