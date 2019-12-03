package com.github.qq120011676.rsa.autoconfigure;

import com.github.qq120011676.rsa.RSAUHelper;
import com.github.qq120011676.rsa.properties.RSAHelperProperties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

@Configuration
@ConditionalOnClass(RSAUHelper.class)
@EnableConfigurationProperties(RSAHelperProperties.class)
public class RSAHelperAutoConfiguration {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Resource
    private RSAHelperProperties rsaHelperProperties;

    @Bean
    @ConditionalOnMissingBean(RSAUHelper.class)
    public RSAUHelper rsauHelper() throws IOException, NoSuchAlgorithmException {
        RSAUHelper rsauHelper = new RSAUHelper();
        if (StringUtils.hasText(this.rsaHelperProperties.getPrivateKeyLocation())) {
            String path = new ClassPathResource(this.rsaHelperProperties.getPrivateKeyLocation()).getPath();
            if (StringUtils.hasText(this.rsaHelperProperties.getPrivateKeyPassword())) {
                rsauHelper.setRSAPrivateKeyByPEM(path, this.rsaHelperProperties.getPrivateKeyPassword());
            } else {
                rsauHelper.setRSAPrivateKeyByPEM(path);
            }
        }
        if (StringUtils.hasText(this.rsaHelperProperties.getPublicKeyLocation())) {
            String path = new ClassPathResource(this.rsaHelperProperties.getPublicKeyLocation()).getPath();
            rsauHelper.setRSAPublicKeyByPEM(path);
        }
        rsauHelper.setTransformation(this.rsaHelperProperties.getTransformation());
        rsauHelper.setProvider(this.rsaHelperProperties.getProvider());
        return rsauHelper;
    }
}
