package com.github.qq120011676.rsa.autoconfigure;

import com.github.qq120011676.rsa.RSAUHelper;
import com.github.qq120011676.rsa.properties.RSAHelperProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;
import java.io.IOException;
import java.io.InputStream;

@Configuration
@ConditionalOnClass(RSAUHelper.class)
@EnableConfigurationProperties(RSAHelperProperties.class)
public class RSAHelperAutoConfiguration {
    @Resource
    private RSAHelperProperties rsaHelperProperties;

    @Bean
    @ConditionalOnMissingBean(RSAUHelper.class)
    public RSAUHelper rsauHelper() throws IOException {
        RSAUHelper rsauHelper = new RSAUHelper();
        if (StringUtils.hasText(this.rsaHelperProperties.getPrivateKeyLocation())) {
            try (InputStream inputStream = new ClassPathResource(this.rsaHelperProperties.getPrivateKeyLocation()).getInputStream()) {
                if (StringUtils.hasText(this.rsaHelperProperties.getPrivateKeyPassword())) {
                    rsauHelper.setRSAPrivateKeyByPEM(inputStream, this.rsaHelperProperties.getPrivateKeyPassword());
                } else {
                    rsauHelper.setRSAPrivateKeyByPEM(inputStream);
                }
            }
        }
        if (StringUtils.hasText(this.rsaHelperProperties.getPublicKeyLocation())) {
            try (InputStream inputStream = new ClassPathResource(this.rsaHelperProperties.getPublicKeyLocation()).getInputStream()) {
                rsauHelper.setRSAPublicKeyByPEM(inputStream);
            }
        }
        rsauHelper.setTransformation(this.rsaHelperProperties.getTransformation());
        rsauHelper.setProvider(this.rsaHelperProperties.getProvider());
        return rsauHelper;
    }
}
