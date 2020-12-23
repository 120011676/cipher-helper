package com.github.qq120011676.rsa.autoconfigure;

import com.github.qq120011676.rsa.RSAHelper;
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
@ConditionalOnClass(RSAHelper.class)
@EnableConfigurationProperties(RSAHelperProperties.class)
public class RSAHelperAutoConfiguration {
    @Resource
    private RSAHelperProperties rsaHelperProperties;

    @Bean
    @ConditionalOnMissingBean(RSAHelper.class)
    public RSAHelper rsaHelper() throws IOException {
        RSAHelper rsaHelper = new RSAHelper();
        if (StringUtils.hasText(this.rsaHelperProperties.getPrivateKeyLocation())) {
            try (InputStream inputStream = new ClassPathResource(this.rsaHelperProperties.getPrivateKeyLocation()).getInputStream()) {
                if (StringUtils.hasText(this.rsaHelperProperties.getPrivateKeyPassword())) {
                    rsaHelper.setRSAPrivateKeyByPEM(inputStream, this.rsaHelperProperties.getPrivateKeyPassword());
                } else {
                    rsaHelper.setRSAPrivateKeyByPEM(inputStream);
                }
            }
        }
        if (StringUtils.hasText(this.rsaHelperProperties.getPublicKeyLocation())) {
            try (InputStream inputStream = new ClassPathResource(this.rsaHelperProperties.getPublicKeyLocation()).getInputStream()) {
                rsaHelper.setRSAPublicKeyByPEM(inputStream);
            }
        }
        rsaHelper.setTransformation(this.rsaHelperProperties.getTransformation());
        rsaHelper.setProvider(this.rsaHelperProperties.getProvider());
        return rsaHelper;
    }
}
