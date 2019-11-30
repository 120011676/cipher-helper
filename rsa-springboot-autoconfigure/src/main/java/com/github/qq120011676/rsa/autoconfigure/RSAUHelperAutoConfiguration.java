package com.github.qq120011676.rsa.autoconfigure;

import com.github.qq120011676.rsa.RSAUHelper;
import com.github.qq120011676.rsa.properties.RSAUHelperProperties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import javax.annotation.Resource;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Security;
import java.util.Base64;

@Configuration
@ConditionalOnClass(RSAUHelper.class)
@EnableConfigurationProperties(RSAUHelperProperties.class)
public class RSAUHelperAutoConfiguration {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Resource
    private RSAUHelperProperties payProperties;
    @Resource
    private ApplicationContext applicationContext;

    @Bean
    @ConditionalOnMissingBean(RSAUHelper.class)
    public RSAUHelper rsauHelper() {
        return new RSAUHelper();
    }

    private String readPEM(String filepath) {
        try (PemReader pemObject = new PemReader(new InputStreamReader((new ClassPathResource(filepath).getInputStream())))) {
            return Base64.getEncoder().encodeToString(pemObject.readPemObject().getContent());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
