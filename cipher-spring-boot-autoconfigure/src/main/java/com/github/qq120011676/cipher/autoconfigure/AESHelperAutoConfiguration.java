package com.github.qq120011676.cipher.autoconfigure;

import com.github.qq120011676.cipher.AESHelper;
import com.github.qq120011676.cipher.properties.AESHelperProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;

/**
 * 自动注入AESHelper类
 */
@Configuration
@ConditionalOnClass(AESHelper.class)
@EnableConfigurationProperties(AESHelperProperties.class)
public class AESHelperAutoConfiguration {
    @Resource
    private AESHelperProperties aesHelperProperties;

    /**
     * 自动注入AESHelper对象
     *
     * @return AESHelper
     */
    @Bean
    @ConditionalOnMissingBean(AESHelper.class)
    public AESHelper aesHelper() {
        AESHelper aesHelper = new AESHelper();
        if (StringUtils.hasText(this.aesHelperProperties.getTransformation())) {
            aesHelper.setTransformation(this.aesHelperProperties.getTransformation());
        }
        return aesHelper;
    }
}
