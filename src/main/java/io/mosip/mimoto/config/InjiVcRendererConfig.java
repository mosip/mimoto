package io.mosip.mimoto.config;

import io.mosip.injivcrenderer.InjiVcRenderer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class InjiVcRendererConfig {
    @Bean
    public InjiVcRenderer injiVcRenderer() {
        return new InjiVcRenderer();
    }
}