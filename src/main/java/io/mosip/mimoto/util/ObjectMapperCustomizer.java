package io.mosip.mimoto.util;

import com.fasterxml.jackson.core.json.JsonWriteFeature;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ObjectMapperCustomizer {

    @Bean
    public Jackson2ObjectMapperBuilderCustomizer customizeJackson() {
        return builder -> builder.featuresToEnable(JsonWriteFeature.ESCAPE_NON_ASCII.mappedFeature());
    }
}
