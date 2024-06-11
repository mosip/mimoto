package io.mosip.mimoto;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.biometrics.spi.CbeffUtil;
import io.mosip.kernel.cbeffutil.impl.CbeffImpl;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.mimoto.util.LoggerUtil;
import org.json.simple.JSONObject;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.cache.CacheAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;


@SpringBootApplication(scanBasePackages = {
        "io.mosip.mimoto.*",
        "${mosip.auth.adapter.impl.basepackage}"
}, exclude = {
        SecurityAutoConfiguration.class,
        DataSourceAutoConfiguration.class,
        HibernateJpaAutoConfiguration.class,
        CacheAutoConfiguration.class
})
@EnableScheduling
@EnableAsync
@Import({io.mosip.kernel.websub.api.config.WebSubClientConfig.class,
        io.mosip.kernel.websub.api.config.publisher.WebSubPublisherClientConfig.class,
        io.mosip.kernel.websub.api.config.publisher.RestTemplateHelper.class
})
public class MimotoServiceApplication {

    private static Logger logger = LoggerUtil.getLogger(MimotoServiceApplication.class);

    @Bean
    @Primary
    public CbeffUtil getCbeffUtil() {
        return new CbeffImpl();
    }

    @Bean
    public ThreadPoolTaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler threadPoolTaskScheduler = new ThreadPoolTaskScheduler();
        threadPoolTaskScheduler.setPoolSize(5);
        threadPoolTaskScheduler.setThreadNamePrefix("ThreadPoolTaskScheduler");
        return threadPoolTaskScheduler;
    }

    public static JSONObject getGitProp() {
        try {
            return (new ObjectMapper()).readValue(
                MimotoServiceApplication.class.getClassLoader().getResourceAsStream("build.json"),
                JSONObject.class
            );
        } catch (Exception e) {
            logger.error("Error when trying to read build.json file: " + e);
        }
        return new JSONObject();
    }

    public static void main(String[] args) {
        JSONObject gitProp = getGitProp();
        logger.info(
                String.format(
                        "Mimoto Service version: %s - revision: %s @ branch: %s | build @ %s",
                        gitProp.get("git.build.version"),
                        gitProp.get("git.commit.id.abbrev"),
                        gitProp.get("git.branch"),
                        gitProp.get("git.build.time")));
        SpringApplication.run(MimotoServiceApplication.class, args);
    }

}
