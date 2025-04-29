package io.mosip.mimoto;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.biometrics.spi.CbeffUtil;
import io.mosip.kernel.cbeffutil.impl.CbeffImpl;
import io.mosip.kernel.keygenerator.bouncycastle.KeyGenerator;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;


@SpringBootApplication(scanBasePackages = {
        "io.mosip.mimoto.*",
        "io.mosip.mimoto.dbentity",
        "io.mosip.kernel.websub.*",
        "io.mosip.kernel.cryptomanager.*",
        "io.mosip.kernel.keymanager.*",
        "io.mosip.kernel.keymanagerservice.helper",
        "io.mosip.kernel.keymanagerservice.util",
        "io.mosip.kernel.keymanagerservice.service",
        "io.mosip.kernel.keymanagerservice.validator",
        "io.mosip.kernel.crypto",
        "${mosip.auth.adapter.impl.basepackage}"
}, exclude = {
        SecurityAutoConfiguration.class
})
@EntityScan(basePackages = {"io.mosip.mimoto.dbentity", "io.mosip.kernel.keymanagerservice.entity"})
@EnableJpaRepositories(basePackages = {"io.mosip.mimoto.repository", "io.mosip.kernel.keymanagerservice.repository"})
@Slf4j
@EnableScheduling
@EnableAsync
@SecurityScheme(
        name = "SessionAuth",
        type = SecuritySchemeType.APIKEY,
        in = SecuritySchemeIn.COOKIE,
        paramName = "SESSION",
        description = "Session-based authentication using a session ID stored in the cookie. The client must send the 'SESSION' cookie (e.g., SESSION=<session-id>) with each request."
)
public class MimotoServiceApplication {

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

    @Bean
    public KeyGenerator keyGenerator() {
        return new KeyGenerator();
    }

    public static JSONObject getGitProp() {
        try {
            return (new ObjectMapper()).readValue(
                MimotoServiceApplication.class.getClassLoader().getResourceAsStream("build.json"),
                JSONObject.class
            );
        } catch (Exception e) {
            log.error("Error when trying to read build.json file: " + e);
        }
        return new JSONObject();
    }

    public static void main(String[] args) {
        JSONObject gitProp = getGitProp();
        log.info(
                String.format(
                        "Mimoto Service version: %s - revision: %s @ branch: %s | build @ %s",
                        gitProp.get("git.build.version"),
                        gitProp.get("git.commit.id.abbrev"),
                        gitProp.get("git.branch"),
                        gitProp.get("git.build.time")));
        SpringApplication.run(MimotoServiceApplication.class, args);
    }

}
