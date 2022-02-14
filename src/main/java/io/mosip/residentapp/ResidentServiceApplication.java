package io.mosip.residentapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.cache.CacheAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

import io.mosip.residentapp.service.impl.CbeffImpl;
import io.mosip.residentapp.spi.CbeffUtil;

@SpringBootApplication(
    scanBasePackages = {
        "io.mosip.residentapp.*",
        "${mosip.auth.adapter.impl.basepackage}"
    },
    exclude = {
        SecurityAutoConfiguration.class,
        DataSourceAutoConfiguration.class,
        HibernateJpaAutoConfiguration.class,
        CacheAutoConfiguration.class
    }
)
@EnableScheduling
@EnableAsync
public class ResidentServiceApplication {

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

    public static void main(String[] args) {
        SpringApplication.run(ResidentServiceApplication.class, args);
    }

}
