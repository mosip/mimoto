package io.mosip.mimoto.util;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;

import org.jboss.jandex.Main;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;

@Component
public class VersionInfo {
    @Autowired
    private BuildProperties buildProperties;

    @Value("${mosipbox.public.url}")
    private String mosipHost;

    @Value("${mosip.event.hubUrl}")
    private String websubUrl;

    private Properties gitProperties = new Properties();

    public final String[] DEFAULT_GIT_PROPERTIES = {
        "git.build.time",
        "git.branch",
        "git.tags",
        "git.commit.id.abbrev",
    };

    @PostConstruct
    public void initialize() {
        try {
            gitProperties.load(Main.class.getResourceAsStream("/git.properties"));;

        } catch (Exception e) {
            System.err.println("Error when trying to read git.properties file: " + e);
        }
        System.out.println("=".repeat(160));
        System.out.println(getBuildString());
        System.out.println(getServiceString());
        System.out.println("=".repeat(160));
    }

    public Map<String, Object> getVersionInfo() {
        Map<String, Object> versionInfo = new HashMap<String, Object>();

        Map<String, String> appInfo = new HashMap<String, String>();
        appInfo.put("name", buildProperties.getName());
        appInfo.put("version", buildProperties.getVersion());
        versionInfo.put("application", appInfo);

        Map<String, String> buildInfo = new HashMap<String, String>();
        for (String prop : DEFAULT_GIT_PROPERTIES) {
            buildInfo.put(prop, gitProperties.getProperty(prop));
        }
        versionInfo.put("build", buildInfo);

        Map<String, String> configInfo = new HashMap<String, String>();
        configInfo.put("mosip.host", mosipHost);
        configInfo.put("websub.url", websubUrl);
        versionInfo.put("config", configInfo);

        return versionInfo;
    }

    public String getBuildString() {
        return String.format(
                "%s build [version=%s, time=%s] | commit: %s @ branch: %s",
                buildProperties.getName(),
                buildProperties.getVersion(),
                buildProperties.getTime(),
                gitProperties.getProperty("git.commit.id.abbrev"),
                gitProperties.getProperty("git.branch")
        );
    }

    public String getServiceString() {
        return String.format(
                "MOSIP Host: %s | Websub URL: %s",
                mosipHost,
                websubUrl
        );
    }
}
