package io.mosip.mimoto.util;

import lombok.extern.slf4j.Slf4j;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * This class provides Server IP and Name.
 *
 * @author Kiran Raj M1048860
 */
@Slf4j
public class ServerUtil {

    /** The server instance. */
    private static ServerUtil serverInstance = null;

    /** The host not found. */
    private String noHost = "HOST_NOT_FOUND";

    /**
     *
     * Instantiates a new server util.
     */
    private ServerUtil() {
        super();
    }

    /**
     * This method return singleton instance.
     *
     * @return The ServerUtil object
     */
    public static synchronized ServerUtil getServerUtilInstance() {

        if (serverInstance == null) {
            serverInstance = new ServerUtil();
            return serverInstance;
        } else {
            return serverInstance;
        }

    }

    /**
     * This method return ServerIp.
     *
     * @return The ServerIp
     *
     */
    public String getServerIp() {

        try {
            return InetAddress.getLocalHost().getHostAddress();
        } catch (UnknownHostException e) {
            log.error(noHost, e.getMessage());
            return "UNKNOWN-HOST";
        }

    }

    /**
     * This method return Server Host Name.
     *
     * @return The ServerName
     *
     */
    public String getServerName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            log.error(noHost, e.getMessage());
            return "UNKNOWN-HOST";
        }
    }

}
