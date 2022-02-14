package io.mosip.residentapp.util;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.logger.logback.factory.Logfactory;

/**
 * The Class LoggerUtil.
 * 
 * @author : Rishabh Keshari
 */
public final class LoggerUtil {

    private LoggerUtil() {
    }

    /**
     * Gets the logger.
     *
     * @param clazz the clazz
     * @return the logger
     */
    public static Logger getLogger(Class<?> clazz) {
        return Logfactory.getSlf4jLogger(clazz);
    }
}
