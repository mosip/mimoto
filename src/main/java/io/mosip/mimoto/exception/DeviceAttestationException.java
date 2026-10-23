package io.mosip.mimoto.exception;

import java.io.Serial;

/**
 * Raised when a device registration or device proof is rejected. The error code is one of the
 * device-related {@link ErrorConstants} and is returned to the caller; the message is for logs.
 */
public class DeviceAttestationException extends BaseUncheckedException {

    @Serial
    private static final long serialVersionUID = 1L;

    public DeviceAttestationException(ErrorConstants error, String detail) {
        super(error.getErrorCode(), detail);
    }

    public DeviceAttestationException(ErrorConstants error, String detail, Throwable cause) {
        super(error.getErrorCode(), detail, cause);
    }
}
