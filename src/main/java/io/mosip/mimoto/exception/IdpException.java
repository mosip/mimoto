package io.mosip.mimoto.exception;

public class IdpException extends BaseUncheckedException {
    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    /**
     * Instantiates a new Idp exception.
     *
     */
    public IdpException() {
        super(PlatformErrorMessages.MIMOTO_IDP_GENERIC_EXCEPTION.getCode(),
                PlatformErrorMessages.MIMOTO_IDP_GENERIC_EXCEPTION.getMessage());
    }

    public IdpException(String message) {
        super(PlatformErrorMessages.MIMOTO_IDP_GENERIC_EXCEPTION.getCode(), message);
    }
}
