package io.mosip.residentapp.exception;

public class UINNotFoundInDatabase extends BaseUncheckedException {

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    /**
     * Instantiates a new file not found in destination exception.
     */
    public UINNotFoundInDatabase() {
        super();

    }

    /**
     * Instantiates a new file not found in destination exception.
     *
     * @param errorMessage the error message
     */
    public UINNotFoundInDatabase(String errorMessage) {
        super(PlatformErrorMessages.RESIDENT_APP_UIN_NOT_FOUND_IN_DATABASE.getCode(), errorMessage);
    }

    /**
     * Instantiates a new file not found in destination exception.
     *
     * @param message the message
     * @param cause   the cause
     */
    public UINNotFoundInDatabase(String message, Throwable cause) {
        super(PlatformErrorMessages.RESIDENT_APP_UIN_NOT_FOUND_IN_DATABASE.getCode() + EMPTY_SPACE, message, cause);

    }
}
