package io.mosip.residentapp.exception;

public class ApiNotAccessibleException extends BaseCheckedException {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    public ApiNotAccessibleException() {
        super(PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION.getCode(),
                PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION.getMessage());
    }

    public ApiNotAccessibleException(String message) {
        super(PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION.getCode(),
                message);
    }

    public ApiNotAccessibleException(Throwable e) {
        super(PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION.getCode(),
                PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION.getMessage(), e);
    }

    public ApiNotAccessibleException(String errorMessage, Throwable t) {
        super(PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION.getCode(), errorMessage, t);
    }

}
