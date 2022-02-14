package io.mosip.residentapp.exception;

public class DataShareException extends BaseCheckedException {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    public DataShareException() {
        super(PlatformErrorMessages.DATASHARE_EXCEPTION.getCode(),
                PlatformErrorMessages.DATASHARE_EXCEPTION.getMessage());
    }

    public DataShareException(String message) {
        super(PlatformErrorMessages.DATASHARE_EXCEPTION.getCode(),
                message);
    }

    public DataShareException(Throwable e) {
        super(PlatformErrorMessages.DATASHARE_EXCEPTION.getCode(),
                PlatformErrorMessages.DATASHARE_EXCEPTION.getMessage(), e);
    }

    public DataShareException(String errorMessage, Throwable t) {
        super(PlatformErrorMessages.DATASHARE_EXCEPTION.getCode(), errorMessage, t);
    }

}
