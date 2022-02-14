package io.mosip.residentapp.exception;

public class BiometricTagMatchException extends BaseUncheckedException {

  /**
   * The Constant serialVersionUID.
   */
  private static final long serialVersionUID = 1L;

  /**
   * Instantiates a new field not found exception.
   */
  public BiometricTagMatchException() {
    super();
  }

  /**
   * Instantiates a new field not found exception.
   *
   * @param errorMessage the error message
   */
  public BiometricTagMatchException(String errorMessage) {
    super(PlatformErrorMessages.RESIDENT_APP_UTL_BIOMETRIC_TAG_MATCH.getCode() + EMPTY_SPACE, errorMessage);
  }

  /**
   * Instantiates a new field not found exception.
   *
   * @param message the message
   * @param cause   the cause
   */
  public BiometricTagMatchException(String message, Throwable cause) {
    super(PlatformErrorMessages.RESIDENT_APP_UTL_BIOMETRIC_TAG_MATCH.getCode() + EMPTY_SPACE, message, cause);
  }
}