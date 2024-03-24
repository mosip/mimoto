package io.mosip.mimoto.exception;

public class IssuerOnboardingException extends BaseUncheckedException{

    private static final long serialVersionUID = 1L;

    public IssuerOnboardingException(String errorMessage) {
        super(PlatformErrorMessages.MIMOTO_ISSUER_ONBOARDING_EXCEPTION.getCode(), errorMessage);
    }

}
