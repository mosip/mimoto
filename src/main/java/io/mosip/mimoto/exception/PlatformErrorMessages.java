
package io.mosip.mimoto.exception;

// TODO: Auto-generated Javadoc
/**
 * The Enum PlatformErrorMessages.
 *
 * @author M1047487
 */
public enum PlatformErrorMessages {

    /** The applicant photo not set. */
    MIMOTO_APPLICANT_PHOTO_NOT_SET(PlatformConstants.PREFIX + "006", "Error while setting applicant photo"),
    /** The qrcode not set. */
    MIMOTO_QRCODE_NOT_SET(PlatformConstants.PREFIX + "007", "Error while setting qrCode for uin card"),
    /** VC decryption failed. */
    MIMOTO_VC_DECRYPTION_FAILED(PlatformConstants.PREFIX + "004", "Verifiable Credential failed to decrypt"),
    /** The document generation failed. */
    MIMOTO_DOCUMENT_GENERATION_FAILED(PlatformConstants.PREFIX + "010", "Document Generation Failed"),
    /** The pdf generation failed. */
    MIMOTO_PDF_GENERATION_FAILED(PlatformConstants.PREFIX + "003", "PDF Generation Failed"),
    /** The qrcode not generated. */
    MIMOTO_QRCODE_NOT_GENERATED(PlatformConstants.PREFIX + "005", "Error while generating QR Code"),
    /** The qr code generation error. */
    MIMOTO_QR_CODE_GENERATION_ERROR(PlatformConstants.PREFIX + "022", "Error while QR Code Generation"),

    /** The vid creation error. */
    MIMOTO_VID_CREATION_ERROR(PlatformConstants.PREFIX + "023", "Error while creating VID"),

    /** The vid exception. */
    MIMOTO_VID_EXCEPTION(PlatformConstants.PREFIX + "018",
            "Could not generate/regenerate VID as per policy,Please use existing VID"),
    // Printing stage exceptions
    MIMOTO_PDF_NOT_GENERATED(PlatformConstants.PREFIX + "001", "Error while generating PDF for UIN Card"),
    /** The rgs json parsing exception. */
    MIMOTO_RGS_JSON_PARSING_EXCEPTION(PlatformConstants.PREFIX + "017", "JSON Parsing Failed"),
    /** The invalid input parameter. */
    MIMOTO_PGS_INVALID_INPUT_PARAMETER(PlatformConstants.PREFIX + "011", "Invalid Input Parameter"),
    /** The rgs json mapping exception. */
    MIMOTO_RGS_JSON_MAPPING_EXCEPTION(PlatformConstants.PREFIX + "016", "JSON Mapping Failed"),
    MIMOTO_PDF_SIGNATURE_EXCEPTION(PlatformConstants.PREFIX + "024", "PDF Signature error"),
    /** The pvm invalid uin. */
    MIMOTO_PVM_INVALID_UIN(PlatformConstants.PREFIX + "012", "Invalid UIN"),
    /** The rct unknown resource exception. */
    MIMOTO_RCT_UNKNOWN_RESOURCE_EXCEPTION(PlatformConstants.PREFIX + "001", "Unknown resource provided"),
    /** The utl digital sign exception. */
    MIMOTO_UTL_DIGITAL_SIGN_EXCEPTION(PlatformConstants.PREFIX + "003", "Failed to generate digital signature"),
    /** The utl biometric tag match. */
    MIMOTO_UTL_BIOMETRIC_TAG_MATCH(PlatformConstants.PREFIX + "001", "Both Files have same biometrics"),
    /** The uin not found in database. */
    MIMOTO_UIN_NOT_FOUND_IN_DATABASE(PlatformConstants.PREFIX + "002", "UIN not found in database"),
    /** The bdd abis abort. */
    MIMOTO_BDD_ABIS_ABORT(PlatformConstants.PREFIX + "002",
            "ABIS for the Reference ID and Request ID was Abort"),
    /** The tem processing failure. */
    MIMOTO_TEM_PROCESSING_FAILURE(PlatformConstants.PREFIX + "002", "The Processing of Template Failed "),
    MIMOTO_SYS_JSON_PARSING_EXCEPTION(PlatformConstants.PREFIX + "009", "Error while parsing Json"),
    MIMOTO_AUT_INVALID_TOKEN(PlatformConstants.PREFIX + "01", "Invalid Token Present"),
    /** The cmb unsupported encoding. */
    MIMOTO_CMB_UNSUPPORTED_ENCODING(PlatformConstants.PREFIX + "002", "Unsupported Failure"),
    /** The sys no such field exception. */
    MIMOTO_SYS_NO_SUCH_FIELD_EXCEPTION(PlatformConstants.PREFIX + "008", "Could not find the field"),

    /** The sys instantiation exception. */
    MIMOTO_SYS_INSTANTIATION_EXCEPTION(PlatformConstants.PREFIX + "007",
            "Error while creating object of JsonValue class"),

    MIMOTO_PIS_IDENTITY_NOT_FOUND(PlatformConstants.PREFIX + "002",
            "Unable to Find Identity Field in ID JSON"),
    /** Access denied for the token present. */
    MIMOTO_AUT_ACCESS_DENIED(PlatformConstants.PREFIX + "02", "Access Denied For Role - %s"),
    DATASHARE_EXCEPTION(PlatformConstants.PREFIX + "025", "Data share api failure"),
    API_NOT_ACCESSIBLE_EXCEPTION(PlatformConstants.PREFIX + "026", "Api not accessible failure"),
    CERTIFICATE_THUMBPRINT_ERROR(PlatformConstants.PREFIX + "026", "certificate thumbprint failure"),
    MIMOTO_INVALID_KEY_EXCEPTION(PlatformConstants.PREFIX + "027", "invalid key"),
    MIMOTO_PDF_SIGN_EXCEPTION(PlatformConstants.PREFIX + "028", "error occured while signing pdf"),
    MIMOTO_WALLET_BINDING_EXCEPTION(PlatformConstants.PREFIX + "028", "Wallet binding exception occured"),
    MIMOTO_OTP_BINDING_EXCEPTION(PlatformConstants.PREFIX + "029", "OTP binding exception occured"),
    MIMOTO_LINK_TRANSACTION_EXCEPTION(PlatformConstants.PREFIX + "030", "Idp link transaction exception occured"),
    MIMOTO_IDP_AUTHENTICATE_EXCEPTION(PlatformConstants.PREFIX + "031", "Idp authenticate exception occured"),
    MIMOTO_IDP_CONSENT_EXCEPTION(PlatformConstants.PREFIX + "032", "Idp consent exception occured"),
    MIMOTO_IDP_OTP_EXCEPTION(PlatformConstants.PREFIX + "033", "IDP Otp error occured"),
    MIMOTO_IDP_GENERIC_EXCEPTION(PlatformConstants.PREFIX + "034", "Could not get response from server"),
    INVALID_ISSUER_ID_EXCEPTION(PlatformConstants.PREFIX + "035", "Invalid issuer ID"),
    INVALID_CREDENTIAL_TYPE_EXCEPTION(PlatformConstants.PREFIX + "036", "Invalid Credential Type Id"),
    MIMOTO_ISSUER_ONBOARDING_EXCEPTION(PlatformConstants.PREFIX + "037", "Issuers Onboarding exception occurred "),
    INVALID_VERIFIER_ID_EXCEPTION(PlatformConstants.PREFIX + "038", "Invalid Verifier ClientId"),
    INVALID_VERIFIER_REDIRECT_URI_EXCEPTION(PlatformConstants.PREFIX + "039", "Invalid Redirect Uri"),
    INVALID_CREDENTIAL_RESOURCE_URI_EXCEPTION(PlatformConstants.PREFIX + "040", "The Credential Resource is Invalid"),
    INVALID_CREDENTIAL_ISSUER_WELLKNOWN_RESPONSE_EXCEPTION(PlatformConstants.PREFIX + "041", "Invalid Wellknown from Issuer"),
    INVALID_AUTHORIZATION_SERVER_WELLKNOWN_RESPONSE_EXCEPTION(PlatformConstants.PREFIX + "042", "Invalid Authorization Server well-known from server:");


    /** The error message. */
    private final String errorMessage;

    /** The error code. */
    private final String errorCode;

    /**
     * Instantiates a new platform error messages.
     *
     * @param errorCode
     *                  the error code
     * @param errorMsg
     *                  the error msg
     */
    private PlatformErrorMessages(String errorCode, String errorMsg) {
        this.errorCode = errorCode;
        this.errorMessage = errorMsg;
    }

    /**
     * Gets the error message.
     *
     * @return the error message
     */
    public String getMessage() {
        return this.errorMessage;
    }

    /**
     * Gets the error code.
     *
     * @return the error code
     */
    public String getCode() {
        return this.errorCode;
    }

}

