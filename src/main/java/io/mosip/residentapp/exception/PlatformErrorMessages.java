
package io.mosip.residentapp.exception;

// TODO: Auto-generated Javadoc
/**
 * The Enum PlatformErrorMessages.
 *
 * @author M1047487
 */
public enum PlatformErrorMessages {

    /** The applicant photo not set. */
    RESIDENT_APP_APPLICANT_PHOTO_NOT_SET(PlatformConstants.PREFIX + "006", "Error while setting applicant photo"),
    /** The qrcode not set. */
    RESIDENT_APP_QRCODE_NOT_SET(PlatformConstants.PREFIX + "007", "Error while setting qrCode for uin card"),
    /** VC decryption failed. */
    RESIDENT_APP_VC_DECRYPTION_FAILED(PlatformConstants.PREFIX + "004", "Verifiable Credential failed to decrypt"),
    /** The document generation failed. */
    RESIDENT_APP_DOCUMENT_GENERATION_FAILED(PlatformConstants.PREFIX + "010", "Document Generation Failed"),
    /** The pdf generation failed. */
    RESIDENT_APP_PDF_GENERATION_FAILED(PlatformConstants.PREFIX + "003", "PDF Generation Failed"),
    /** The qrcode not generated. */
    RESIDENT_APP_QRCODE_NOT_GENERATED(PlatformConstants.PREFIX + "005", "Error while generating QR Code"),
    /** The qr code generation error. */
    RESIDENT_APP_QR_CODE_GENERATION_ERROR(PlatformConstants.PREFIX + "022", "Error while QR Code Generation"),

    /** The vid creation error. */
    RESIDENT_APP_VID_CREATION_ERROR(PlatformConstants.PREFIX + "023", "Error while creating VID"),

    /** The vid exception. */
    RESIDENT_APP_VID_EXCEPTION(PlatformConstants.PREFIX + "018",
            "Could not generate/regenerate VID as per policy,Please use existing VID"),
    // Printing stage exceptions
    RESIDENT_APP_PDF_NOT_GENERATED(PlatformConstants.PREFIX + "001", "Error while generating PDF for UIN Card"),
    /** The rgs json parsing exception. */
    RESIDENT_APP_RGS_JSON_PARSING_EXCEPTION(PlatformConstants.PREFIX + "017", "JSON Parsing Failed"),
    /** The invalid input parameter. */
    RESIDENT_APP_PGS_INVALID_INPUT_PARAMETER(PlatformConstants.PREFIX + "011", "Invalid Input Parameter - %s"),
    /** The rgs json mapping exception. */
    RESIDENT_APP_RGS_JSON_MAPPING_EXCEPTION(PlatformConstants.PREFIX + "016", "JSON Mapping Failed"),
    RESIDENT_APP_PDF_SIGNATURE_EXCEPTION(PlatformConstants.PREFIX + "024", "PDF Signature error"),
    /** The pvm invalid uin. */
    RESIDENT_APP_PVM_INVALID_UIN(PlatformConstants.PREFIX + "012", "Invalid UIN"),
    /** The rct unknown resource exception. */
    RESIDENT_APP_RCT_UNKNOWN_RESOURCE_EXCEPTION(PlatformConstants.PREFIX + "001", "Unknown resource provided"),
    /** The utl digital sign exception. */
    RESIDENT_APP_UTL_DIGITAL_SIGN_EXCEPTION(PlatformConstants.PREFIX + "003", "Failed to generate digital signature"),
    /** The utl biometric tag match. */
    RESIDENT_APP_UTL_BIOMETRIC_TAG_MATCH(PlatformConstants.PREFIX + "001", "Both Files have same biometrics"),
    /** The uin not found in database. */
    RESIDENT_APP_UIN_NOT_FOUND_IN_DATABASE(PlatformConstants.PREFIX + "002", "UIN not found in database"),
    /** The bdd abis abort. */
    RESIDENT_APP_BDD_ABIS_ABORT(PlatformConstants.PREFIX + "002",
            "ABIS for the Reference ID and Request ID was Abort"),
    /** The tem processing failure. */
    RESIDENT_APP_TEM_PROCESSING_FAILURE(PlatformConstants.PREFIX + "002", "The Processing of Template Failed "),
    RESIDENT_APP_SYS_JSON_PARSING_EXCEPTION(PlatformConstants.PREFIX + "009", "Error while parsing Json"),
    RESIDENT_APP_AUT_INVALID_TOKEN(PlatformConstants.PREFIX + "01", "Invalid Token Present"),
    /** The cmb unsupported encoding. */
    RESIDENT_APP_CMB_UNSUPPORTED_ENCODING(PlatformConstants.PREFIX + "002", "Unsupported Failure"),
    /** The sys no such field exception. */
    RESIDENT_APP_SYS_NO_SUCH_FIELD_EXCEPTION(PlatformConstants.PREFIX + "008", "Could not find the field"),

    /** The sys instantiation exception. */
    RESIDENT_APP_SYS_INSTANTIATION_EXCEPTION(PlatformConstants.PREFIX + "007",
            "Error while creating object of JsonValue class"),

    RESIDENT_APP_PIS_IDENTITY_NOT_FOUND(PlatformConstants.PREFIX + "002",
            "Unable to Find Identity Field in ID JSON"),
    /** Access denied for the token present. */
    RESIDENT_APP_AUT_ACCESS_DENIED(PlatformConstants.PREFIX + "02", "Access Denied For Role - %s"),
    DATASHARE_EXCEPTION(PlatformConstants.PREFIX + "025", "Data share api failure"),
    API_NOT_ACCESSIBLE_EXCEPTION(PlatformConstants.PREFIX + "026", "Api not accessible failure"),
    CERTIFICATE_THUMBPRINT_ERROR(PlatformConstants.PREFIX + "026", "certificate thumbprint failure"),
    RESIDENT_APP_INVALID_KEY_EXCEPTION(PlatformConstants.PREFIX + "027", "invalid key"),
    RESIDENT_APP_PDF_SIGN_EXCEPTION(PlatformConstants.PREFIX + "028", "error occured while signing pdf");

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