package io.mosip.mimoto.constant;

public class SwaggerLiteralConstants {

    /*  Attestation Controller */
    public static final String ATTESTATION_NAME = "Attestation" ;
    public static final String ATTESTATION_DESCRIPTION = "All the Attestation Related Endpoints" ;


    /*  Common Inji Controller */
    public static final String COMMON_INJI_NAME = "Properties" ;
    public static final String COMMON_INJI_DESCRIPTION = "All the Inji Wallet properties Related Endpoints" ;
    public static final String COMMON_INJI_GET_PROPERTIES_SUMMARY = "Retrieve All Inji Wallet properties" ;
    public static final String COMMON_INJI_GET_PROPERTIES_DESCRIPTION = "This endpoint allow you to retrieve all the Inji Wallet properties" ;

    /*  Credentials Controller */
    public static final String CREDENTIALS_NAME = "Credentials download using OpenId4VCI" ;
    public static final String CREDENTIALS_DESCRIPTION = "All the Credentials Related Endpoints" ;
    public static final String CREDENTIALS_DOWNLOAD_VC_SUMMARY = "Download credentials as PDF" ;
    public static final String CREDENTIALS_DOWNLOAD_VC_DESCRIPTION = "This endpoint allow you to download the credentials as PDF" ;

    /*  Credentials Share Controller */
    public static final String CREDENTIALS_SHARE_NAME = "Credential Share" ;
    public static final String CREDENTIALS_SHARE_DESCRIPTION = "All the credential download Endpoints" ;
    public static final String CREDENTIALS_SHARE_HANDLE_SUBSCRIBED_EVENT_SUMMARY = "Notify through Web Sub once Credential is downloaded" ;
    public static final String CREDENTIALS_SHARE_HANDLE_SUBSCRIBED_EVENT_DESCRIPTION = "This endpoint allow Web Sub to callback once the credential is issued" ;
    public static final String CREDENTIALS_SHARE_REQUEST_VC_SUMMARY = "request for credential issue" ;
    public static final String CREDENTIALS_SHARE_REQUEST_VC_DESCRIPTION = "This endpoint allow you to request for credential issue" ;
    public static final String CREDENTIALS_SHARE_REQUEST_VC_STATUS_SUMMARY = "polling for credential issue status" ;
    public static final String CREDENTIALS_SHARE_REQUEST_VC_STATUS_DESCRIPTION = "This endpoint allow you to poll for credential issue status" ;
    public static final String CREDENTIALS_SHARE_DOWNLOAD_VC_SUMMARY = "Download the credential using OTP Flow" ;
    public static final String CREDENTIALS_SHARE_DOWNLOAD_VC_DESCRIPTION = "This endpoint allow you to download credential issued" ;

    /*  IDP Controller */
    public static final String IDP_NAME = "Wallet Binding" ;
    public static final String IDP_DESCRIPTION = "All the Authorization Related Endpoints" ;
    public static final String IDP_BINDING_OTP_SUMMARY = "Invoke OTP Request for Wallet Binding" ;
    public static final String IDP_BINDING_OTP_DESCRIPTION = "This endpoint allow you to invoke OTP for wallet binding" ;
    public static final String IDP_WALLET_BINDING_SUMMARY = "Wallet Binding" ;
    public static final String IDP_WALLET_BINDING_DESCRIPTION = "This endpoint allow you to perform the wallet binding" ;
    public static final String IDP_GET_TOKEN_SUMMARY = "Retrieve AccessToken for OIDC Flow" ;
    public static final String IDP_GET_TOKEN_DESCRIPTION = "This endpoint allow you to retrieve the access token in exchange for authorization Code" ;

    /*  Issuers Controller */
    public static final String ISSUERS_NAME = "Issuers" ;
    public static final String ISSUERS_DESCRIPTION = "All the Issuers Related Endpoints" ;
    public static final String ISSUERS_GET_ISSUERS_SUMMARY = "Retrieve All Onboarded Issuers" ;
    public static final String ISSUERS_GET_ISSUERS_DESCRIPTION = "This endpoint allow you to retrieve all the onboarded issuers" ;
    public static final String ISSUERS_GET_SPECIFIC_ISSUER_SUMMARY = "Retrieve Specific Issuer's Config" ;
    public static final String ISSUERS_GET_SPECIFIC_ISSUER_DESCRIPTION = "This endpoint allow you to retrieve the complete configuration of the specific issuer" ;
    public static final String ISSUERS_GET_ISSUER_WELLKNOWN_SUMMARY = "Retrieve Specific Issuer's Well known" ;
    public static final String ISSUERS_GET_ISSUER_WELLKNOWN_DESCRIPTION = "This endpoint allow you to retrieve the well known of the specific issuer" ;

    /*  Prensentation Controller */
    public static final String PRESENTATION_NAME = "Presentation" ;
    public static final String PRESENTATION_DESCRIPTION = "All the Online Sharing Related Endpoints" ;
    public static final String PRESENTATION_AUTHORIZE_SUMMARY = "Perform the Authorization" ;
    public static final String PRESENTATION_AUTHORIZE_DESCRIPTION = "This endpoint allow you to redirect the token back to the caller post authorization" ;

    /*  Resident Service Controller */
    public static final String RESIDENT_NAME = "Resident Service" ;
    public static final String RESIDENT_DESCRIPTION = "All the Resident Service Related Endpoints" ;
    public static final String RESIDENT_REQUEST_OTP_SUMMARY = "Request for OTP" ;
    public static final String RESIDENT_REQUEST_OTP_DESCRIPTION = "This endpoint allow you to request OTP for credential download" ;
    public static final String RESIDENT_REQUEST_INDIVIDUALID_OTP_SUMMARY = "Request OTP for retrieving Individual Id" ;
    public static final String RESIDENT_REQUEST_INDIVIDUALID_OTP_DESCRIPTION = "This endpoint allow you to request OTP to retrieve Individual Id" ;
    public static final String RESIDENT_GET_INDIVIDUALID_SUMMARY = "Retrieve Individual Id using AID" ;
    public static final String RESIDENT_GET_INDIVIDUALID_DESCRIPTION = "This endpoint allow you to retrieve the Individual Id using AID" ;


    /*  Verifiers Controller */
    public static final String VERIFIERS_NAME = "Verifiers" ;
    public static final String VERIFIERS_DESCRIPTION = "All the verifiers related endpoints" ;
    public static final String VERIFIERS_GET_VERIFIERS_SUMMARY = "Retrieve all trusted verifiers" ;
    public static final String VERIFIERS_GET_VERIFIERS_DESCRIPTION = "This endpoint allow you to retrieve all the trusted verifiers" ;

}
