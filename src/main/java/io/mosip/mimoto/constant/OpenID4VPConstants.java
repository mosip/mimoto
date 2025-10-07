package io.mosip.mimoto.constant;

/**
 * Constants for OpenID4VP structure keys used in presentation definitions, authorization requests, and VP session data.
 */
public class OpenID4VPConstants {
    
    // VP Session data keys
    public static final String CREATED_AT = "createdAt";
    public static final String OPENID4VP_INSTANCE = "openID4VPInstance";
    
    // Authorization request structure keys
    public static final String AUTHORIZATION_REQUEST = "authorizationRequest";
    public static final String AUTHORIZATION_REQUEST_URL = "authorizationRequestUrl";
    
    // Presentation definition structure keys
    public static final String PRESENTATION_DEFINITION = "presentationDefinition";
    public static final String ID = "id";
    public static final String INPUT_DESCRIPTORS = "inputDescriptors";
    public static final String FORMAT = "format";
    public static final String CONSTRAINTS = "constraints";
    public static final String LIMIT_DISCLOSURE = "limitDisclosure";
    public static final String FIELDS = "fields";
    public static final String PATH = "path";
    public static final String FILTER = "filter";
    public static final String TYPE = "type";
    public static final String PATTERN = "pattern";
    
    // VP Token signing result keys
    public static final String JWS = "jws";
    public static final String PROOF_VALUE = "proofValue";
    public static final String SIGNATURE_ALGORITHM = "signatureAlgorithm";
    public static final String SIGNATURE = "signature";
    public static final String MDOC_AUTHENTICATION_ALGORITHM = "mdocAuthenticationAlgorithm";
    public static final String DOCUMENT_TYPE_SIGNATURES = "documentTypeSignatures";
    
    // MSO_MDOC specific keys
    public static final String DOC_TYPE_TO_DEVICE_AUTHENTICATION_BYTES = "docTypeToDeviceAuthenticationBytes";
    
    // Credential format type strings
    public static final String FORMAT_LDP_VC_UNDERSCORE = "ldp_vc";
    public static final String FORMAT_LDP_VC_HYPHEN = "ldp-vc";
    public static final String FORMAT_MSO_MDOC_UNDERSCORE = "mso_mdoc";
    public static final String FORMAT_MSO_MDOC_HYPHEN = "mso-mdoc";
    
    // Algorithm names
    public static final String ALGORITHM_ES256 = "ES256";
    public static final String ALGORITHM_EDDSA = "EdDSA";
    
    // JWT separators and delimiters
    public static final String DETACHED_JWT_SEPARATOR = "..";
    
    // JWT header critical parameters
    public static final String JWT_CRITICAL_PARAM_B64 = "b64";
    
    // DID (Decentralized Identifier) related constants
    public static final String DID_JWK_PREFIX = "did:jwk:";
    public static final String DID_KEY_FRAGMENT = "#0";
    
    // Response status constants
    public static final String STATUS_SUCCESS = "SUCCESS";
    public static final String STATUS_ERROR = "ERROR";
    
    // Database record status constants (lowercase)
    public static final String DB_STATUS_SUCCESS = "success";
    public static final String DB_STATUS_ERROR = "error";
    
    // Response message constants
    public static final String MESSAGE_PRESENTATION_SUCCESS = "Presentation successfully submitted and shared with verifier";
    public static final String MESSAGE_PRESENTATION_SHARE_FAILED = "Presentation submitted but failed to share with verifier";
    
    // Credential selection keys
    public static final String SELECTED_CREDENTIALS = "selectedCredentials";
}

