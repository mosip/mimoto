package io.mosip.mimoto.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorConstants {

    INVALID_REQUEST("invalid_request", "Some incorrect parameters in the request"),
    UNSUPPORTED_FORMAT("unsupported_format", "No VC of this format is found"),
    RESOURCE_NOT_FOUND("resource_not_found", "The requested resource doesn’t exist."),
    SERVER_UNAVAILABLE("server_unavailable", "The server is not reachable right now."),
    RESOURCE_EXPIRED("resource_expired", "The requested resource expired."),
    RESOURCE_INVALID("invalid_resource", "The requested resource is invalid."),
    REQUEST_TIMED_OUT("request_timed_out", "We are unable to process your request right now"),
    URI_TOO_LONG("uri_too_long", "Resource URI is too long to be handled"),
    INVALID_CLIENT("invalid_client", "The requested client doesn’t match."),
    INVALID_REDIRECT_URI("invalid_redirect_uri", "The requested redirect uri doesn’t match."),
    INTERNAL_SERVER_ERROR("internal_server_error", "We are unable to process request now"),

    PROOF_TYPE_NOT_SUPPORTED_EXCEPTION("proof_type_not_supported", "Proof Type available in received credentials is not matching with supported proof terms" ),
    SIGNATURE_VERIFICATION_EXCEPTION("signature_verification_failed", "Error while doing signature verification" ),
    JSON_PARSING_EXCEPTION("json_parsing_failed", "Given data couldn't be parsed to JSON string" ),
    UNKNOWN_EXCEPTION("unknown_exception", "Error while doing verification of verifiable credential" ),
    PROOF_DOCUMENT_NOT_FOUND_EXCEPTION("proof_document_not_found", "Proof document is not available in the received credentials" ),
    PUBLIC_KEY_NOT_FOUND_EXCEPTION("public_key_not_found", "Proof document is not available in the received credentials"),
    OAUTH2_AUTHENTICATION_EXCEPTION( "user_authentication_error", "Failed to authenticate user via OAuth Identity Provider during login"),
    LOGIN_SESSION_INVALIDATE_EXCEPTION("user_logout_error", "Exception occurred when invalidating the session of a user"),
    SESSION_EXPIRED_OR_INVALID( "session_invalid_or_expired", "User session is missing or expired. Please log in again."),
    DATABASE_CONNECTION_EXCEPTION( "database_unavailable", "Failed to connect to the database"),
    REDIS_CONNECTION_EXCEPTION( "redis_unavailable", "Failed to connect to the redis"),
    ENCRYPTION_FAILED( "encryption_failed", "Failed to encrypt the data"),
    DECRYPTION_FAILED( "decryption_failed", "Failed to decrypt the data"),
    SCHEMA_MISMATCH( "schema_mismatch", "Failed to restored the stored data"),
    INVALID_USER("invalid_user", "User does not exist in database"),
    CREDENTIAL_DOWNLOAD_EXCEPTION( "credential_download_error", "Failed to download and store the credential"),
    CREDENTIAL_FETCH_EXCEPTION( "credential_fetch_error", "Failed to fetch the credential");

    private final String errorCode;
    private final String errorMessage;

}
