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
    PROOF_DOCUMENT_NOT_FOUND_EXCEPTION("proof_document_not_found", "Proof document is not available in the received credentials" );



    private final String errorCode;
    private final String errorMessage;

}
