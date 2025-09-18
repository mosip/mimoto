package io.mosip.mimoto.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.CredentialMatchingService;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.service.impl.SessionManager;
import io.mosip.mimoto.util.Utilities;
import io.mosip.mimoto.util.WalletUtil;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Map;
import java.time.Instant;

import static io.mosip.mimoto.exception.ErrorConstants.*;

@Slf4j
@RestController
@RequestMapping("/wallets/{walletId}/presentations")
public class WalletPresentationsController {

    @Autowired
    private PresentationService presentationService;

    @Autowired
    private CredentialMatchingService credentialMatchingService;

    @Autowired
    private SessionManager sessionManager;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * Processes the Verifiable Presentation Authorization Request for a specific wallet.
     *
     * @param walletId               The unique identifier of the wallet.
     * @param httpSession            The HTTP session containing wallet details such as wallet ID.
     * @param vpAuthorizationRequest The Verifiable Presentation Authorization Request parameters.
     * @return The processed Verifiable Presentation details, including information about the verifier.
     */
    @Operation(summary = "Processes Verifiable Presentation Authorization Request and provides details about the verifier and presentation.", description = "This API is secured using session-based authentication. Upon receiving a request, the session is first retrieved using the session ID extracted from the Cookie header to authenticate the user. Once authenticated, the API processes the received Verifiable Presentation Authorization Request from the Verifier for a specific wallet. It validates the session, verifies the authenticity of the request, and checks if the Verifier is pre-registered and trusted by the wallet. If all validations pass, the API returns a response containing the presentation details; otherwise, an appropriate error response is returned.", operationId = "processVPAuthorizationRequest", security = @SecurityRequirement(name = "SessionAuth"), parameters = {
            @Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "The unique identifier of the Wallet.", schema = @Schema(type = "string"))},
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    description = "Request body containing the Verifiable Presentation Authorization Request parameters.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = VerifiablePresentationAuthorizationRequest.class),
                            examples = @ExampleObject(
                                    name = "Verifier Verifiable Presentation Authorization Request",
                                    value = "{ \"authorizationRequestUrl\": \"client_id=mock-client&presentation_definition_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=NHgLcWlae745DpfJbUyfdg%253D%253D&response_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response&state=pcmxBfvdPEcjFObgt%252BLekA%253D%253D\" }"
                            )
                    )
            )
    )
    @ApiResponse(responseCode = "200", description = "Successfully processed the Verifiable Presentation Authorization Request.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = VerifiablePresentationResponseDTO.class), examples = @ExampleObject(name = "Success response", value = "{ \"presentationId\": \"123e4567-e89b-12d3-a456-426614174000\", \"verifier\": { \"id\": \"mock-client\", \"name\": \"Requester name\", \"logo\": \"https://api.collab.mosip.net/inji/verifier-logo.png\", \"isTrusted\": true, \"isPreregisteredWithWallet\": true, \"redirectUri\": \"https://injiverify.collab.mosip.net/redirect\" } }")))
    @ApiResponse(responseCode = "400", description = "Invalid request or missing required parameters.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {
            @ExampleObject(name = "response_type is missing in Authorization request", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Missing Input: response_type param is required\"}"),
            @ExampleObject(name = "Invalid Wallet ID", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Invalid Wallet ID. Session and request Wallet ID do not match\"}"),
            @ExampleObject(name = "Wallet ID not found in session", value = "{\"errorCode\": \"wallet_locked\", \"errorMessage\": \"Wallet is locked\"}")
    }))
    @ApiResponse(responseCode = "401", description = "Unauthorized user performing the Verifiable Presentation flow", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "User ID is not present in session", value = "{\"errorCode\": \"unauthorized\", \"errorMessage\": \"User ID not found in session\"}")))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {
            @ExampleObject(name = "Failed to fetch pre-registered trusted verifiers", value = "{\"errorCode\": \"RESIDENT-APP-026\", \"errorMessage\": \"Api not accessible failure\"}"),
            @ExampleObject(name = "Unexpected Server Error", value = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}"),
            @ExampleObject(name = "Invalid URI syntax", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Incorrect URI parameters in the request\"}")
    }))
    @PostMapping
    public ResponseEntity<VerifiablePresentationResponseDTO> handleVPAuthorizationRequest(@PathVariable("walletId") String walletId, HttpSession httpSession, @RequestBody VerifiablePresentationAuthorizationRequest vpAuthorizationRequest) {
        try {
            WalletUtil.validateWalletId(httpSession, walletId);

            VerifiablePresentationResponseDTO verifiablePresentationResponseDTO = presentationService.handleVPAuthorizationRequest(vpAuthorizationRequest.getAuthorizationRequestUrl(), walletId);

            VerifiablePresentationSessionData verifiablePresentationSessionData = new VerifiablePresentationSessionData(verifiablePresentationResponseDTO.getPresentationId(),
                    vpAuthorizationRequest.getAuthorizationRequestUrl(), Instant.now(),
                    verifiablePresentationResponseDTO.getVerifiablePresentationVerifierDTO().isPreregisteredWithWallet(), null);

            sessionManager.storePresentationSessionData(httpSession, verifiablePresentationSessionData, walletId);

            return ResponseEntity.status(HttpStatus.OK).body(verifiablePresentationResponseDTO);
        } catch (OpenID4VPExceptions exception) {
            log.error("Error occurred while processing the received VP Authorization Request from Verifier: ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, exception.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        } catch (ApiNotAccessibleException | IOException | VPNotCreatedException exception) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, WALLET_CREATE_VP_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        } catch (URISyntaxException exception) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        }
    }

    /**
     * Gets matching credentials for a specific presentation request.
     *
     * @param walletId       The unique identifier of the wallet.
     * @param presentationId The unique identifier of the presentation.
     * @param httpSession    The HTTP session containing wallet details.
     * @return The matching credentials response with available credentials and
     * missing claims.
     */
    @Operation(summary = "Get matching credentials for a presentation request", description = "This API retrieves credentials from the wallet that match the presentation definition requirements. It returns available credentials that can satisfy the presentation request along with any missing claims that are required but not available.", operationId = "getMatchingCredentials", security = @SecurityRequirement(name = "SessionAuth"), parameters = {@Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "The unique identifier of the Wallet.", schema = @Schema(type = "string")), @Parameter(name = "presentationId", in = ParameterIn.PATH, required = true, description = "The unique identifier of the Presentation.", schema = @Schema(type = "string"))})
    @ApiResponse(responseCode = "200", description = "Successfully retrieved matching credentials.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = MatchingCredentialsResponseDTO.class), examples = @ExampleObject(name = "Success response", value = "{ \"availableCredentials\": [{ \"credentialId\": \"cred-123\", \"credentialTypeDisplayName\": \"Mock Verifiable Credential (SD-JWT)\", \"credentialTypeLogo\": \"https://mosip.github.io/inji-config/logos/mosipid-logo.png\", \"type\": [\"IDCredential\"], \"claims\": { \"birthdate\": \"1990-01-01\" } }], \"missingClaims\": [] }")))
    @ApiResponse(responseCode = "400", description = "Invalid request or missing required parameters.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {@ExampleObject(name = "Invalid Wallet ID", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Invalid Wallet ID. Session and request Wallet ID do not match\"}"), @ExampleObject(name = "Presentation not found", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Presentation not found in session\"}")}))
    @ApiResponse(responseCode = "401", description = "Unauthorized user performing the Verifiable Presentation flow", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "User ID is not present in session", value = "{\"errorCode\": \"unauthorized\", \"errorMessage\": \"User ID not found in session\"}")))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Unexpected Server Error", value = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}")))
    @GetMapping("/{presentationId}/credentials")
    public ResponseEntity<MatchingCredentialsResponseDTO> getMatchingCredentials(@PathVariable("walletId") String walletId, @PathVariable("presentationId") String presentationId, HttpSession httpSession) {

        WalletUtil.validateWalletId(httpSession, walletId);

        String base64Key = (String) httpSession.getAttribute(SessionKeys.WALLET_KEY);
        if (base64Key == null) {
            log.warn("Wallet key not found in session for walletId: {}", walletId);
            return Utilities.getErrorResponseEntityFromPlatformErrorMessage(UNAUTHORIZED_ACCESS, HttpStatus.UNAUTHORIZED, MediaType.APPLICATION_JSON);
        }

        VerifiablePresentationSessionData sessionData = sessionManager.getPresentationSessionData(httpSession, walletId, presentationId);

        try {
            MatchingCredentialsWithWalletDataDTO matchingCredentialsWithWalletData = credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
            // Store the matching credentials and pre-filtered matched credentials in session cache before returning
            sessionManager.storeMatchingWalletCredentialsInPresentationSessionData(httpSession, walletId, sessionData, matchingCredentialsWithWalletData.getMatchingCredentials());
            return ResponseEntity.status(HttpStatus.OK).body(matchingCredentialsWithWalletData.getMatchingCredentialsResponse());
        } catch (ApiNotAccessibleException | IOException | VPNotCreatedException exception) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, WALLET_CREATE_VP_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        } catch (IllegalArgumentException e) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    e, INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        }

    }

    /**
     * Endpoint invoked when a wallet user rejects a Verifiable Presentation request from a Verifier.
     *
     * Validates the session and that the provided presentationId exists in the session store.
     * If valid, forwards the rejection payload to the OpenID4VP instance associated with the
     * presentation so the Verifier is notified. Returns a brief status object on success.
     *
     * @param walletId       The unique identifier of the wallet (path parameter).
     * @param httpSession    The HTTP session holding presentation session data.
     * @param presentationId The presentation session identifier (path parameter) that was previously created.
     * @param payload        Error payload containing rejection reason/description.
     * @return 200 with {@link RejectedVerifierDTO} when rejection is accepted; appropriate error responses otherwise.
     */
    @Operation(
            summary = "User rejects a verifier for a presentation",
            description = "Allows an authenticated wallet user to reject a verifier's Verifiable Presentation request. Validates session and presentationId, then forwards the rejection to the OpenID4VP instance stored in session.",
            operationId = "userRejectedVerifier",
            security = @SecurityRequirement(name = "SessionAuth"),
            parameters = {
                    @Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "The unique identifier of the Wallet.", schema = @Schema(type = "string")),
                    @Parameter(name = "presentationId", in = ParameterIn.PATH, required = true, description = "The presentation session identifier.", schema = @Schema(type = "string"))
            },
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    description = "Error payload containing rejection reason sent by the user.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorDTO.class),
                            examples = @ExampleObject(name = "Rejection payload", value = "{\"errorCode\": \"access_denied\", \"errorMessage\": \"User denied authorization to share credentials\"}")
                    )
            )
    )
    @ApiResponse(responseCode = "200", description = "Verifier rejection accepted.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = RejectedVerifierDTO.class), examples = @ExampleObject(name = "Success response", value = "{\"status\": \"success\", \"message\": \"Presentation request rejected. An OpenID4VP error response has been sent to the verifier.\", \"redirectUri\": https://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee}")))
    @ApiResponse(responseCode = "400", description = "Invalid request (missing/incorrect presentationId or wallet mismatch).", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {
            @ExampleObject(name = "presentationId not found in session", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"presentationId not found in session\"}"),
            @ExampleObject(name = "Invalid Wallet ID", value = "{\"errorCode\":\"invalid_request\",\"errorMessage\":\"Invalid Wallet ID. Session and request Wallet ID do not match\"}")
    }))
    @ApiResponse(responseCode = "401", description = "Unauthorized or invalid session.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "unauthorized", value = "{\"errorCode\": \"unauthorized\", \"errorMessage\": \"User ID not found in session\"}")))
    @ApiResponse(responseCode = "500", description = "Internal server error.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Failed to reject verifier", value = "{\"errorCode\": \"error\", \"errorMessage\": \"Unable to process reject verifier request\"}")))
    @PatchMapping("/{presentationId}")
    public ResponseEntity<?> userRejectedVerifier(@PathVariable("walletId") String walletId, HttpSession httpSession, @PathVariable("presentationId") String presentationId, @RequestBody ErrorDTO payload) {
        try {
            WalletUtil.validateWalletId(httpSession, walletId);

            @SuppressWarnings("unchecked")
            Map<String, String> presentations = (Map<String, String>) httpSession.getAttribute("presentations");

            if (presentations == null || !presentations.containsKey(presentationId)) {
                return Utilities.getErrorResponseEntityWithoutWrapper(
                        new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "presentationId not found in session"),
                        INVALID_REQUEST.getErrorCode(),
                        HttpStatus.BAD_REQUEST,
                        MediaType.APPLICATION_JSON
                );
            }

            String vpSessionJson = presentations.get(presentationId);
            Map<String, Object> vpSessionData = objectMapper.readValue(
                    vpSessionJson, new TypeReference<Map<String, Object>>() {});

            presentationService.rejectVerifier(walletId, vpSessionData, payload);

            RejectedVerifierDTO rejectedVerifierDTO = new RejectedVerifierDTO();
            rejectedVerifierDTO.setStatus(REJECTED_VERIFIER.getErrorCode());
            rejectedVerifierDTO.setMessage(REJECTED_VERIFIER.getErrorMessage());
            // todo set redirect uri
            rejectedVerifierDTO.setRedirectUri(null);
            return ResponseEntity.status(HttpStatus.OK).body(rejectedVerifierDTO);
        } catch (Exception e) {
            log.error("Error during user rejection for VP request: ", e);
            return Utilities.getErrorResponseEntityWithoutWrapper(e, REJECT_VERIFIER_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }
}