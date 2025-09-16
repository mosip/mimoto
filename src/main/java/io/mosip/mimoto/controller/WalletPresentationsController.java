package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.VerifiablePresentationAuthorizationRequest;
import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.VPNotCreatedException;
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

import static io.mosip.mimoto.exception.ErrorConstants.WALLET_CREATE_VP_EXCEPTION;

@Slf4j
@RestController
@RequestMapping("/wallets/{walletId}/presentations")
public class WalletPresentationsController {

    @Autowired
    private PresentationService presentationService;

    @Autowired
    private SessionManager sessionManager;

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
            @ExampleObject(name = "Unexpected Server Error", value = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}")
    }))
    @PostMapping
    public ResponseEntity<VerifiablePresentationResponseDTO> handleVPAuthorizationRequest(@PathVariable("walletId") String walletId, HttpSession httpSession, @RequestBody VerifiablePresentationAuthorizationRequest vpAuthorizationRequest) throws URISyntaxException {
        try {
            WalletUtil.validateWalletId(httpSession, walletId);

            VerifiablePresentationResponseDTO verifiablePresentationResponseDTO = presentationService.handleVPAuthorizationRequest(vpAuthorizationRequest.getAuthorizationRequestUrl(), walletId);
            sessionManager.storePresentationSessionDataInSession(httpSession, verifiablePresentationResponseDTO.getVerifiablePresentationSessionData(), verifiablePresentationResponseDTO.getPresentationId(), walletId);

            return ResponseEntity.status(HttpStatus.OK).body(verifiablePresentationResponseDTO);
        } catch (OpenID4VPExceptions exception) {
            log.error("Error occurred while processing the received VP Authorization Request from Verifier: ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, exception.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        } catch (ApiNotAccessibleException | IOException | VPNotCreatedException | URISyntaxException exception) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, WALLET_CREATE_VP_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }
}
