package io.mosip.mimoto.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.service.OpenID4VPService;
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
import java.util.HashMap;
import java.util.Map;

import static io.mosip.mimoto.exception.ErrorConstants.WALLET_CREATE_VP_EXCEPTION;

@Slf4j
@RestController
@RequestMapping("/wallets/{walletId}/presentations")
public class OpenID4VPController {

    @Autowired
    private OpenID4VPService openID4VPService;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * Processes the Verifiable Presentation Authorization Request for a specific wallet.
     *
     * @param walletId                    The unique identifier of the wallet.
     * @param httpSession                 The HTTP session containing wallet details such as wallet ID.
     * @param urlEncodedVPAuthorizationRequest The URL-encoded Verifiable Presentation Authorization Request parameters.
     * @return The processed Verifiable Presentation details, including information about the verifier.
     * @throws ApiNotAccessibleException If the API used for fetching pre-registered trsuted verifiers is not accessible or returns null.
     * @throws InvalidRequestException If the urlEncodedVPAuthorizationRequest parameters or walletId in session is invalid.
     */
    @Operation(summary = "Processes Verifiable Presentation Authorization Request and provides details about the verifier and presentation.", description = "This API is secured using session-based authentication. Upon receiving a request, the session is first retrieved using the session ID extracted from the Cookie header to authenticate the user. Once authenticated, the API processes the received Verifiable Presentation Authorization Request from the Verifier for a specific wallet. It validates the session, verifies the authenticity of the request, and checks if the Verifier is pre-registered and trusted by the wallet. If all validations pass, the API returns a response containing the presentation details; otherwise, an appropriate error response is returned.", operationId = "processVPAuthorizationRequest", security = @SecurityRequirement(name = "SessionAuth"), parameters = {
            @Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "The unique identifier of the Wallet.", schema = @Schema(type = "string"))},
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    description = "Request body containing the Verifiable Presentation Authorization Request parameters.",
                    content = @Content(
                            mediaType = "application/x-www-form-urlencoded",
                            schema = @Schema(type = "string"),
                            examples = @ExampleObject(
                                    name = "Verifier Verifiable Presentation Authorization Request",
                                    value = "client_id=mock-client&presentation_definition_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=NHgLcWlae745DpfJbUyfdg%253D%253D&response_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response&state=pcmxBfvdPEcjFObgt%252BLekA%253D%253D"
                            )
                    )
            )
    )
    @ApiResponse(responseCode = "200", description = "Successfully processed the Verifiable Presentation Authorization Request.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = VerifiablePresentationResponseDTO.class), examples = @ExampleObject(name = "Success response", value = "{ \"presentationId\": \"123e4567-e89b-12d3-a456-426614174000\", \"verifier\": { \"clientId\": \"mock-client\", \"clientName\": \"Requester name\", \"logoUri\": \"https://api.collab.mosip.net/inji/verifier-logo.png\", \"isVerifierTrustedByWallet\": true, \"isVerifierPreRegisteredWithWallet\": true, \"redirectUri\": \"https://injiverify.collab.mosip.net/redirect\" } }")))
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
    @PostMapping(consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<VerifiablePresentationResponseDTO> handleVPAuthorizationRequest(@PathVariable("walletId") String walletId, HttpSession httpSession, @RequestBody String urlEncodedVPAuthorizationRequest) throws ApiNotAccessibleException, IOException {
        try {
            String sessionWalletId = (String) httpSession.getAttribute(SessionKeys.WALLET_ID);
            if (sessionWalletId != null) {
                WalletUtil.validateWalletId(httpSession, walletId);
            }
            VerifiablePresentationResponseDTO verifiablePresentationResponseDTO = openID4VPService.handleVPAuthorizationRequest(urlEncodedVPAuthorizationRequest, walletId);
            storePresentationSessionDataInHttpSession(httpSession, verifiablePresentationResponseDTO.getVerifiablePresentationSessionData(), verifiablePresentationResponseDTO.getPresentationId());

            return ResponseEntity.status(HttpStatus.OK).body(verifiablePresentationResponseDTO);
        } catch (OpenID4VPExceptions exception) {
            log.error("Error occurred while processing the received VP Authorization Request from Verifier: ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, exception.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        } catch (ApiNotAccessibleException | IOException exception) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, WALLET_CREATE_VP_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }

    public void storePresentationSessionDataInHttpSession(HttpSession httpSession, VerifiablePresentationSessionData sessionData, String presentationId) throws JsonProcessingException {
        Map<String, String> presentations = (Map<String, String>) httpSession.getAttribute("presentations");

        if (presentations == null) {
            presentations = new HashMap<>();
        }

        // Create a new presentation entry
        Map<String, Object> vpSessionData = new HashMap<>();
        vpSessionData.put("authorizationRequest", sessionData.getAuthorizationRequest());
        vpSessionData.put("createdAt", sessionData.getCreatedAt().toString());

        // Serialize the presentationData map to a JSON string
        String presentationDataJson = objectMapper.writeValueAsString(vpSessionData);

        // Add the new presentation to the map
        presentations.put(presentationId, presentationDataJson);

        // Store the updated map in the session
        httpSession.setAttribute("presentations", presentations);
    }
}
