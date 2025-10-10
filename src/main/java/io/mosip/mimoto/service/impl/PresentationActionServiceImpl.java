package io.mosip.mimoto.service.impl;

import com.nimbusds.jose.JOSEException;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.SubmitPresentationResponseDTO;
import io.mosip.mimoto.dto.SubmitPresentationRequestDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.PresentationActionService;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.service.PresentationSubmissionService;
import io.mosip.mimoto.util.Utilities;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.lang.IllegalArgumentException;

import static io.mosip.mimoto.exception.ErrorConstants.*;

/**
 * Service implementation for handling presentation actions
 */
@Slf4j
@Service
public class PresentationActionServiceImpl implements PresentationActionService {

    @Autowired
    private PresentationSubmissionService presentationSubmissionService;

    @Autowired
    private PresentationService presentationService;

    @Override
    public ResponseEntity<SubmitPresentationResponseDTO> handlePresentationAction(String walletId, String presentationId, SubmitPresentationRequestDTO request, VerifiablePresentationSessionData vpSessionData, String base64Key) {

        log.info("Processing presentation action for walletId: {}, presentationId: {}", walletId, presentationId);

        try {
            // Determine the action based on request content
            if (request.isSubmissionRequest()) {
                log.info("Processing presentation submission for presentationId: {}", presentationId);
                return handlePresentationSubmission(walletId, presentationId, request, vpSessionData, base64Key);

            } else if (request.isRejectionRequest()) {
                log.info("Processing verifier rejection for presentationId: {}", presentationId);
                return handleVerifierRejection(walletId, vpSessionData, request);

            } else {
                log.warn("Invalid request format - must contain either selectedCredentials or both errorCode and errorMessage");
                return Utilities.getErrorResponseEntityWithoutWrapper(new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Request must contain either selectedCredentials or both errorCode and errorMessage"), INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
            }

        } catch (JOSEException exception) {
            log.error("JWT signing error during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, JWT_SIGNING_ERROR.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (KeyGenerationException exception) {
            log.error("Key generation/retrieval error during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, KEY_GENERATION_ERROR.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (DecryptionException exception) {
            log.error("Decryption error during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, DECRYPTION_ERROR.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (ApiNotAccessibleException | IOException exception) {
            log.error("Error during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, WALLET_CREATE_VP_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (VPErrorNotSentException exception) {
            log.error("Error sending rejection to verifier for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, REJECT_VERIFIER_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (IllegalArgumentException exception) {
            log.error("Invalid argument during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        }
    }

    /**
     * Handles presentation submission with selected credentials
     */
    private ResponseEntity<SubmitPresentationResponseDTO> handlePresentationSubmission(String walletId, String presentationId, SubmitPresentationRequestDTO request, VerifiablePresentationSessionData sessionData, String base64Key) throws ApiNotAccessibleException, IOException, JOSEException, KeyGenerationException, DecryptionException {

        log.debug("Submitting presentation for walletId: {}, presentationId: {}", walletId, presentationId);

        if (base64Key == null || base64Key.isBlank()) {
            log.warn("Wallet key not found for walletId: {}", walletId);
            throw new IllegalArgumentException("Wallet key is required for presentation submission");
        }

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);

        log.info("Presentation submission completed successfully for walletId: {}, presentationId: {}", walletId, presentationId);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    /**
     * Handles verifier rejection with error details
     */
    private ResponseEntity<SubmitPresentationResponseDTO> handleVerifierRejection(String walletId, VerifiablePresentationSessionData vpSessionData, SubmitPresentationRequestDTO request) throws VPErrorNotSentException {

        log.debug("Rejecting verifier for walletId: {}", walletId);

        // Create ErrorDTO from the request
        ErrorDTO errorPayload = new ErrorDTO();
        errorPayload.setErrorCode(request.getErrorCode());
        errorPayload.setErrorMessage(request.getErrorMessage());

        // Call the presentation service to reject the verifier
        SubmitPresentationResponseDTO submitPresentationResponseDTO = presentationService.rejectVerifier(walletId, vpSessionData, errorPayload);

        log.info("Verifier rejection completed successfully for walletId: {}", walletId);

        return ResponseEntity.status(HttpStatus.OK).body(submitPresentationResponseDTO);
    }
}

