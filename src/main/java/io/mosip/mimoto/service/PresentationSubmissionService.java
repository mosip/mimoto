package io.mosip.mimoto.service;

import com.nimbusds.jose.JOSEException;
import io.mosip.mimoto.dto.SubmitPresentationRequestDTO;
import io.mosip.mimoto.dto.SubmitPresentationResponseDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.KeyGenerationException;

import java.io.IOException;

/**
 * Service interface for handling presentation submission operations
 */
public interface PresentationSubmissionService {

    /**
     * Submits a presentation with selected credentials
     *
     * @param sessionData The session data containing presentation information
     * @param walletId The wallet ID
     * @param presentationId The presentation ID
     * @param request The submission request with selected credentials
     * @param base64Key The user's private key for signing
     * @return The submission response
     * @throws ApiNotAccessibleException if API is not accessible
     * @throws IOException if there's an IO error
     * @throws JOSEException if JWT signing fails
     * @throws KeyGenerationException if key pair retrieval or generation fails
     * @throws DecryptionException if decryption of private key fails
     */
    SubmitPresentationResponseDTO submitPresentation(
            VerifiablePresentationSessionData sessionData,
            String walletId,
            String presentationId,
            SubmitPresentationRequestDTO request,
            String base64Key
    ) throws ApiNotAccessibleException, IOException, JOSEException, KeyGenerationException, DecryptionException;
}
