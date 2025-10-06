package io.mosip.mimoto.service.impl;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;

import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.constant.OpenID4VPConstants;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.dto.SubmitPresentationRequestDTO;
import io.mosip.mimoto.dto.SubmitPresentationResponseDTO;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.util.JwtGeneratorUtil;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.KeyGenerationException;
import io.mosip.mimoto.model.VerifiablePresentation;
import io.mosip.mimoto.service.PresentationSubmissionService;
import io.mosip.mimoto.service.KeyPairService;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.mimoto.repository.VerifiablePresentationRepository;
import io.mosip.mimoto.util.UrlParameterUtils;
import io.mosip.mimoto.util.WalletPresentationUtil;
import io.mosip.mimoto.util.Base64Util;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.constants.FormatType;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service implementation for handling presentation submission operations
 */
@Slf4j
@Service
public class PresentationSubmissionServiceImpl implements PresentationSubmissionService {

    private static final String DEFAULT_SIGNATURE_SUITE = "JsonWebSignature2020";
    private static final String UNKNOWN_VERIFIER = "unknown";
    private static final String EMPTY_JSON = "{}";
    
    @Value("${mimoto.presentation.signing.algorithm:ED25519}")
    private String defaultSigningAlgorithmName;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private OpenID4VPService openID4VPService;

    @Autowired
    private VerifierService verifierService;

    @Autowired
    private KeyPairService keyPairService;

    @Autowired
    private VerifiablePresentationRepository verifiablePresentationRepository;

    @Override
    public SubmitPresentationResponseDTO submitPresentation(VerifiablePresentationSessionData sessionData, String walletId, String presentationId, SubmitPresentationRequestDTO request, String base64Key) throws ApiNotAccessibleException, IOException, JOSEException, KeyGenerationException, DecryptionException {

        // Validate all inputs before processing
        validateInputs(sessionData, walletId, presentationId, request, base64Key);
        
        log.info("Starting presentation submission for walletId: {}, presentationId: {}", walletId, presentationId);

        LocalDateTime requestedAt = LocalDateTime.now();

        // Step 1: Fetch full credentials by ID from cache
        List<DecryptedCredentialDTO> selectedCredentials = fetchSelectedCredentials(sessionData, request.getSelectedCredentials());

        // Step 2: Create OpenID4VP instance and construct unsigned VP token
        OpenID4VP openID4VP = openID4VPService.create(presentationId);
        List<Verifier> preRegisteredVerifiers = verifierService.getTrustedVerifiers().getVerifiers().stream()
                .map(WalletPresentationUtil::mapToVerifier).toList();
        openID4VP.authenticateVerifier(sessionData.getAuthorizationRequest(), preRegisteredVerifiers, sessionData.isVerifierClientPreregistered());

        // Use configurable signing algorithm
        SigningAlgorithm signingAlgorithm = SigningAlgorithm.valueOf(defaultSigningAlgorithmName);
        log.debug("Using signing algorithm: {} for wallet: {}", signingAlgorithm, walletId);
        KeyPair keyPair = keyPairService.getKeyPairFromDB(walletId, base64Key, signingAlgorithm);
        JWK jwk = JwtGeneratorUtil.generateJwk(signingAlgorithm, keyPair);
        Map<FormatType, UnsignedVPToken> unsignedVPToken = constructUnsignedVPToken(openID4VP, selectedCredentials, jwk);

        // Step 3: Sign token using user's private key
        JWSSigner jwsSigner = JwtGeneratorUtil.createSigner(signingAlgorithm, jwk);
        Map<FormatType, LdpVPTokenSigningResult> vpTokenSigningResults = signVPToken(unsignedVPToken, jwsSigner, walletId, base64Key);

        // Step 4: Share verifiable presentation with verifier using OpenID4VP JAR
        boolean shareSuccess = shareVerifiablePresentation(vpTokenSigningResults, sessionData, openID4VP);

        // Step 5: Store presentation record in database
        storePresentationRecord(walletId, presentationId, request, sessionData, shareSuccess, requestedAt);

        // Step 6: Return success response
        return SubmitPresentationResponseDTO.builder().presentationId(presentationId)
                .status(shareSuccess ? OpenID4VPConstants.STATUS_SUCCESS : OpenID4VPConstants.STATUS_ERROR)
                .message(shareSuccess ? OpenID4VPConstants.MESSAGE_PRESENTATION_SUCCESS
                        : OpenID4VPConstants.MESSAGE_PRESENTATION_SHARE_FAILED)
                .build();
    }

    /**
     * Signs VP token using JWSSigner for different format types
     * This method delegates to format-specific signing methods
     * 
     * @param unsignedVPTokensMap Map of unsigned VP tokens by format type
     * @param jwsSigner The JWS signer to use for signing operations (for LDP_VC)
     * @param walletId The wallet ID for fetching keypairs (for MSO_MDOC)
     * @param base64Key The base64 encoded wallet key for decryption (for MSO_MDOC)
     * @return Map of signed VP token results by format type
     * @throws JOSEException if JWT signing fails
     * @throws IOException if I/O operations fail
     * @throws KeyGenerationException if key pair retrieval or generation fails
     * @throws DecryptionException if decryption of private key fails
     */
    private Map<FormatType, LdpVPTokenSigningResult> signVPToken(Map<FormatType, UnsignedVPToken> unsignedVPTokensMap, JWSSigner jwsSigner, String walletId, String base64Key) throws JOSEException, IOException, KeyGenerationException, DecryptionException {
        log.debug("Signing VP token for {} format types", unsignedVPTokensMap.size());

        return unsignedVPTokensMap.entrySet().stream()
                .map(entry -> {
                    FormatType formatType = entry.getKey();
                    UnsignedVPToken unsignedVPToken = entry.getValue();

                    try {
                        LdpVPTokenSigningResult signingResult = switch (formatType) {
                            case LDP_VC -> signLdpVcFormat(unsignedVPToken, jwsSigner);
                            case MSO_MDOC -> signMsoMdocFormat(unsignedVPToken, walletId, base64Key);
                            default -> {
                                log.warn("Unsupported format type: {}", formatType);
                                yield null;
                            }
                        };

                        return signingResult != null ? Map.entry(formatType, signingResult) : null;
                    } catch (JOSEException | IOException | KeyGenerationException | DecryptionException e) {
                        // Wrap checked exceptions in unchecked for stream processing
                        throw new RuntimeException("Failed to sign VP token for format: " + formatType, e);
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    /**
     * Signs LDP_VC format verifiable presentation using detached JWT
     * 
     * @param unsignedVPToken The unsigned VP token
     * @param jwsSigner The JWS signer (EdDSA) for signing
     * @return Signing result with detached JWT proof
     * @throws JOSEException if JWT signing fails
     */
    private LdpVPTokenSigningResult signLdpVcFormat(UnsignedVPToken unsignedVPToken, JWSSigner jwsSigner) throws JOSEException {
        log.debug("Signing LDP_VC format VP token");

        String dataToSign = ((UnsignedLdpVPToken) unsignedVPToken).getDataToSign();

        // Create JWSHeader with critical parameters for detached JWT
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .criticalParams(Set.of(OpenID4VPConstants.JWT_CRITICAL_PARAM_B64))
                .base64URLEncodePayload(false)
                .build();

        // Convert dataToSign from base64 to byte array
        byte[] vpTokenBytes = Base64Util.decodeFlexible(dataToSign);

        // Create header bytes for signing input
        String headerJson = header.toString();
        String header64 = Base64Util.encode(headerJson);

        // Create input bytes for detached JWT signing: header + '.' + payload
        byte[] inputBytes = Base64Util.createDetachedJwtSigningInput(header64, vpTokenBytes);

        // Sign using the provided JWSSigner
        Base64URL signatureBase64URL = jwsSigner.sign(header, inputBytes);
        String signature = signatureBase64URL.toString();

        // Create the detached JWT proof: header64 + '..' + signature
        String proof = header64 + OpenID4VPConstants.DETACHED_JWT_SEPARATOR + signature;

        Map<String, Object> signingResultData = new HashMap<>();
        signingResultData.put(OpenID4VPConstants.JWS, proof);
        signingResultData.put(OpenID4VPConstants.PROOF_VALUE, null);
        signingResultData.put(OpenID4VPConstants.SIGNATURE_ALGORITHM, DEFAULT_SIGNATURE_SUITE);

        return objectMapper.convertValue(signingResultData, LdpVPTokenSigningResult.class);
    }

    /**
     * Signs MSO_MDOC format verifiable presentation
     * Creates ES256 keypair and signs each document type
     * 
     * @param unsignedVPToken The unsigned VP token
     * @param walletId The wallet ID for fetching keypairs
     * @param base64Key The base64 encoded wallet key for decryption
     * @return Signing result with document type signatures
     * @throws JOSEException if JWT signing fails
     * @throws IOException if I/O operations fail
     * @throws KeyGenerationException if key pair retrieval or generation fails
     * @throws DecryptionException if decryption of private key fails
     */
    private LdpVPTokenSigningResult signMsoMdocFormat(UnsignedVPToken unsignedVPToken, String walletId, String base64Key) throws JOSEException, IOException, KeyGenerationException, DecryptionException {
        log.debug("Signing MSO_MDOC format VP token");

        // Convert UnsignedVPToken to Map for MSO_MDOC format
        @SuppressWarnings("unchecked")
        Map<String, Object> credentials = objectMapper.convertValue(unsignedVPToken, Map.class);
        Map<String, Map<String, Object>> documentTypeSignatures = new HashMap<>();

        // For MSO_MDOC format, look for docTypeToDeviceAuthenticationBytes
        if (!credentials.containsKey(OpenID4VPConstants.DOC_TYPE_TO_DEVICE_AUTHENTICATION_BYTES)) {
            log.warn("MSO_MDOC format type but no docTypeToDeviceAuthenticationBytes found");
            return createMsoMdocSigningResult(documentTypeSignatures);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> docTypeToDeviceAuthenticationBytes =
                (Map<String, Object>) credentials.get(OpenID4VPConstants.DOC_TYPE_TO_DEVICE_AUTHENTICATION_BYTES);

        if (docTypeToDeviceAuthenticationBytes == null) {
            return createMsoMdocSigningResult(documentTypeSignatures);
        }

        // Get MDOC authentication algorithm (defaulting to ES256)
        String mdocAuthenticationAlgorithm = OpenID4VPConstants.ALGORITHM_ES256;
        SigningAlgorithm mdocSigningAlgorithm = SigningAlgorithm.ES256;

        // Fetch key pair for MSO_MDOC signing (ES256 algorithm)
        log.debug("Fetching ES256 keypair for MSO_MDOC signing for walletId: {}", walletId);
        KeyPair mdocKeyPair = keyPairService.getKeyPairFromDB(walletId, base64Key, mdocSigningAlgorithm);
        JWK mdocJwk = JwtGeneratorUtil.generateJwk(mdocSigningAlgorithm, mdocKeyPair);
        JWSSigner mdocSigner = JwtGeneratorUtil.createSigner(mdocSigningAlgorithm, mdocJwk);

        // Process each docType entry using streams
        Map<String, Map<String, Object>> signedDocTypes = docTypeToDeviceAuthenticationBytes.entrySet().stream()
                .map(docTypeEntry -> {
                    String docType = docTypeEntry.getKey();
                    Object payload = docTypeEntry.getValue();

                    log.debug("Processing MSO_MDOC docType: {} with algorithm: {}", docType, mdocAuthenticationAlgorithm);

                    try {
                        String signature = signMsoMdocDocType(payload, mdocSigner);

                        // If signature was created successfully
                        if (signature != null && !signature.isEmpty()) {
                            Map<String, Object> docTypeResult = new HashMap<>();
                            docTypeResult.put(OpenID4VPConstants.SIGNATURE, signature);
                            docTypeResult.put(OpenID4VPConstants.MDOC_AUTHENTICATION_ALGORITHM, mdocAuthenticationAlgorithm);

                            log.debug("Successfully signed MSO_MDOC docType: {} with algorithm: {}",
                                    docType, mdocAuthenticationAlgorithm);

                            return Map.entry(docType, docTypeResult);
                        }
                        return null;
                    } catch (JOSEException | IOException e) {
                        log.error("Failed to sign MSO_MDOC docType: {}", docType, e);
                        throw new RuntimeException("Failed to sign docType: " + docType, e);
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        documentTypeSignatures.putAll(signedDocTypes);

        return createMsoMdocSigningResult(documentTypeSignatures);
    }

    /**
     * Signs a single MSO_MDOC document type payload
     * 
     * @param payload The payload to sign (string or object)
     * @param mdocSigner The ES256 signer
     * @return Base64URL encoded signature
     * @throws JOSEException if signing operation fails
     * @throws IOException if payload serialization fails
     */
    private String signMsoMdocDocType(Object payload, JWSSigner mdocSigner) throws JOSEException, IOException {
        // Create JWSHeader for ES256 algorithm
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).build();

        // Convert payload to bytes for signing
        byte[] payloadBytes;
        if (payload instanceof String) {
            payloadBytes = ((String) payload).getBytes(StandardCharsets.UTF_8);
        } else {
            payloadBytes = objectMapper.writeValueAsBytes(payload);
        }

        // Sign using the MSO_MDOC specific signer (ES256)
        Base64URL signatureBase64URL = mdocSigner.sign(header, payloadBytes);
        return signatureBase64URL.toString();
    }

    /**
     * Creates MSO_MDOC signing result from document type signatures
     * 
     * @param documentTypeSignatures Map of document type to signature data
     * @return LdpVPTokenSigningResult
     */
    private LdpVPTokenSigningResult createMsoMdocSigningResult(Map<String, Map<String, Object>> documentTypeSignatures) {
        Map<String, Object> signingResultData = new HashMap<>();
        signingResultData.put(OpenID4VPConstants.DOCUMENT_TYPE_SIGNATURES, documentTypeSignatures);
        return objectMapper.convertValue(signingResultData, LdpVPTokenSigningResult.class);
    }

    /**
     * Fetches selected credentials from the session cache
     */
    private List<DecryptedCredentialDTO> fetchSelectedCredentials(VerifiablePresentationSessionData sessionData, List<String> selectedCredentialIds) {

        log.debug("Fetching {} selected credentials from cache", selectedCredentialIds.size());

        if (sessionData.getMatchingCredentials() == null) {
            throw new IllegalStateException("No matching credentials found in session cache");
        }

        return sessionData.getMatchingCredentials().stream()
                .filter(credential -> selectedCredentialIds.contains(credential.getId()))
                .collect(Collectors.toList());
    }

    /**
     * Constructs unsigned VP token using the OpenID4VP JAR
     */
    private Map<FormatType, UnsignedVPToken> constructUnsignedVPToken(OpenID4VP openID4VP, List<DecryptedCredentialDTO> credentials, JWK jwk) throws IOException {

        log.debug("Constructing unsigned VP token for {} credentials", credentials.size());

        try {
            Map<String, Map<FormatType, List<Object>>> verifiableCredentials = convertCredentialsToJarFormat(credentials);
            String holderId = resolveHolderId(jwk);
            return openID4VP.constructUnsignedVPToken(verifiableCredentials, holderId, DEFAULT_SIGNATURE_SUITE);
        } catch (Exception e) {
            log.error("Failed to construct unsigned VP token", e);
            throw new IOException("Failed to construct VP token: " + e.getMessage(), e);
        }
    }

    /**
     * Resolves holderId from the user's public key using JWK format
     */
    private String resolveHolderId(JWK jwk) throws IOException {
        try {
            // Convert JWK to JSON string
            String jwkJson = objectMapper.writeValueAsString(jwk.toPublicJWK().toJSONObject());

            // Base64URL encode the JWK JSON
            String base64UrlEncodedJwk = Base64Util.encode(jwkJson);

            // Construct holderId: did:jwk:{base64url(jwk)}#0
            return OpenID4VPConstants.DID_JWK_PREFIX + base64UrlEncodedJwk + OpenID4VPConstants.DID_KEY_FRAGMENT;

        } catch (Exception e) {
            log.error("Failed to resolve holderId from public key", e);
            throw new IOException("Failed to resolve holderId: " + e.getMessage(), e);
        }
    }

    /**
     * Converts DecryptedCredentialDTO list to the format expected by the OpenID4VP JAR
     * Extracts the inner credential data from VCCredentialResponse wrapper to remove the "credential" wrapper
     */
    private Map<String, Map<FormatType, List<Object>>> convertCredentialsToJarFormat(List<DecryptedCredentialDTO> credentials) {

        return credentials.stream()
                .collect(Collectors.groupingBy(
                        DecryptedCredentialDTO::getId,
                        Collectors.collectingAndThen(
                                Collectors.toList(),
                                credList -> credList.stream()
                                        .collect(Collectors.groupingBy(
                                                credential -> {
                                                    // Get format and credential data
                                                    VCCredentialResponse vcCredentialResponse = credential.getCredential();
                                                    String credentialFormat = vcCredentialResponse.getFormat();
                                                    // Convert format string to FormatType enum
                                                    return mapStringToFormatType(credentialFormat);
                                                },
                                                Collectors.mapping(
                                                        credential -> credential.getCredential().getCredential(),
                                                        Collectors.toList()
                                                )
                                        ))
                        )
                ));
    }

    /**
     * Maps format string to FormatType enum
     */
    private FormatType mapStringToFormatType(String format) {
        if (format == null) {
            return FormatType.LDP_VC; // Default fallback
        }

        return switch (format.toLowerCase()) {
            case OpenID4VPConstants.FORMAT_LDP_VC_UNDERSCORE, 
                 OpenID4VPConstants.FORMAT_LDP_VC_HYPHEN -> FormatType.LDP_VC;
            case OpenID4VPConstants.FORMAT_MSO_MDOC_UNDERSCORE, 
                 OpenID4VPConstants.FORMAT_MSO_MDOC_HYPHEN -> FormatType.MSO_MDOC;
            // Add other supported formats as they become available in the OpenID4VP library
            default -> {
                log.warn("Unknown credential format: {}, defaulting to LDP_VC", format);
                yield FormatType.LDP_VC;
            }
        };
    }

    /**
     * Shares the verifiable presentation with the verifier
     * First calls OpenID4VP JAR's shareVerifiablePresentation method, then makes HTTP POST
     */
    private boolean shareVerifiablePresentation(Map<FormatType, LdpVPTokenSigningResult> vpTokenSigningResults, VerifiablePresentationSessionData sessionData, OpenID4VP openID4VP) {
        log.debug("Sharing verifiable presentation with verifier");

        try {
            // Step 1: Call OpenID4VP JAR's shareVerifiablePresentation method
            log.debug("Calling OpenID4VP JAR's shareVerifiablePresentation method");
            // Cast to the expected type for the JAR method
            @SuppressWarnings({"unchecked", "rawtypes"}) Map<FormatType, VPTokenSigningResult> jarMap = (Map) vpTokenSigningResults;
            String vpToken = openID4VP.shareVerifiablePresentation(jarMap);

            return vpToken.trim().isEmpty();

        } catch (Exception e) {
            log.error("Failed to share verifiable presentation with verifier", e);
            return false;
        }
    }

    /**
     * Stores presentation record in the database
     * Uses @Transactional to ensure atomicity of database operations
     */
    @Transactional
    private void storePresentationRecord(String walletId, String presentationId, SubmitPresentationRequestDTO request, VerifiablePresentationSessionData sessionData, boolean success, LocalDateTime requestedAt) {
        log.debug("Storing presentation record in database - success: {}", success);

        try {
            if (sessionData == null) {
                log.warn("Session data is null for presentationId: {}", presentationId);
                return;
            }

            // Extract verifier information from OpenID4VP object
            String verifierId = extractVerifierId(sessionData);
            String authRequest = extractVerifierAuthRequest(sessionData);
            String presentationData = createPresentationData(request, sessionData);

            // Create the presentation record
            VerifiablePresentation presentation = VerifiablePresentation.builder().id(presentationId).walletId(walletId)
                    .authRequest(authRequest).presentationData(presentationData).verifierId(verifierId)
                    .status(success ? OpenID4VPConstants.DB_STATUS_SUCCESS : OpenID4VPConstants.DB_STATUS_ERROR).requestedAt(requestedAt)
                    .consent(true)
                    .build();

            // Save to database
            verifiablePresentationRepository.save(presentation);

            log.info("Presentation record stored successfully - recordId: {}, walletId: {}, presentationId: {}, status: {}", presentationId, walletId, presentationId, success ? OpenID4VPConstants.DB_STATUS_SUCCESS : OpenID4VPConstants.DB_STATUS_ERROR);

        } catch (Exception e) {
            // Critical failure - log with high severity and include all context
            log.error("CRITICAL: Failed to store presentation record - walletId: {}, presentationId: {}, verifierId: {}, success: {}", 
                    walletId, presentationId, 
                    sessionData != null ? extractVerifierId(sessionData) : "unknown", 
                    success, e);
            // Note: Consider adding metrics/alerting here for production monitoring
            // Example: metrics.incrementCounter("presentation.storage.failures");
        }
    }

    /**
     * Extracts verifier ID from session data
     */
    private String extractVerifierId(VerifiablePresentationSessionData sessionData) {
        try {
            // Since authorizationRequest is a URL, we need to extract client_id from URL parameters
            if (sessionData.getAuthorizationRequest() != null) {
                String authRequestUrl = sessionData.getAuthorizationRequest();
                return UrlParameterUtils.extractClientIdFromUrl(authRequestUrl);
            }
        } catch (Exception e) {
            log.warn("Failed to extract verifier ID", e);
        }
        return UNKNOWN_VERIFIER;
    }

    /**
     * Extracts verifier authorization request as JSON
     */
    private String extractVerifierAuthRequest(VerifiablePresentationSessionData sessionData) {
        try {
            if (sessionData.getAuthorizationRequest() != null) {
                // Convert the URL string to a JSON object
                Map<String, Object> authRequestData = new HashMap<>();
                authRequestData.put(OpenID4VPConstants.AUTHORIZATION_REQUEST_URL, sessionData.getAuthorizationRequest());
                return objectMapper.writeValueAsString(authRequestData);
            }
        } catch (Exception e) {
            log.warn("Failed to extract verifier auth request", e);
        }
        return EMPTY_JSON;
    }

    /**
     * Creates presentation data JSON with selected credentials and metadata
     */
    private String createPresentationData(SubmitPresentationRequestDTO request, VerifiablePresentationSessionData sessionData) {
        try {
            Map<String, Object> presentationData = new HashMap<>();
            presentationData.put(OpenID4VPConstants.SELECTED_CREDENTIALS, request.getSelectedCredentials());

            return objectMapper.writeValueAsString(presentationData);
        } catch (Exception e) {
            log.warn("Failed to create presentation data", e);
            return EMPTY_JSON;
        }
    }

    /**
     * Validates all input parameters for presentation submission
     * 
     * @throws IllegalArgumentException if any input is invalid
     */
    private void validateInputs(VerifiablePresentationSessionData sessionData, 
                                String walletId, 
                                String presentationId, 
                                SubmitPresentationRequestDTO request, 
                                String base64Key) {
        if (sessionData == null) {
            log.error("Session data cannot be null");
            throw new IllegalArgumentException("Session data cannot be null");
        }
        
        if (walletId == null || walletId.isBlank()) {
            log.error("Wallet ID cannot be null or empty");
            throw new IllegalArgumentException("Wallet ID cannot be null or empty");
        }
        
        if (presentationId == null || presentationId.isBlank()) {
            log.error("Presentation ID cannot be null or empty");
            throw new IllegalArgumentException("Presentation ID cannot be null or empty");
        }
        
        if (request == null) {
            log.error("Request cannot be null");
            throw new IllegalArgumentException("Request cannot be null");
        }
        
        if (request.getSelectedCredentials() == null || request.getSelectedCredentials().isEmpty()) {
            log.error("Selected credentials cannot be null or empty");
            throw new IllegalArgumentException("Selected credentials cannot be null or empty");
        }
        
        if (base64Key == null || base64Key.isBlank()) {
            log.error("Base64 key cannot be null or empty");
            throw new IllegalArgumentException("Base64 key cannot be null or empty");
        }
        
        log.debug("Input validation passed for walletId: {}, presentationId: {}", walletId, presentationId);
    }
}
