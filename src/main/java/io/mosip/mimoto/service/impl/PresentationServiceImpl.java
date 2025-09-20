package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.AvailableCredentialDTO;
import io.mosip.mimoto.dto.MatchingCredentialsResponseDTO;
import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.dto.VerifiablePresentationVerifierDTO;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponseProof;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.openid.presentation.*;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.model.VerifiableCredential;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.WalletPresentationUtil;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static io.mosip.mimoto.util.JwtUtils.extractJwtPayloadFromSdJwt;
import static io.mosip.mimoto.util.JwtUtils.parseJwtHeader;

@Slf4j
@Service
public class PresentationServiceImpl implements PresentationService {

    // Constants for credential matching
    private static final String JSON_PATH_PREFIX = "$.";
    private static final String TYPE_PATH = "$.type";
    private static final String LDP_VC_FORMAT = "ldp_vc";
    private static final String PROOF_TYPE_KEY = "proof_type";

    @Autowired
    private DataShareServiceImpl dataShareService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RestApiClient restApiClient;

    @Autowired
    private VerifierService verifierService;

    @Autowired
    private OpenID4VPFactory openID4VPFactory;

    @Autowired
    private WalletCredentialsRepository walletCredentialsRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Autowired
    private IssuersService issuersService;

    @Value("${mosip.inji.ovp.redirect.url.pattern}")
    private String injiOvpRedirectURLPattern;

    @Value("${server.tomcat.max-http-response-header-size:65536}")
    private Integer maximumResponseHeaderSize;

    @Override
    public VerifiablePresentationResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId) throws ApiNotAccessibleException, IOException, URISyntaxException {
        String presentationId = UUID.randomUUID().toString();

        //Initialize OpenID4VP instance with presentationId as traceability id for each new Verifiable Presentation request
        OpenID4VP openID4VP = openID4VPFactory.create(presentationId);

        List<Verifier> preRegisteredVerifiers = getPreRegisteredVerifiers();
        boolean shouldValidateClient = verifierService.isVerifierClientPreregistered(preRegisteredVerifiers, urlEncodedVPAuthorizationRequest);
        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, preRegisteredVerifiers, shouldValidateClient);
        VerifiablePresentationVerifierDTO verifiablePresentationVerifierDTO = createVPResponseVerifierDTO(preRegisteredVerifiers, authorizationRequest, walletId);
        VerifiablePresentationSessionData verifiablePresentationSessionData = new VerifiablePresentationSessionData(openID4VP, Instant.now());

        return new VerifiablePresentationResponseDTO(presentationId, verifiablePresentationVerifierDTO, verifiablePresentationSessionData);
    }

    private VerifiablePresentationVerifierDTO createVPResponseVerifierDTO(List<Verifier> preRegisteredVerifiers, AuthorizationRequest authorizationRequest, String walletId) throws ApiNotAccessibleException, IOException {

        boolean isVerifierPreRegisteredWithWallet = preRegisteredVerifiers.stream().map(
                Verifier::getClientId).toList().contains(authorizationRequest.getClientId());

        boolean isVerifierTrustedByWallet = verifierService.isVerifierTrustedByWallet(authorizationRequest.getClientId(), walletId);

        String clientName = Optional.ofNullable(authorizationRequest.getClientMetadata())
                .map(ClientMetadata::getClientName)
                .filter(name -> !name.isBlank())
                .orElse(authorizationRequest.getClientId());

        String logo = Optional.ofNullable(authorizationRequest.getClientMetadata())
                .map(ClientMetadata::getLogoUri)
                .orElse(null);

        return new VerifiablePresentationVerifierDTO(
                authorizationRequest.getClientId(),
                clientName,
                logo,
                isVerifierTrustedByWallet,
                isVerifierPreRegisteredWithWallet,
                authorizationRequest.getRedirectUri()
        );
    }

    private List<Verifier> getPreRegisteredVerifiers() throws ApiNotAccessibleException, IOException {

        return verifierService.getTrustedVerifiers().getVerifiers().stream()
                .map(WalletPresentationUtil::mapToVerifier)
                .toList();
    }

    @Override
    public String authorizePresentation(PresentationRequestDTO presentationRequestDTO) throws IOException {
        VCCredentialResponse vcCredentialResponse = dataShareService.downloadCredentialFromDataShare(presentationRequestDTO);
        PresentationDefinitionDTO presentationDefinitionDTO = presentationRequestDTO.getPresentationDefinition();
        if (presentationDefinitionDTO == null) {
            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        }

        log.info("Started the Constructing VP Token");

        return presentationDefinitionDTO.getInputDescriptors()
                .stream()
                .findFirst()
                .map(inputDescriptorDTO -> {
                    try {
                        return processInputDescriptor(vcCredentialResponse, inputDescriptorDTO, presentationRequestDTO, presentationDefinitionDTO);
                    } catch (JsonProcessingException e) {
                        throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
                    }
                })
                .orElseThrow(() -> new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage()));
    }

    private String processInputDescriptor(VCCredentialResponse vcCredentialResponse, InputDescriptorDTO inputDescriptorDTO,
                                          PresentationRequestDTO presentationRequestDTO, PresentationDefinitionDTO presentationDefinitionDTO) throws JsonProcessingException {
        String format = vcCredentialResponse.getFormat();
        VerifiablePresentationDTO vpDTO;

        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            VCCredentialProperties ldpCredential = objectMapper.convertValue(vcCredentialResponse.getCredential(), VCCredentialProperties.class);
            if (inputDescriptorDTO.getFormat().get("ldpVc").get("proofTypes")
                    .stream().anyMatch(proofType -> ldpCredential.getProof().getType().equals(proofType))) {
                vpDTO = constructVerifiablePresentationString(ldpCredential);
            } else {
                throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
            }
        } else if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(format)
                || CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
            String credential = objectMapper.convertValue(vcCredentialResponse.getCredential(), String.class);
            Map<String, Object> jwtHeaders = parseJwtHeader(credential);
            String responseAlgo = (String) jwtHeaders.get("alg");
            if (inputDescriptorDTO.getFormat().get(format).get("sd-jwt_alg_values")
                    .stream().anyMatch(responseAlgo::equals)) {
                vpDTO = constructVerifiablePresentationStringForSDjwt(credential);
            } else {
                throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
            }
        } else {
            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        }

        // Create VP Token
        String vpToken = createVpToken(vpDTO);
        // Create PresentationSubmission
        String presentationSubmission = constructPresentationSubmission(format, vpDTO, presentationDefinitionDTO, inputDescriptorDTO);

        // If response_uri is present, POST the response
        if (presentationRequestDTO.getResponseMode() != null && "direct_post".equals(presentationRequestDTO.getResponseMode())) {
            return postVpToResponseUri(
                    presentationRequestDTO.getResponseUri(),
                    vpToken,
                    presentationSubmission,
                    presentationRequestDTO.getState(),
                    presentationRequestDTO.getNonce()
            );
        }

        // Otherwise, do redirect
        String redirectString = buildRedirectString(
                vpToken,
                presentationRequestDTO.getRedirectUri(),
                presentationSubmission
        );

        if (redirectString.length() > maximumResponseHeaderSize) {
            throw new VPNotCreatedException(ErrorConstants.URI_TOO_LONG.getErrorCode(), ErrorConstants.URI_TOO_LONG.getErrorMessage());
        }

        return redirectString;
    }

    private String createVpToken(VerifiablePresentationDTO vpDTO) throws JsonProcessingException {
        return objectMapper.writeValueAsString(vpDTO);
    }

    private String buildRedirectString(String vpToken, String redirectUri, String presentationSubmission) {
        return String.format(injiOvpRedirectURLPattern,
                redirectUri,
                Base64.getUrlEncoder().encodeToString(vpToken.getBytes(StandardCharsets.UTF_8)),
                URLEncoder.encode(presentationSubmission, StandardCharsets.UTF_8));
    }

    private String postVpToResponseUri(String responseUri, String vpToken, String presentationSubmission, String state, String nonce) throws JsonProcessingException {
        Map<String, Object> postRequest = new HashMap<>();
        postRequest.put("vp_token", vpToken);
        postRequest.put("presentation_submission", objectMapper.readTree(presentationSubmission));

        if (state != null) {
            postRequest.put("state", state);
        }

        if (nonce != null) {
            postRequest.put("nonce", nonce);
        }

        log.info("Posting VP to response_uri: {}", responseUri);
        Map<String, Object> postResponse = null;
        try {
            postResponse = restApiClient.postApi(
                    responseUri,
                    MediaType.APPLICATION_JSON,
                    postRequest,
                    Map.class
            );
        } catch (Exception e) {
            log.error("Exception while submitting the vp_token to the response_uri", e);
            throw new VPNotCreatedException(ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode(), ErrorConstants.INTERNAL_SERVER_ERROR.getErrorMessage());
        }

        log.info("Response from verifier after POST: {}", postResponse);

        // Check for redirect_uri in response
        String redirectUri = (String) postResponse.get("redirect_uri");
        if (redirectUri != null && !redirectUri.isEmpty()) {
            return redirectUri;
        }

        // Fallback behavior if redirect_uri is not provided
        log.warn("No redirect_uri received from verifier in POST response. Falling back to response_uri.");
        return responseUri + "?status=vp_sent";
    }

    private VerifiablePresentationDTO constructVerifiablePresentationString(VCCredentialProperties vcCredentialProperties) {
        Object context = vcCredentialProperties.getContext();
        List<Object> contextList = (context instanceof List<?> list)
                ? (List<Object>) list
                : List.of(context);

        return VerifiablePresentationDTO.builder()
                .verifiableCredential(Collections.singletonList(vcCredentialProperties))
                .type(Collections.singletonList("VerifiablePresentation"))
                .context(contextList)
                .build();
    }

    private VerifiablePresentationDTO constructVerifiablePresentationStringForSDjwt(String vcCredential) {
        return VerifiablePresentationDTO.builder()
                .verifiableCredential(Collections.singletonList(vcCredential))
                .type(Collections.singletonList("VerifiablePresentation"))
                .build();
    }

    private String constructPresentationSubmission(String format, VerifiablePresentationDTO verifiablePresentationDTO, PresentationDefinitionDTO presentationDefinitionDTO, InputDescriptorDTO inputDescriptorDTO) throws JsonProcessingException {
        AtomicInteger atomicInteger = new AtomicInteger(0);
        List<SubmissionDescriptorDTO> submissionDescriptorDTOList = verifiablePresentationDTO.getVerifiableCredential()
                .stream().map(verifiableCredential -> SubmissionDescriptorDTO.builder()
                        .id(inputDescriptorDTO.getId())
                        .format(format)
                        .path("$.verifiableCredential[" + atomicInteger.getAndIncrement() + "]").build()).collect(Collectors.toList());

        PresentationSubmissionDTO presentationSubmissionDTO = PresentationSubmissionDTO.builder()
                .id(UUID.randomUUID().toString())
                .definition_id(presentationDefinitionDTO.getId())
                .descriptorMap(submissionDescriptorDTOList).build();
        return objectMapper.writeValueAsString(presentationSubmissionDTO);
    }

    public PresentationDefinitionDTO constructPresentationDefinition(VCCredentialResponse vcRes) {
        String vcFormat = vcRes.getFormat();
        List<InputDescriptorDTO> inputDescriptors = new ArrayList<>();

        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(vcFormat)) {
            VCCredentialProperties ldp = objectMapper.convertValue(vcRes.getCredential(), VCCredentialProperties.class);
            String lastType = ldp.getType().get(ldp.getType().size() - 1);
            String proofType = Optional.ofNullable(ldp.getProof()).map(VCCredentialResponseProof::getType).orElse(null);

            FieldDTO field = FieldDTO.builder()
                    .path(new String[]{"$.type"})
                    .filter(FilterDTO.builder().type("String").pattern(lastType).build())
                    .build();

            Map<String, Map<String, List<String>>> format = Map.of(
                    "ldpVc", Map.of("proofTypes", List.of(proofType))
            );

            inputDescriptors.add(InputDescriptorDTO.builder()
                    .id(UUID.randomUUID().toString())
                    .constraints(ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build())
                    .format(format)
                    .build());

        } else if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(vcFormat) || CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(vcFormat)) {
            Map<String, Object> jwtPayload = extractJwtPayloadFromSdJwt((String) vcRes.getCredential());
            List<?> typeList = (List<?>) jwtPayload.get("type");
            String lastType = null;
            if (typeList != null && !typeList.isEmpty()) {
                Object lastItem = typeList.get(typeList.size() - 1);
                if (lastItem instanceof Map) {
                    Object value = ((Map<?, ?>) lastItem).get("_value");
                    lastType = value != null ? value.toString() : null;
                } else {
                    lastType = lastItem.toString();
                }
            }
            Map<String, Object> jwtHeaders = parseJwtHeader((String) vcRes.getCredential());
            String algo = (String) jwtHeaders.get("alg");

            FieldDTO field = FieldDTO.builder()
                    .path(new String[]{"$.type"})
                    .filter(FilterDTO.builder().type("String").pattern(lastType).build())
                    .build();
            Map<String, Map<String, List<String>>> format = Map.of(
                    vcRes.getFormat(), Map.of(
                            "sd-jwt_alg_values", List.of(algo)
                    )
            );
            inputDescriptors.add(InputDescriptorDTO.builder()
                    .id(UUID.randomUUID().toString())
                    .constraints(ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build())
                    .format(format)
                    .build());

        }
        return PresentationDefinitionDTO.builder()
                .id(UUID.randomUUID().toString())
                .inputDescriptors(inputDescriptors)
                .build();
    }

    @Override
    public MatchingCredentialsResponseDTO getMatchingCredentials(PresentationDefinitionDTO presentationDefinition, String walletId, String base64Key) throws ApiNotAccessibleException, IOException {
        log.info("Getting matching credentials for walletId: {}", walletId);

        try {
            validateInputParameters(presentationDefinition, walletId, base64Key);

            List<VerifiableCredential> walletCredentials = getWalletCredentials(walletId);
            if (walletCredentials.isEmpty()) {
                return createEmptyResponseWithMissingClaims(presentationDefinition);
            }

            List<AvailableCredentialDTO> availableCredentials;
            try {
                availableCredentials = processCredentialsForMatching(walletCredentials, presentationDefinition, base64Key);
            } catch (Exception e) {
                log.error("Error processing credentials for matching: {}", e.getMessage());
                throw new ApiNotAccessibleException();
            }

            List<String> missingClaims;
            try {
                missingClaims = extractMissingClaims(walletCredentials, presentationDefinition, base64Key);
            } catch (Exception e) {
                log.error("Error extracting missing claims: {}", e.getMessage());
                missingClaims = new ArrayList<>();
            }

            logMatchingResults(availableCredentials, missingClaims, walletId);

            return MatchingCredentialsResponseDTO.builder().availableCredentials(availableCredentials).missingClaims(missingClaims).build();

        } catch (IllegalArgumentException e) {
            log.error("Invalid input parameters for getMatchingCredentials: {}", e.getMessage());
            throw e;
        } catch (ApiNotAccessibleException e) {
            log.error("API not accessible while getting matching credentials for walletId: {}", walletId, e);
            throw e;
        }
    }

    /**
     * Validates input parameters for the getMatchingCredentials method
     */
    private void validateInputParameters(PresentationDefinitionDTO presentationDefinition, String walletId, String base64Key) {
        if (walletId == null || walletId.trim().isEmpty()) {
            throw new IllegalArgumentException("Wallet ID cannot be null or empty");
        }

        if (base64Key == null || base64Key.trim().isEmpty()) {
            throw new IllegalArgumentException("Base64 key cannot be null or empty");
        }

        if (presentationDefinition == null) {
            throw new IllegalArgumentException("Presentation definition cannot be null");
        }

        if (presentationDefinition.getInputDescriptors() == null || presentationDefinition.getInputDescriptors().isEmpty()) {
            throw new IllegalArgumentException("Presentation definition must contain at least one input descriptor");
        }

        // Validate each input descriptor
        for (int i = 0; i < presentationDefinition.getInputDescriptors().size(); i++) {
            InputDescriptorDTO descriptor = presentationDefinition.getInputDescriptors().get(i);
            if (descriptor.getId() == null || descriptor.getId().trim().isEmpty()) {
                throw new IllegalArgumentException("Input descriptor at index " + i + " must have a valid ID");
            }
        }
    }


    /**
     * Creates an empty response with missing claims when no wallet credentials are found
     */
    private MatchingCredentialsResponseDTO createEmptyResponseWithMissingClaims(PresentationDefinitionDTO presentationDefinition) {
        log.info("No credentials found for wallet");
        return MatchingCredentialsResponseDTO.builder().availableCredentials(Collections.emptyList()).missingClaims(extractRequiredClaims(presentationDefinition)).build();
    }

    /**
     * Retrieves wallet credentials from the repository
     */
    private List<VerifiableCredential> getWalletCredentials(String walletId) {
        return walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(walletId);
    }

    /**
     * Processes all credentials to find matches against input descriptors
     */
    private List<AvailableCredentialDTO> processCredentialsForMatching(List<VerifiableCredential> walletCredentials, PresentationDefinitionDTO presentationDefinition, String base64Key) throws Exception {

        log.info("Starting credential matching process for {} credentials against {} input descriptors", walletCredentials.size(), presentationDefinition.getInputDescriptors().size());

        List<AvailableCredentialDTO> availableCredentials = new ArrayList<>();
        Set<String> addedCredentialIds = new HashSet<>();

        for (VerifiableCredential credential : walletCredentials) {
            VCCredentialResponse vcCredentialResponse = decryptAndParseCredential(credential, base64Key);
            processCredentialAgainstInputDescriptors(credential, vcCredentialResponse, presentationDefinition, availableCredentials, addedCredentialIds);
        }

        log.info("Completed credential matching process - found {} matching credentials", availableCredentials.size());
        return availableCredentials;
    }

    /**
     * Decrypts and parses a credential into VCCredentialResponse
     */
    private VCCredentialResponse decryptAndParseCredential(VerifiableCredential credential, String base64Key) throws Exception {
        if (credential == null) {
            throw new IllegalArgumentException("Credential cannot be null");
        }

        if (credential.getCredential() == null) {
            throw new IllegalArgumentException("Credential data cannot be null");
        }

        String decryptedCredential = encryptionDecryptionUtil.decryptCredential(credential.getCredential(), base64Key);
        if (decryptedCredential == null || decryptedCredential.trim().isEmpty()) {
            throw new IllegalArgumentException("Failed to decrypt credential or decrypted data is empty");
        }

        return objectMapper.readValue(decryptedCredential, VCCredentialResponse.class);
    }

    /**
     * Processes a single credential against all input descriptors
     */
    private boolean processCredentialAgainstInputDescriptors(VerifiableCredential credential, VCCredentialResponse vcCredentialResponse, PresentationDefinitionDTO presentationDefinition, List<AvailableCredentialDTO> availableCredentials, Set<String> addedCredentialIds) {

        boolean foundMatch = false;

        for (InputDescriptorDTO inputDescriptor : presentationDefinition.getInputDescriptors()) {
            if (matchesInputDescriptor(vcCredentialResponse, inputDescriptor, presentationDefinition)) {
                if (!addedCredentialIds.contains(credential.getId())) {
                    AvailableCredentialDTO availableCredential = buildAvailableCredential(credential, vcCredentialResponse);
                    availableCredentials.add(availableCredential);
                    addedCredentialIds.add(credential.getId());
                    foundMatch = true;
                }
                break;
            }
        }

        return foundMatch;
    }

    /**
     * Extracts missing claims from input descriptors that have no matching credentials
     */
    private List<String> extractMissingClaims(List<VerifiableCredential> walletCredentials, PresentationDefinitionDTO presentationDefinition, String base64Key) throws JsonProcessingException, IllegalArgumentException {

        log.info("Starting missing claims extraction for {} input descriptors", presentationDefinition.getInputDescriptors().size());

        List<String> missingClaims = new ArrayList<>();

        for (InputDescriptorDTO inputDescriptor : presentationDefinition.getInputDescriptors()) {
            if (!hasMatchingCredential(walletCredentials, inputDescriptor, presentationDefinition, base64Key)) {
                missingClaims.addAll(extractClaimsFromInputDescriptor(inputDescriptor));
            }
        }

        log.info("Completed missing claims extraction - found {} missing claims", missingClaims.size());
        return missingClaims;
    }

    /**
     * Checks if any credential matches the given input descriptor
     */
    private boolean hasMatchingCredential(List<VerifiableCredential> walletCredentials, InputDescriptorDTO inputDescriptor, PresentationDefinitionDTO presentationDefinition, String base64Key) throws JsonProcessingException, IllegalArgumentException {

        for (VerifiableCredential credential : walletCredentials) {
            try {
                VCCredentialResponse vcCredentialResponse = decryptAndParseCredential(credential, base64Key);
                if (matchesInputDescriptor(vcCredentialResponse, inputDescriptor, presentationDefinition)) {
                    return true;
                }
            } catch (Exception e) {
                log.error("Failed to decrypt credential {} for missing claims check: {}", credential.getId(), e.getMessage());
            }
        }
        return false;
    }

    /**
     * Extracts claims from an input descriptor's constraints
     */
    private List<String> extractClaimsFromInputDescriptor(InputDescriptorDTO inputDescriptor) {
        List<String> claims = new ArrayList<>();

        if (inputDescriptor.getConstraints() != null && inputDescriptor.getConstraints().getFields() != null) {

            for (FieldDTO field : inputDescriptor.getConstraints().getFields()) {
                if (field.getPath() != null && field.getPath().length > 0) {
                    claims.addAll(Arrays.asList(field.getPath()));
                }
            }
        }

        return claims;
    }

    /**
     * Logs the final matching results
     */
    private void logMatchingResults(List<AvailableCredentialDTO> availableCredentials, List<String> missingClaims, String walletId) {
        log.info("Matching completed for walletId: {} - Found {} matching credentials and {} missing claims", walletId, availableCredentials.size(), missingClaims.size());
    }

    /**
     * Simple method to check if a credential matches an input descriptor
     */
    private boolean matchesInputDescriptor(VCCredentialResponse vc, InputDescriptorDTO inputDescriptor, PresentationDefinitionDTO presentationDefinition) {

        Map<String, Map<String, List<String>>> formatToCheck = inputDescriptor.getFormat();

        if (!matchesFormat(vc, formatToCheck)) {
            return false;
        }

        // Check constraints - if no constraints specified, accept the credential
        if (inputDescriptor.getConstraints() != null && inputDescriptor.getConstraints().getFields() != null) {
            return matchesConstraints(vc, inputDescriptor.getConstraints());
        }
        return true;
    }

    /**
     * Check if VC format matches the input descriptor format
     */
    private boolean matchesFormat(VCCredentialResponse vc, Map<String, Map<String, List<String>>> descriptorFormat) {
        if (descriptorFormat == null) {
            return true; // No format specified, any format is acceptable
        }

        String vcFormat = vc.getFormat();

        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(vcFormat)) {
            if (descriptorFormat.containsKey(LDP_VC_FORMAT)) {
                Map<String, List<String>> ldpVcFormat = descriptorFormat.get(LDP_VC_FORMAT);

                if (ldpVcFormat.containsKey(PROOF_TYPE_KEY)) {
                    VCCredentialProperties ldpCredential = objectMapper.convertValue(vc.getCredential(), VCCredentialProperties.class);
                    String vcProofType = ldpCredential.getProof() != null ? ldpCredential.getProof().getType() : null;
                    List<String> requiredProofTypes = ldpVcFormat.get(PROOF_TYPE_KEY);
                    boolean matches = vcProofType != null && requiredProofTypes.contains(vcProofType);

                    return matches;
                } else {
                    return true;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Check if VC matches the constraints
     */
    private boolean matchesConstraints(VCCredentialResponse vc, ConstraintsDTO constraints) {
        if (constraints.getFields() == null) {
            return true; // No constraints, any credential is acceptable
        }

        for (int i = 0; i < constraints.getFields().length; i++) {
            FieldDTO field = constraints.getFields()[i];

            if (field.getPath() == null || field.getPath().length == 0) {
                continue;
            }

            boolean fieldMatches = false;
            for (String path : field.getPath()) {
                if (matchesFieldPath(vc, path, field.getFilter())) {
                    fieldMatches = true;
                    break;
                }
            }

            if (!fieldMatches) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if a specific field path matches the filter
     */
    private boolean matchesFieldPath(VCCredentialResponse vc, String path, FilterDTO filter) {
        try {
            Object credentialData = getCredentialData(vc);

            List<Object> matches = evaluateJsonPath(path, credentialData);

            if (matches == null || matches.isEmpty()) {
                return false;
            }

            for (Object match : matches) {
                if (matchesFilter(match, filter)) {
                    return true;
                }
            }

            return false;
        } catch (JsonProcessingException | NoSuchFieldException | IllegalAccessException e) {
            log.error("Error checking field path {}: {}", path, e.getMessage());
            return false;
        }
    }

    /**
     * Get credential data based on format
     */
    private Object getCredentialData(VCCredentialResponse vc) {
        String format = vc.getFormat();

        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            Object credentialData = vc.getCredential();

            if (credentialData instanceof Map) {
                return credentialData;
            } else {
                return objectMapper.convertValue(credentialData, VCCredentialProperties.class);
            }
        } else if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(format) || CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
            String credential = objectMapper.convertValue(vc.getCredential(), String.class);
            return extractJwtPayloadFromSdJwt(credential);
        }

        return vc.getCredential();
    }

    /**
     * Check if a match satisfies the filter
     */
    private boolean matchesFilter(Object match, FilterDTO filter) {
        if (filter == null) {
            return true; // No filter, any match is acceptable
        }

        if (filter.getPattern() != null) {
            String matchValue = match.toString();
            return matchValue.contains(filter.getPattern());
        }

        return true;
    }

    /**
     * Evaluates JSONPath and returns matching values
     */
    private List<Object> evaluateJsonPath(String path, Object json) throws JsonProcessingException, NoSuchFieldException, IllegalAccessException {
        if (path == null || path.trim().isEmpty()) {
            return Collections.emptyList();
        }

        if (!path.startsWith(JSON_PATH_PREFIX)) {
            return Collections.emptyList();
        }

        if (json == null) {
            return Collections.emptyList();
        }

        String[] pathParts = path.substring(2).split("\\.");
        Object current = json;

        for (String part : pathParts) {
            if (current instanceof Map) {
                @SuppressWarnings("unchecked") Map<String, Object> map = (Map<String, Object>) current;
                current = map.get(part);
            } else if (current instanceof List) {
                @SuppressWarnings("unchecked") List<Object> list = (List<Object>) current;
                try {
                    int index = Integer.parseInt(part);
                    if (index >= 0 && index < list.size()) {
                        current = list.get(index);
                    } else {
                        return Collections.emptyList();
                    }
                } catch (NumberFormatException e) {
                    return Collections.emptyList();
                }
            } else if (current != null) {
                try {
                    // First try using convertValue which is more efficient
                    @SuppressWarnings("unchecked") Map<String, Object> map = objectMapper.convertValue(current, Map.class);
                    current = map.get(part);
                } catch (Exception convertException) {
                    // Fallback to serialize/deserialize approach
                    if (objectMapper.canSerialize(current.getClass())) {
                        String jsonString = objectMapper.writeValueAsString(current);
                        @SuppressWarnings("unchecked") Map<String, Object> map = objectMapper.readValue(jsonString, Map.class);
                        current = map.get(part);
                    } else {
                        // If can't serialize, try direct field access using reflection
                        java.lang.reflect.Field field = current.getClass().getDeclaredField(part);
                        field.setAccessible(true);
                        current = field.get(current);
                    }
                }
            } else {
                return Collections.emptyList();
            }

            if (current == null) {
                return Collections.emptyList();
            }
        }

        // Special handling for $.type path - return all type values for matching
        if (TYPE_PATH.equals(path) && current instanceof List) {
            @SuppressWarnings("unchecked") List<Object> typeList = (List<Object>) current;
            return new ArrayList<>(typeList);
        }

        return Collections.singletonList(current);
    }

    private List<String> extractRequiredClaims(PresentationDefinitionDTO presentationDefinition) {
        Set<String> requiredClaims = new HashSet<>();

        if (presentationDefinition.getInputDescriptors() != null) {
            for (InputDescriptorDTO inputDescriptor : presentationDefinition.getInputDescriptors()) {
                if (inputDescriptor.getConstraints() != null && inputDescriptor.getConstraints().getFields() != null) {
                    for (FieldDTO field : inputDescriptor.getConstraints().getFields()) {
                        if (field.getPath() != null && field.getPath().length > 0) {
                            String path = field.getPath()[0];
                            if (path.startsWith(JSON_PATH_PREFIX)) {
                                requiredClaims.add(path); // Keep the full JSONPath including "$."
                            }
                        }
                    }
                }
            }
        }
        return new ArrayList<>(requiredClaims);
    }

    private AvailableCredentialDTO buildAvailableCredential(VerifiableCredential credential, VCCredentialResponse vcCredentialResponse) {
        try {
            // Get issuer config to extract proper display name and logo
            String issuerId = credential.getCredentialMetadata().getIssuerId();
            String credentialType = credential.getCredentialMetadata().getCredentialType();

            String credentialTypeDisplayName = "Unknown Credential";
            String credentialTypeLogo = null;

            try {
                IssuerConfig issuerConfig = issuersService.getIssuerConfig(issuerId, credentialType);
                if (issuerConfig != null) {
                    // Use the same approach as fetchAllCredentialsForWallet
                    VerifiableCredentialResponseDTO credentialResponse = VerifiableCredentialResponseDTO.fromIssuerConfig(issuerConfig, "en", credential.getId());
                    credentialTypeDisplayName = credentialResponse.getCredentialTypeDisplayName();
                    credentialTypeLogo = credentialResponse.getCredentialTypeLogo();
                }
            } catch (InvalidIssuerIdException | ApiNotAccessibleException e) {
                log.warn("Failed to fetch issuer config for issuerId: {}, credentialType: {}", issuerId, credentialType, e);
            }

            return AvailableCredentialDTO.builder().credentialId(credential.getId()).credentialTypeDisplayName(credentialTypeDisplayName).credentialTypeLogo(credentialTypeLogo).format(vcCredentialResponse.getFormat()).build();
        } catch (Exception e) {
            log.warn("Error building available credential for credential {}: {}", credential.getId(), e.getMessage());
            return AvailableCredentialDTO.builder().credentialId(credential.getId()).credentialTypeDisplayName("Unknown Credential").credentialTypeLogo(null).format(vcCredentialResponse.getFormat()).build();
        }
    }

    private PresentationDefinitionDTO convertToPresentationDefinitionDTO(PresentationDefinition presentationDefinition) {
        if (presentationDefinition == null) {
            return null;
        }

        List<InputDescriptorDTO> inputDescriptors = new ArrayList<>();
        for (InputDescriptor inputDescriptor : presentationDefinition.getInputDescriptors()) {
            InputDescriptorDTO inputDescriptorDTO = convertToInputDescriptorDTO(inputDescriptor);
            inputDescriptors.add(inputDescriptorDTO);
        }

        return PresentationDefinitionDTO.builder().id(presentationDefinition.getId()).inputDescriptors(inputDescriptors).build();
    }

    private InputDescriptorDTO convertToInputDescriptorDTO(InputDescriptor inputDescriptor) {
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        if (inputDescriptor.getFormat() != null) {
            for (Map.Entry<String, Map<String, List<String>>> entry : inputDescriptor.getFormat().entrySet()) {
                format.put(entry.getKey(), entry.getValue());
            }
        }

        ConstraintsDTO constraints = null;
        if (inputDescriptor.getConstraints() != null) {
            FieldDTO[] fields = null;
            if (inputDescriptor.getConstraints().getFields() != null) {
                fields = new FieldDTO[inputDescriptor.getConstraints().getFields().size()];
                for (int i = 0; i < inputDescriptor.getConstraints().getFields().size(); i++) {
                    Fields field = inputDescriptor.getConstraints().getFields().get(i);
                    fields[i] = FieldDTO.builder().path(field.getPath().toArray(new String[0])).filter(FilterDTO.builder().type(field.getFilter() != null ? field.getFilter().getType() : null).pattern(field.getFilter() != null ? field.getFilter().getPattern() : null).build()).build();
                }
            }
            constraints = ConstraintsDTO.builder().fields(fields).limitDisclosure(inputDescriptor.getConstraints().getLimitDisclosure()).build();
        }

        return InputDescriptorDTO.builder().id(inputDescriptor.getId()).format(format).constraints(constraints).build();
    }

}
