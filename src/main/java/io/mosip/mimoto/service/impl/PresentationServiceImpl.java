package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.dto.VerifiablePresentationVerifierDTO;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponseProof;
import io.mosip.mimoto.dto.openid.presentation.*;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata;
import io.mosip.mimoto.util.RestApiClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.io.IOException;
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

    @Value("${mosip.inji.ovp.redirect.url.pattern}")
    private String injiOvpRedirectURLPattern;

    @Value("${server.tomcat.max-http-response-header-size:65536}")
    private Integer maximumResponseHeaderSize;

    @Override
    public VerifiablePresentationResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId) throws ApiNotAccessibleException, IOException {
        String presentationId = UUID.randomUUID().toString();

        //Initialize OpenID4VP instance with presentationId as traceability id for each new Verifiable Presentation request
        OpenID4VP openID4VP = openID4VPFactory.create(presentationId);

        List<Verifier> preRegisteredVerifiers = getPreRegisteredVerifiers();
        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, preRegisteredVerifiers);
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
                .map(verifierDTO -> new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris()))
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
}
