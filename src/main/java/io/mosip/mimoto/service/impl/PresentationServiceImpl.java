package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.presentation.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.OpenIdErrorMessages;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.service.VerifiersService;
import io.mosip.mimoto.util.RestApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

@Service
public class PresentationServiceImpl implements PresentationService {

    @Autowired
    VerifiersService verifiersService;

    @Autowired
    DataShareServiceImpl dataShareService;

    @Autowired
    RestApiClient restApiClient;

    @Autowired
    ObjectMapper objectMapper;

    @Value("${mosip.inji.verify.redirect.url}")
    String injiVerifyRedirectUrl;

    @Value("${mosip.data.share.url}")
    String dataShareUrl;

    @Value("${server.tomcat.max-http-response-header-size:65536}")
    Integer maximumResponseHeaderSize;

    private final Logger logger = LoggerFactory.getLogger(PresentationServiceImpl.class);

    @Override
    public String authorizePresentation(PresentationRequestDTO presentationRequestDTO) throws ApiNotAccessibleException, IOException {

        verifiersService.validateVerifier(presentationRequestDTO);
        VCCredentialResponse vcCredentialResponse = dataShareService.downloadCredentialFromDataShare(presentationRequestDTO);

        PresentationDefinitionDTO presentationDefinitionDTO;
        try {
            presentationDefinitionDTO = objectMapper.readValue(presentationRequestDTO.getPresentation_definition(), PresentationDefinitionDTO.class);
            if (presentationDefinitionDTO == null) {
                throw new VPNotCreatedException(OpenIdErrorMessages.INVALID_REQUEST.getErrorMessage());
            }
        } catch (IOException ioException) {
            throw new VPNotCreatedException(OpenIdErrorMessages.INVALID_REQUEST.getErrorMessage());
        }

        logger.info("Started the Constructing VP Token");
        String redirectionString = presentationDefinitionDTO.getInputDescriptors()
                .stream()
                .findFirst()
                .map(inputDescriptorDTO -> {
                    boolean matchingProofTypes = inputDescriptorDTO.getFormat().getLdpVc().getProofTypes()
                            .stream()
                            .anyMatch(proofType -> vcCredentialResponse.getCredential().getProof().getType().equals(proofType));
                    if (matchingProofTypes) {
                        logger.info("Started the Construction of VP token");
                        try {
                            String vpToken = constructVerifiablePresentationString(vcCredentialResponse.getCredential());
                            String presentationSubmission = constructPresentationSubmission(vpToken);
                            return String.format(injiVerifyRedirectUrl,
                                    presentationRequestDTO.getRedirect_uri(),
                                    Base64.getUrlEncoder().encodeToString(vpToken.getBytes(StandardCharsets.UTF_8)),
                                    URLEncoder.encode(presentationSubmission, StandardCharsets.UTF_8));
                        } catch (JsonProcessingException e) {
                            throw new VPNotCreatedException(OpenIdErrorMessages.INVALID_REQUEST.getErrorMessage());
                        }
                    }
                    logger.info("No Credentials Matched the VP request.");
                    throw new VPNotCreatedException(OpenIdErrorMessages.INVALID_REQUEST.getErrorMessage());
                }).orElseThrow(() -> new VPNotCreatedException(OpenIdErrorMessages.INVALID_REQUEST.getErrorMessage()));
        if(redirectionString.length() > maximumResponseHeaderSize) {
            throw new VPNotCreatedException(
                    OpenIdErrorMessages.URI_TOO_LONG.getErrorCode(),
                    OpenIdErrorMessages.URI_TOO_LONG.getErrorMessage());
        }
        return redirectionString;
    }

    private String constructVerifiablePresentationString(VCCredentialProperties vcCredentialProperties) throws JsonProcessingException {
        VerifiablePresentationDTO verifiablePresentationDTO = VerifiablePresentationDTO.builder()
                .verifiableCredential(Collections.singletonList(vcCredentialProperties))
                .type(Collections.singletonList("VerifiablePresentation"))
                .context(Collections.singletonList("https://www.w3.org/2018/credentials/v1"))
                .build();
        return objectMapper.writeValueAsString(verifiablePresentationDTO);
    }

    private String constructPresentationSubmission(String vpToken) throws JsonProcessingException {
        VerifiablePresentationDTO verifiablePresentationDTO = objectMapper.readValue(vpToken, VerifiablePresentationDTO.class);

        AtomicInteger atomicInteger = new AtomicInteger(0);
        List<SubmissionDescriptorDTO> submissionDescriptorDTOList = verifiablePresentationDTO.getVerifiableCredential()
                .stream().map(verifiableCredential -> SubmissionDescriptorDTO.builder()
                    .id(UUID.randomUUID().toString())
                    .format("ldp_vc")
                    .path("$.verifiableCredential[" + atomicInteger.getAndIncrement() + "]").build()).collect(Collectors.toList());

        PresentationSubmissionDTO presentationSubmissionDTO = PresentationSubmissionDTO.builder()
                .id(UUID.randomUUID().toString())
                .definition_id(UUID.randomUUID().toString())
                .descriptorMap(submissionDescriptorDTOList).build();
        return objectMapper.writeValueAsString(presentationSubmissionDTO);
    }

    PresentationDefinitionDTO constructPresentationDefinition(VCCredentialResponse vcCredentialResponse){
        LDPVc ldpVc = LDPVc.builder().proofTypes(Collections.singletonList(vcCredentialResponse.getCredential().getProof().getType())).build();
        Format format = Format.builder().ldpVc(ldpVc).build();
        InputDescriptorDTO inputDescriptorDTO = InputDescriptorDTO.builder().id(UUID.randomUUID().toString()).format(format).build();

        return PresentationDefinitionDTO.builder()
                .inputDescriptors(Collections.singletonList(inputDescriptorDTO))
                .id(UUID.randomUUID().toString()).build();
    }

}
