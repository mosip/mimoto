package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.presentation.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.PlatformErrorMessages;
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
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

@Service
public class PresentationServiceImpl implements PresentationService {

    @Autowired
    VerifiersService verifiersService;

    @Autowired
    RestApiClient restApiClient;

    @Autowired
    ObjectMapper objectMapper;

    @Value("${mosip.inji.verify.redirect.url}")
    String injiVerifyRedirectUrl;

    @Value("${mosip.data.share.url}")
    String dataShareUrl;

    private final Logger logger = LoggerFactory.getLogger(PresentationServiceImpl.class);

    @Override
    public String authorizePresentation(PresentationRequestDTO presentationRequestDTO) throws ApiNotAccessibleException, IOException {

        logger.info("Started the presentation Validation");
        verifiersService.validateVerifier(presentationRequestDTO);

        logger.info("Started the Credential Download From DataShare");
        String credentialsResourceUri = presentationRequestDTO.getResource();
        if(!credentialsResourceUri.contains(dataShareUrl)){
            throw new InvalidCredentialResourceException(PlatformErrorMessages.INVALID_CREDENTIAL_RESOURCE_URI_EXCEPTION.getMessage());
        }

        String  vcCredentialResponseString = restApiClient.getApi(credentialsResourceUri, String.class);

        logger.info("Started the ObjectMapping");
        VCCredentialResponse vcCredentialResponse = objectMapper.readValue(vcCredentialResponseString, VCCredentialResponse.class);
        PresentationDefinitionDTO presentationDefinitionDTO = objectMapper.readValue(presentationRequestDTO.getPresentation_definition(), PresentationDefinitionDTO.class);

        return presentationDefinitionDTO.getInputDescriptors()
                .stream()
                .findFirst()
                .map( inputDescriptorDTO -> {
                    boolean matchingProofTypes = inputDescriptorDTO.getFormat().getLdpVc().getProofTypes()
                            .stream()
                            .anyMatch(proofType -> vcCredentialResponse.getCredential().getProof().getType().equals(proofType));
                    if(matchingProofTypes){
                        logger.info("Started the Construction of VP token");
                        try {
                            String vpToken = constructVerifiablePresentationString(vcCredentialResponse.getCredential());
                            String presentationSubmission = constructPresentationSubmission(vpToken);
                            return String.format(injiVerifyRedirectUrl,
                                    presentationRequestDTO.getRedirect_uri(),
                                    Base64.getUrlEncoder().encodeToString(vpToken.getBytes(StandardCharsets.UTF_8)),
                                    URLEncoder.encode(presentationSubmission, StandardCharsets.UTF_8));
                        } catch (JsonProcessingException e) {
                            throw new RuntimeException(e);
                        }
                    }
                    logger.info("No Credentials Matched the VP request.");
                    throw new VPNotCreatedException(PlatformErrorMessages.NO_CREDENTIALS_MATCH_VP_DEFINITION_EXCEPTION.getMessage());
                }).orElseThrow(() -> new VPNotCreatedException(PlatformErrorMessages.NO_CREDENTIALS_MATCH_VP_DEFINITION_EXCEPTION.getMessage()));
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
