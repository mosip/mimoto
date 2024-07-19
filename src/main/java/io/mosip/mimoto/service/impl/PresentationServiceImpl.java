package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.presentation.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
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

    private final Logger logger = LoggerFactory.getLogger(PresentationServiceImpl.class);

    @Override
    public String authorizePresentation(PresentationRequestDTO presentationRequestDTO) throws ApiNotAccessibleException, IOException {

        logger.info("Started the presentation Validation");
        verifiersService.validateVerifier(presentationRequestDTO);

        logger.info("Started the Credential Download From DataShare");
        String credentialsResourceUri = presentationRequestDTO.getResource();
        String  vcCredentialResponseString = restApiClient.getApi(credentialsResourceUri, String.class);

        logger.info("Started the ObjectMapping");
        VCCredentialResponse vcCredentialResponse = objectMapper.readValue(vcCredentialResponseString, VCCredentialResponse.class);
        PresentationDefinitionDTO presentationDefinitionDTO = objectMapper.readValue(presentationRequestDTO.getPresentation_definition(), PresentationDefinitionDTO.class);

        String proofTypeInPresentationDefinition = presentationDefinitionDTO.getInputDescriptors().get(0).getFormat().getLdpVc().getProofTypes().get(0);
        String proofTypeInCredential = vcCredentialResponse.getCredential().getProof().getType();

        if(proofTypeInPresentationDefinition.equals(proofTypeInCredential)){
            logger.info("Started the Construction of VP token");
            String vpToken = constructVerifiablePresentationString(vcCredentialResponse.getCredential());
            String presentationSubmission = constructPresentationSubmission(vpToken);
            return String.format(injiVerifyRedirectUrl,
                    presentationRequestDTO.getRedirect_uri(),
                    Base64.getUrlEncoder().encodeToString(vpToken.getBytes(StandardCharsets.UTF_8)),
                    URLEncoder.encode(presentationSubmission, StandardCharsets.UTF_8));
        }
        throw new VPNotCreatedException(PlatformErrorMessages.NO_CREDENTIALS_MATCH_VP_DEFINITION_EXCEPTION.getMessage());
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
        List<SubmissionDescriptorDTO> submissionDescriptorDTOList = new ArrayList<>();
        verifiablePresentationDTO.getVerifiableCredential().forEach(verifiableCredential -> {
            SubmissionDescriptorDTO submissionDescriptorDTO = SubmissionDescriptorDTO.builder()
                    .id(UUID.randomUUID().toString())
                    .format("ldp_vc")
                    .path("$.verifiableCredential[" + atomicInteger.getAndIncrement() + "]").build();
            submissionDescriptorDTOList.add(submissionDescriptorDTO);
        });

        PresentationSubmissionDTO presentationSubmissionDTO = PresentationSubmissionDTO.builder()
                .id(UUID.randomUUID().toString())
                .definition_id(UUID.randomUUID().toString())
                .descriptorMap(submissionDescriptorDTOList).build();
        return objectMapper.writeValueAsString(presentationSubmissionDTO);
    }

}
