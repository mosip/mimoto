package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.openid.presentation.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.service.VerifiersService;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class PresentationServiceImpl implements PresentationService {

    @Autowired
    VerifiersService verifiersService;

    @Value("${mosip.inji.verify.redirect.url}")
    String injiVerifyRedirectUrl;

    @Override
    public String authorizePresentation(PresentationRequestDTO presentationRequestDTO) throws ApiNotAccessibleException, IOException {

        verifiersService.validateVerifier(presentationRequestDTO);

        //todo: Download the Credential From DataShare & extract to dataShare Service
        RestTemplate restTemplate = new RestTemplate();
        String credentials_uri = presentationRequestDTO.getResource();
        String  vcCredentialResponseString = restTemplate.getForEntity(credentials_uri, String.class).getBody();

        ObjectMapper objectMapper = new ObjectMapper();
        VCCredentialProperties vcCredentialProperties = objectMapper.readValue(vcCredentialResponseString, VCCredentialProperties.class);
        PresentationDefinitionDTO presentationDefinitionDTO = objectMapper.readValue(presentationRequestDTO.getPresentation_definition(), PresentationDefinitionDTO.class);

        if(presentationDefinitionDTO.getInputDescriptors().get(0).getFormat().getLdpVc().getProofTypes().get(0).equals(vcCredentialProperties.getProof().getType())){
            String vpToken = constructVerifiablePresentationString(vcCredentialProperties);
            String presentationSubmission =constructPresentationSubmission(vpToken);
            return String.format(injiVerifyRedirectUrl,
                    presentationRequestDTO.getRedirect_uri(),
                    Base64.getUrlEncoder().encodeToString(vpToken.getBytes(StandardCharsets.UTF_8)),
                    Base64.getUrlEncoder().encodeToString(presentationSubmission.getBytes(StandardCharsets.UTF_8)));
        }
        return null;
    }

    @NotNull
    private static String constructVerifiablePresentationString(VCCredentialProperties vcCredentialProperties) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        VerifiablePresentationDTO verifiablePresentationDTO = new VerifiablePresentationDTO();
        verifiablePresentationDTO.setVerifiableCredential(Collections.singletonList(vcCredentialProperties));
        verifiablePresentationDTO.setType(Collections.singletonList("VerifiablePresentation"));
        verifiablePresentationDTO.setContext(Collections.singletonList("https://www.w3.org/2018/credentials/v1"));
        return objectMapper.writeValueAsString(verifiablePresentationDTO);
    }

    @NotNull
    private static String constructPresentationSubmission(String vpToken) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        VerifiablePresentationDTO verifiablePresentationDTO = objectMapper.readValue(vpToken, VerifiablePresentationDTO.class);
        PresentationSubmissionDTO presentationSubmissionDTO = new PresentationSubmissionDTO();
        List<SubmissionDescriptorDTO> submissionDescriptorDTOList = new ArrayList<SubmissionDescriptorDTO>();
        AtomicInteger atomicInteger = new AtomicInteger(0);
        verifiablePresentationDTO.getVerifiableCredential().forEach(verifiableCredential -> {
            SubmissionDescriptorDTO submissionDescriptorDTO = new SubmissionDescriptorDTO();
            submissionDescriptorDTO.setId(UUID.randomUUID().toString());
            submissionDescriptorDTO.setFormat("ldp_vc");
            submissionDescriptorDTO.setPath("$.verifiableCredential[" + atomicInteger.getAndIncrement() + "]");
            submissionDescriptorDTOList.add(submissionDescriptorDTO);
        });
        presentationSubmissionDTO.setId(UUID.randomUUID().toString());
        presentationSubmissionDTO.setDefinition_id(UUID.randomUUID().toString());
        presentationSubmissionDTO.setDescriptorMap(submissionDescriptorDTOList);
        return objectMapper.writeValueAsString(presentationSubmissionDTO);
    }

}
