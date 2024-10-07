package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.presentation.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.util.RestApiClient;
import lombok.extern.slf4j.Slf4j;
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

@Slf4j
@Service
public class PresentationServiceImpl implements PresentationService {

    @Autowired
    DataShareServiceImpl dataShareService;

    @Autowired
    RestApiClient restApiClient;

    @Autowired
    ObjectMapper objectMapper;

    @Value("${mosip.inji.ovp.redirect.url.pattern}")
    String injiOvpRedirectURLPattern;

    @Value("${mosip.data.share.url}")
    String dataShareUrl;

    @Value("${server.tomcat.max-http-response-header-size:65536}")
    Integer maximumResponseHeaderSize;

    @Override
    public String authorizePresentation(PresentationRequestDTO presentationRequestDTO) throws IOException {
        VCCredentialResponse vcCredentialResponse = dataShareService.downloadCredentialFromDataShare(presentationRequestDTO);

        PresentationDefinitionDTO presentationDefinitionDTO = presentationRequestDTO.getPresentationDefinition();
        if (presentationDefinitionDTO == null) {
            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        }

        log.info("Started the Constructing VP Token");
        String redirectionString = presentationDefinitionDTO.getInputDescriptors()
                .stream()
                .findFirst()
                .map(inputDescriptorDTO -> {
                    boolean matchingProofTypes = inputDescriptorDTO.getFormat().get("ldpVc").get("proofTypes")
                            .stream()
                            .anyMatch(proofType -> vcCredentialResponse.getCredential().getProof().getType().equals(proofType));
                    if (matchingProofTypes) {
                        log.info("Started the Construction of VP token");
                        try {
                            VerifiablePresentationDTO verifiablePresentationDTO = constructVerifiablePresentationString(vcCredentialResponse.getCredential());
                            String presentationSubmission = constructPresentationSubmission(verifiablePresentationDTO, presentationDefinitionDTO, inputDescriptorDTO);
                            String vpToken = objectMapper.writeValueAsString(verifiablePresentationDTO);
                            return String.format(injiOvpRedirectURLPattern,
                                    presentationRequestDTO.getRedirectUri(),
                                    Base64.getUrlEncoder().encodeToString(vpToken.getBytes(StandardCharsets.UTF_8)),
                                    URLEncoder.encode(presentationSubmission, StandardCharsets.UTF_8));
                        } catch (JsonProcessingException e) {
                            throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
                        }
                    }
                    log.info("No Credentials Matched the VP request.");
                    throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
                }).orElseThrow(() -> new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage()));
        if(redirectionString.length() > maximumResponseHeaderSize) {
            throw new VPNotCreatedException(
                    ErrorConstants.URI_TOO_LONG.getErrorCode(),
                    ErrorConstants.URI_TOO_LONG.getErrorMessage());
        }
        return redirectionString;
    }

    private VerifiablePresentationDTO constructVerifiablePresentationString(VCCredentialProperties vcCredentialProperties) throws JsonProcessingException {
        return VerifiablePresentationDTO.builder()
                .verifiableCredential(Collections.singletonList(vcCredentialProperties))
                .type(Collections.singletonList("VerifiablePresentation"))
                .context(Collections.singletonList("https://www.w3.org/2018/credentials/v1"))
                .build();
    }

    private String constructPresentationSubmission(VerifiablePresentationDTO verifiablePresentationDTO, PresentationDefinitionDTO presentationDefinitionDTO, InputDescriptorDTO inputDescriptorDTO) throws JsonProcessingException {
        AtomicInteger atomicInteger = new AtomicInteger(0);
        List<SubmissionDescriptorDTO> submissionDescriptorDTOList = verifiablePresentationDTO.getVerifiableCredential()
                .stream().map(verifiableCredential -> SubmissionDescriptorDTO.builder()
                    .id(inputDescriptorDTO.getId())
                    .format("ldp_vc")
                    .path("$.verifiableCredential[" + atomicInteger.getAndIncrement() + "]").build()).collect(Collectors.toList());

        PresentationSubmissionDTO presentationSubmissionDTO = PresentationSubmissionDTO.builder()
                .id(UUID.randomUUID().toString())
                .definition_id(presentationDefinitionDTO.getId())
                .descriptorMap(submissionDescriptorDTOList).build();
        return objectMapper.writeValueAsString(presentationSubmissionDTO);
    }

    PresentationDefinitionDTO constructPresentationDefinition(VCCredentialResponse vcCredentialResponse){
        FilterDTO filterDTO = FilterDTO.builder().type("String").pattern(vcCredentialResponse.getCredential().getType().getLast()).build();
        FieldDTO fieldDTO = FieldDTO.builder().path(new String[]{"$.type"}).filter(filterDTO).build();
        ConstraintsDTO constraintsDTO = ConstraintsDTO.builder().fields(new FieldDTO[]{fieldDTO}).build();
        Map<String, List<String>> proofTypes = Map.of("proofTypes", Collections.singletonList(vcCredentialResponse.getCredential().getProof().getType()));
        Map<String, Map<String, List<String>>> format = Map.of("ldpVc", proofTypes );
        InputDescriptorDTO inputDescriptorDTO = InputDescriptorDTO.builder()
                .id(UUID.randomUUID().toString())
                .constraints(constraintsDTO)
                .format(format).build();

        return PresentationDefinitionDTO.builder()
                .inputDescriptors(Collections.singletonList(inputDescriptorDTO))
                .id(UUID.randomUUID().toString()).build();
    }

}
