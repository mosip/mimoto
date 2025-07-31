package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponseProof;
import io.mosip.mimoto.dto.openid.presentation.*;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import lombok.extern.slf4j.Slf4j;
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
    ObjectMapper objectMapper;

    @Value("${mosip.inji.ovp.redirect.url.pattern}")
    String injiOvpRedirectURLPattern;

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

                    if (CredentialFormat.LDP_VC.toString().equalsIgnoreCase(vcCredentialResponse.getFormat())) {
                        VCCredentialProperties ldpCredential = objectMapper.convertValue(vcCredentialResponse.getCredential(), VCCredentialProperties.class);
                        boolean matchingProofTypes = inputDescriptorDTO.getFormat().get("ldpVc").get("proofTypes")
                                .stream()
                                .anyMatch(proofType -> ldpCredential.getProof().getType().equals(proofType));

                        if (matchingProofTypes) {
                            log.info("Started the Construction of VP token");
                            try {
                                VerifiablePresentationDTO verifiablePresentationDTO = constructVerifiablePresentationString(ldpCredential);
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
                    } else if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(vcCredentialResponse.getFormat())
                            || CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(vcCredentialResponse.getFormat())) {

                        throw new UnsupportedOperationException("OnlineSharing is not supported for SD-JWT format yet.");
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
                        .format(CredentialFormat.LDP_VC.getFormat())
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
                    .constraints(ConstraintsDTO.builder().fields(new FieldDTO[]{ field }).build())
                    .format(format)
                    .build());

        } else {
            throw new UnsupportedOperationException("We don't support constructing Presentation Definition for " + vcFormat + " format yet.");
        }

        return PresentationDefinitionDTO.builder()
                .id(UUID.randomUUID().toString())
                .inputDescriptors(inputDescriptors)
                .build();
    }
}
