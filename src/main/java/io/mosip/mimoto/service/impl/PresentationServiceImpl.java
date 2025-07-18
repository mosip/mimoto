package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponseProof;
import io.mosip.mimoto.dto.openid.presentation.*;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.util.RestApiClient;
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
                    boolean matchingProofTypes = false;

                    if ("ldp_vc".equalsIgnoreCase(vcCredentialResponse.getFormat())
                            && vcCredentialResponse.getCredential() instanceof VCCredentialProperties ldpCredential
                            && ldpCredential.getProof() != null) {

                        matchingProofTypes = inputDescriptorDTO.getFormat().get("ldpVc").get("proofTypes")
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

    public PresentationDefinitionDTO constructPresentationDefinition(VCCredentialResponse vcRes) {
        String fmt = vcRes.getFormat();
        List<InputDescriptorDTO> inputDescriptors = new ArrayList<>();

        if ("ldp_vc".equalsIgnoreCase(fmt)
                && vcRes.getCredential() instanceof VCCredentialProperties ldp) {

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

        } else if ("sd_jwt_vc".equalsIgnoreCase(fmt) || "vc+sd-jwt".equalsIgnoreCase(fmt) || "dc+sd-jwt".equalsIgnoreCase(fmt)) {

            // Use vct (VC type) matching — often in unsecured payload under "vct" or "vc.type"
            FieldDTO field = FieldDTO.builder()
                    .path(new String[]{"$.vct"})
                    .filter(FilterDTO.builder().type("string")
                            .pattern("desiredCredentialTypeUri") // replace with your VC type URI
                            .build())
                    .build();

            Map<String, Object> sdFormat = Map.of(
                    fmt, Map.of(
                            "sd-jwt_alg_values", List.of("ES256","ES384"),
                            "kb-jwt_alg_values", List.of("ES256","ES384")
                    )
            );

            inputDescriptors.add(InputDescriptorDTO.builder()
                    .id(UUID.randomUUID().toString())
                    .constraints(ConstraintsDTO.builder().limitDisclosure("required").fields(new FieldDTO[]{ field }).build())
                    .format((Map) sdFormat)
                    .build());
        }

        return PresentationDefinitionDTO.builder()
                .id(UUID.randomUUID().toString())
                .inputDescriptors(inputDescriptors)
                .build();
    }



}
