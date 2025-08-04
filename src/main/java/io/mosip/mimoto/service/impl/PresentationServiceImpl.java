package io.mosip.mimoto.service.impl;

import com.authlete.sd.SDJWT;
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

import static io.mosip.mimoto.util.JwtUtils.*;

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
                    try {
                        return processInputDescriptor(vcCredentialResponse, inputDescriptorDTO, presentationRequestDTO, presentationDefinitionDTO);
                    } catch (JsonProcessingException e) {
                        throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
                    }
                })
                .orElseThrow(() -> new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage()));

        if (redirectionString.length() > maximumResponseHeaderSize) {
            throw new VPNotCreatedException(
                    ErrorConstants.URI_TOO_LONG.getErrorCode(),
                    ErrorConstants.URI_TOO_LONG.getErrorMessage());
        }
        return redirectionString;
    }

    private String processInputDescriptor(VCCredentialResponse vcCredentialResponse, InputDescriptorDTO inputDescriptorDTO,
                                          PresentationRequestDTO presentationRequestDTO, PresentationDefinitionDTO presentationDefinitionDTO) throws JsonProcessingException {
        String format = vcCredentialResponse.getFormat();
        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            VCCredentialProperties ldpCredential = objectMapper.convertValue(vcCredentialResponse.getCredential(), VCCredentialProperties.class);
            if (inputDescriptorDTO.getFormat().get("ldpVc").get("proofTypes")
                    .stream().anyMatch(proofType -> ldpCredential.getProof().getType().equals(proofType))) {
                return buildRedirectString(
                        constructVerifiablePresentationString(ldpCredential),
                        format,
                        presentationRequestDTO,
                        presentationDefinitionDTO,
                        inputDescriptorDTO
                );
            }
        } else if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(format)
                || CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
            String credential = objectMapper.convertValue(vcCredentialResponse.getCredential(), String.class);
            Map<String, Object> jwtHeaders = parseJwtHeader(credential);
            String responseAlgo = (String) jwtHeaders.get("alg");
            if (inputDescriptorDTO.getFormat().get(format).get("sd-jwt_alg_values")
                    .stream().anyMatch(responseAlgo::equals)) {
                return buildRedirectString(
                        constructVerifiablePresentationStringForSDjwt(credential),
                        format,
                        presentationRequestDTO,
                        presentationDefinitionDTO,
                        inputDescriptorDTO
                );
            }
        }
        log.info("No Credentials Matched the VP request.");
        throw new VPNotCreatedException(ErrorConstants.INVALID_REQUEST.getErrorMessage());
    }

    private String buildRedirectString(VerifiablePresentationDTO verifiablePresentationDTO, String format,
                                       PresentationRequestDTO presentationRequestDTO, PresentationDefinitionDTO presentationDefinitionDTO,
                                       InputDescriptorDTO inputDescriptorDTO) throws JsonProcessingException {
        String presentationSubmission = constructPresentationSubmission(format, verifiablePresentationDTO, presentationDefinitionDTO, inputDescriptorDTO);
        String vpToken = objectMapper.writeValueAsString(verifiablePresentationDTO);
        return String.format(injiOvpRedirectURLPattern,
                presentationRequestDTO.getRedirectUri(),
                Base64.getUrlEncoder().encodeToString(vpToken.getBytes(StandardCharsets.UTF_8)),
                URLEncoder.encode(presentationSubmission, StandardCharsets.UTF_8));
    }

    private VerifiablePresentationDTO constructVerifiablePresentationString(VCCredentialProperties vcCredentialProperties) throws JsonProcessingException {
        return VerifiablePresentationDTO.builder()
                .verifiableCredential(Collections.singletonList(vcCredentialProperties))
                .type(Collections.singletonList("VerifiablePresentation"))
                .context(Collections.singletonList(vcCredentialProperties.getContext()))
                .build();
    }

    private VerifiablePresentationDTO constructVerifiablePresentationStringForSDjwt(String vcCredential) throws JsonProcessingException {
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
                    .constraints(ConstraintsDTO.builder().fields(new FieldDTO[]{ field }).build())
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
