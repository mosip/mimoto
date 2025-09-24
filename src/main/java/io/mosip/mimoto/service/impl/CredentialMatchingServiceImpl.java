package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.dto.MatchingCredentialsResponseDTO;
import io.mosip.mimoto.dto.MatchingCredentialsWithWalletDataDTO;
import io.mosip.mimoto.dto.SelectableCredentialDTO;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.openid.presentation.ConstraintsDTO;
import io.mosip.mimoto.dto.openid.presentation.FieldDTO;
import io.mosip.mimoto.dto.openid.presentation.FilterDTO;
import io.mosip.mimoto.dto.openid.presentation.InputDescriptorDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.model.VerifiableCredential;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.CredentialMatchingService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static io.mosip.mimoto.util.JwtUtils.extractJwtPayloadFromSdJwt;

@Slf4j
@Service
public class CredentialMatchingServiceImpl implements CredentialMatchingService{

    private static final String JSON_PATH_PREFIX = "$.";
    private static final String TYPE_PATH = "$.type";
    private static final String LDP_VC_FORMAT = "ldp_vc";
    private static final String PROOF_TYPE_KEY = "proof_type";

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private WalletCredentialsRepository walletCredentialsRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Autowired
    private IssuersService issuersService;

    public MatchingCredentialsWithWalletDataDTO getMatchingCredentials(VerifiablePresentationSessionData sessionData, String walletId, String base64Key) {
        log.info("Getting matching credentials with wallet data for walletId: {}", walletId);

        try {
            // Extract presentation definition from the session data
            PresentationDefinitionDTO presentationDefinition = extractPresentationDefinitionFromSessionData(sessionData);
            
            if (presentationDefinition == null) {
                log.warn("No presentation definition found in session data");
                throw new IllegalArgumentException("Presentation definition not found in session data");
            }

            validateInputParameters(presentationDefinition, walletId, base64Key);

            List<VerifiableCredential> walletCredentials = getWalletCredentials(walletId);
            if (walletCredentials.isEmpty()) {
                MatchingCredentialsResponseDTO emptyResponse = createEmptyResponseWithMissingClaims(presentationDefinition);
                return MatchingCredentialsWithWalletDataDTO.builder()
                        .matchingCredentialsResponse(emptyResponse)
                        .credentials(new ArrayList<>())
                        .build();
            }

            List<DecryptedCredentialDTO> decryptedCredentials = createDecryptedCredentials(walletCredentials, base64Key);

            List<InputDescriptorDTO> descriptors = presentationDefinition.getInputDescriptors();
            Map<Integer, List<SelectableCredentialDTO>> matchingCredentialsByDescriptor = new HashMap<>();
            Set<String> missingClaims = new HashSet<>();

            IntStream.range(0, descriptors.size())
                    .forEach(i -> {
                        InputDescriptorDTO descriptor = descriptors.get(i);
                        List<SelectableCredentialDTO> matches = decryptedCredentials.stream()
                                .filter(decrypted -> matchesInputDescriptor(decrypted.getCredential(), descriptor))
                                .map(this::buildAvailableCredential)
                                .collect(Collectors.toList());

                        if (!matches.isEmpty()) {
                            matchingCredentialsByDescriptor.put(i, matches);
                        } else {
                            missingClaims.addAll(extractClaimsFromInputDescriptor(descriptor));
                        }
                    });

            // Flatten all matching credentials into a single list, removing duplicates by credential ID
            Set<String> addedCredentialIds = new HashSet<>();
            List<SelectableCredentialDTO> availableCredentials = matchingCredentialsByDescriptor.values().stream()
                    .flatMap(List::stream)
                    .filter(credential -> addedCredentialIds.add(credential.getCredentialId()))
                    .collect(Collectors.toList());

            MatchingCredentialsResponseDTO matchingCredentialsResponse = MatchingCredentialsResponseDTO.builder()
                    .availableCredentials(availableCredentials)
                    .missingClaims(missingClaims)
                    .build();

            return MatchingCredentialsWithWalletDataDTO.builder()
                    .matchingCredentialsResponse(matchingCredentialsResponse)
                    .credentials(decryptedCredentials)
                    .build();

        } catch (IllegalArgumentException e) {
            log.error("Invalid input parameters for getMatchingCredentialsWithWalletData: {}", e.getMessage());
            throw e;
        }
    }

    private void validateInputParameters(PresentationDefinitionDTO presentationDefinition, String walletId, String base64Key) throws IllegalArgumentException {
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

        IntStream.range(0, presentationDefinition.getInputDescriptors().size())
                .filter(i -> {
                    InputDescriptorDTO descriptor = presentationDefinition.getInputDescriptors().get(i);
                    return descriptor.getId() == null || descriptor.getId().trim().isEmpty();
                })
                .findFirst()
                .ifPresent(i -> { throw new IllegalArgumentException("Input descriptor at index " + i + " must have a valid ID"); });
    }

    private MatchingCredentialsResponseDTO createEmptyResponseWithMissingClaims(PresentationDefinitionDTO presentationDefinition) {
        log.info("No credentials found for wallet");
        return MatchingCredentialsResponseDTO.builder()
                .availableCredentials(Collections.emptyList())
                .missingClaims(extractRequiredClaims(presentationDefinition).stream().collect(Collectors.toSet()))
                .build();
    }

    private List<VerifiableCredential> getWalletCredentials(String walletId) {
        return walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(walletId);
    }

    private List<DecryptedCredentialDTO> createDecryptedCredentials(List<VerifiableCredential> walletCredentials, String base64Key) {
        List<DecryptedCredentialDTO> decryptedCredentials = walletCredentials.stream()
                .map(credential -> {
                    try {
                        VCCredentialResponse decryptedCredential = decryptAndParseCredential(credential, base64Key);
                        return Optional.of(DecryptedCredentialDTO.builder()
                                .id(credential.getId())
                                .walletId(credential.getWalletId())
                                .credential(decryptedCredential)
                                .credentialMetadata(credential.getCredentialMetadata())
                                .createdAt(credential.getCreatedAt())
                                .updatedAt(credential.getUpdatedAt())
                                .build());
                    } catch (IOException | IllegalArgumentException | DecryptionException e) {
                        log.warn("Failed to decrypt credential {}: {}", credential.getId(), e.getMessage());
                        return Optional.<DecryptedCredentialDTO>empty();
                    }
                })
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toList());

        log.info("Successfully decrypted {} out of {} credentials", decryptedCredentials.size(), walletCredentials.size());
        return decryptedCredentials;
    }

    private VCCredentialResponse decryptAndParseCredential(VerifiableCredential credential, String base64Key) throws IOException, IllegalArgumentException, DecryptionException {
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


    private List<String> extractClaimsFromInputDescriptor(InputDescriptorDTO inputDescriptor) {
        return extractClaimsFromFields(inputDescriptor.getConstraints() != null ? 
                inputDescriptor.getConstraints().getFields() : null, false);
    }

    /**
     * Common method to extract claims from an array of fields.
     * 
     * @param fields Array of FieldDTO objects to extract claims from
     * @param deduplicate Whether to deduplicate claims using LinkedHashSet
     * @return List of extracted claim keys
     */
    private List<String> extractClaimsFromFields(FieldDTO[] fields, boolean deduplicate) {
        if (fields == null) {
            return Collections.emptyList();
        }
        
        Stream<String> claimsStream = Arrays.stream(fields)
                .filter(Objects::nonNull)
                .filter(field -> field.getPath() != null && field.getPath().length > 0)
                .flatMap(field -> Arrays.stream(field.getPath()))
                .map(this::extractClaimKeyFromPath)
                .filter(Objects::nonNull)
                .filter(claim -> !claim.isBlank());
        
        if (deduplicate) {
            return claimsStream.distinct().collect(Collectors.toList());
        } else {
            return claimsStream.collect(Collectors.toList());
        }
    }

    private boolean matchesInputDescriptor(VCCredentialResponse vc, InputDescriptorDTO inputDescriptor) {
        Map<String, Map<String, List<String>>> formatToCheck = inputDescriptor.getFormat();

        if (!matchesFormat(vc, formatToCheck)) {
            return false;
        }

        if (inputDescriptor.getConstraints() != null && inputDescriptor.getConstraints().getFields() != null) {
            return matchesConstraints(vc, inputDescriptor.getConstraints());
        }
        return true;
    }

    private boolean matchesFormat(VCCredentialResponse vc, Map<String, Map<String, List<String>>> descriptorFormat) {
        if (descriptorFormat == null) {
            return true;
        }
    
        String vcFormat = vc.getFormat();
        
        if (!CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(vcFormat) || 
            !descriptorFormat.containsKey(LDP_VC_FORMAT)) {
            return false;
        }
    
        Map<String, List<String>> ldpVcFormat = descriptorFormat.get(LDP_VC_FORMAT);
        
        if (!ldpVcFormat.containsKey(PROOF_TYPE_KEY)) {
            return true;
        }
    
        VCCredentialProperties ldpCredential = objectMapper.convertValue(vc.getCredential(), VCCredentialProperties.class);
        String vcProofType = ldpCredential.getProof() != null ? ldpCredential.getProof().getType() : null;
        List<String> requiredProofTypes = ldpVcFormat.get(PROOF_TYPE_KEY);
        
        return vcProofType != null && requiredProofTypes.contains(vcProofType);
    }

    private boolean matchesConstraints(VCCredentialResponse vc, ConstraintsDTO constraints) {
        if (constraints.getFields() == null) {
            return true;
        }

        return Arrays.stream(constraints.getFields()).allMatch(field -> {
            if (field.getPath() == null || field.getPath().length == 0) {
                return true;
            }
            return Arrays.stream(field.getPath()).anyMatch(path -> matchesFieldPath(vc, path, field.getFilter()));
        });
    }

    private boolean matchesFieldPath(VCCredentialResponse vc, String path, FilterDTO filter) {
        try {
            Object credentialData = getCredentialData(vc);

            List<Object> matches = evaluateJsonPath(path, credentialData);

            if (matches == null || matches.isEmpty()) {
                return false;
            }

            return matches.stream().anyMatch(match -> matchesFilter(match, filter));
        } catch (JsonProcessingException | NoSuchFieldException | IllegalAccessException e) {
            log.error("Error checking field path {}: {}", path, e.getMessage());
            return false;
        }
    }

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

    private boolean matchesFilter(Object match, FilterDTO filter) {
        if (filter == null) {
            return true;
        }

        if (filter.getPattern() != null) {
            String matchValue = match.toString();
            return matchValue.contains(filter.getPattern());
        }

        return true;
    }

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
            } else {
                try {
                    @SuppressWarnings("unchecked") Map<String, Object> map = objectMapper.convertValue(current, Map.class);
                    current = map.get(part);
                } catch (Exception convertException) {
                    if (objectMapper.canSerialize(current.getClass())) {
                        String jsonString = objectMapper.writeValueAsString(current);
                        @SuppressWarnings("unchecked") Map<String, Object> map = objectMapper.readValue(jsonString, Map.class);
                        current = map.get(part);
                    } else {
                        java.lang.reflect.Field field = current.getClass().getDeclaredField(part);
                        field.setAccessible(true);
                        current = field.get(current);
                    }
                }
            }

            if (current == null) {
                return Collections.emptyList();
            }
        }

        if (TYPE_PATH.equals(path) && current instanceof List) {
            @SuppressWarnings("unchecked") List<Object> typeList = (List<Object>) current;
            return new ArrayList<>(typeList);
        }

        return Collections.singletonList(current);
    }

    private List<String> extractRequiredClaims(PresentationDefinitionDTO presentationDefinition) {
        if (presentationDefinition.getInputDescriptors() == null) {
            return Collections.emptyList();
        }
        
        FieldDTO[] allFields = presentationDefinition.getInputDescriptors().stream()
                .filter(id -> id.getConstraints() != null && id.getConstraints().getFields() != null)
                .flatMap(id -> Arrays.stream(id.getConstraints().getFields()))
                .toArray(FieldDTO[]::new);
                
        return extractClaimsFromFields(allFields, true);
    }

    private String extractClaimKeyFromPath(String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        int lastDot = path.lastIndexOf('.');
        String tail = lastDot >= 0 ? path.substring(lastDot + 1) : path;
        if (tail.startsWith("$")) {
            tail = tail.substring(1);
        }
        return tail;
    }

    private SelectableCredentialDTO buildAvailableCredential(DecryptedCredentialDTO decryptedCredentialDTO) {
        String issuerId = decryptedCredentialDTO.getCredentialMetadata().getIssuerId();
        String credentialType = decryptedCredentialDTO.getCredentialMetadata().getCredentialType();

        String credentialTypeDisplayName = "Unknown Credential";
        String credentialTypeLogo = null;

        try {
            IssuerConfig issuerConfig = issuersService.getIssuerConfig(issuerId, credentialType);
            if (issuerConfig != null) {
                VerifiableCredentialResponseDTO credentialResponse = VerifiableCredentialResponseDTO.fromIssuerConfig(issuerConfig, "en", decryptedCredentialDTO.getId());
                credentialTypeDisplayName = credentialResponse.getCredentialTypeDisplayName();
                credentialTypeLogo = credentialResponse.getCredentialTypeLogo();
            }
        } catch (InvalidIssuerIdException | ApiNotAccessibleException e) {
            log.warn("Failed to fetch issuer config for issuerId: {}, credentialType: {}", issuerId, credentialType, e);
        }

        return SelectableCredentialDTO.builder()
                .credentialId(decryptedCredentialDTO.getId())
                .credentialTypeDisplayName(credentialTypeDisplayName)
                .credentialTypeLogo(credentialTypeLogo)
                .format(decryptedCredentialDTO.getCredential().getFormat())
                .build();
    }

    /**
     * Extracts the presentation definition from the VerifiablePresentationSessionData object.
     *
     * @param sessionData The session data containing the OpenID4VP object.
     * @return The presentation definition if found, null otherwise.
     */
    private PresentationDefinitionDTO extractPresentationDefinitionFromSessionData(VerifiablePresentationSessionData sessionData) {
        try {
            if (sessionData == null || sessionData.getOpenID4VP() == null) {
                log.warn("Session data or OpenID4VP is null");
                return null;
            }

            Map<String, Object> openID4VPInstance = objectMapper.convertValue(sessionData.getOpenID4VP(), Map.class);
            
            Map<String, Object> authorizationRequest = (Map<String, Object>) openID4VPInstance.get("authorizationRequest");
            if (authorizationRequest == null) {
                log.warn("No authorizationRequest found in openID4VPInstance");
                return null;
            }

            Map<String, Object> presentationDefinition = (Map<String, Object>) authorizationRequest.get("presentationDefinition");
            if (presentationDefinition == null) {
                log.warn("No presentationDefinition found in authorizationRequest");
                return null;
            }

            return objectMapper.convertValue(presentationDefinition, PresentationDefinitionDTO.class);

        } catch (Exception e) {
            log.error("Failed to extract presentation definition from session data", e);
            return null;
        }
    }
}