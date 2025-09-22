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

    public MatchingCredentialsWithWalletDataDTO getMatchingCredentials(PresentationDefinitionDTO presentationDefinition, String walletId, String base64Key) throws ApiNotAccessibleException, IOException {
        log.info("Getting matching credentials with wallet data for walletId: {}", walletId);

        try {
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

            List<SelectableCredentialDTO> availableCredentials;
            try {
                availableCredentials = processCredentialsForMatching(walletCredentials, presentationDefinition, base64Key);
            } catch (IOException | IllegalArgumentException | DecryptionException e) {
                log.error("Error processing credentials for matching: {}", e.getMessage());
                throw new ApiNotAccessibleException();
            }

            List<String> missingClaims;
            try {
                missingClaims = extractMissingClaims(walletCredentials, presentationDefinition, base64Key);
            } catch (JsonProcessingException | IllegalArgumentException e) {
                log.error("Error extracting missing claims: {}", e.getMessage());
                missingClaims = new ArrayList<>();
            }

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
        } catch (ApiNotAccessibleException e) {
            log.error("API not accessible while getting matching credentials with wallet data for walletId: {}", walletId, e);
            throw e;
        }
    }

    private void validateInputParameters(PresentationDefinitionDTO presentationDefinition, String walletId, String base64Key) {
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

        for (int i = 0; i < presentationDefinition.getInputDescriptors().size(); i++) {
            InputDescriptorDTO descriptor = presentationDefinition.getInputDescriptors().get(i);
            if (descriptor.getId() == null || descriptor.getId().trim().isEmpty()) {
                throw new IllegalArgumentException("Input descriptor at index " + i + " must have a valid ID");
            }
        }
    }

    private MatchingCredentialsResponseDTO createEmptyResponseWithMissingClaims(PresentationDefinitionDTO presentationDefinition) {
        log.info("No credentials found for wallet");
        return MatchingCredentialsResponseDTO.builder()
                .availableCredentials(Collections.emptyList())
                .missingClaims(extractRequiredClaims(presentationDefinition))
                .build();
    }

    private List<VerifiableCredential> getWalletCredentials(String walletId) {
        return walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(walletId);
    }

    private List<DecryptedCredentialDTO> createDecryptedCredentials(List<VerifiableCredential> walletCredentials, String base64Key) {
        List<DecryptedCredentialDTO> decryptedCredentials = new ArrayList<>();

        for (VerifiableCredential credential : walletCredentials) {
            try {
                VCCredentialResponse decryptedCredential = decryptAndParseCredential(credential, base64Key);

                DecryptedCredentialDTO decryptedCredentialDTO = DecryptedCredentialDTO.builder()
                        .id(credential.getId())
                        .walletId(credential.getWalletId())
                        .credential(decryptedCredential)
                        .credentialMetadata(credential.getCredentialMetadata())
                        .createdAt(credential.getCreatedAt())
                        .updatedAt(credential.getUpdatedAt())
                        .build();

                decryptedCredentials.add(decryptedCredentialDTO);

            } catch (IOException | IllegalArgumentException | DecryptionException e) {
                log.warn("Failed to decrypt credential {}: {}", credential.getId(), e.getMessage());
            }
        }

        log.info("Successfully decrypted {} out of {} credentials", decryptedCredentials.size(), walletCredentials.size());
        return decryptedCredentials;
    }

    private List<SelectableCredentialDTO> processCredentialsForMatching(List<VerifiableCredential> walletCredentials, PresentationDefinitionDTO presentationDefinition, String base64Key) throws IOException, IllegalArgumentException, DecryptionException {
        log.info("Starting credential matching process for {} credentials against {} input descriptors", walletCredentials.size(), presentationDefinition.getInputDescriptors().size());

        List<SelectableCredentialDTO> availableCredentials = new ArrayList<>();
        Set<String> addedCredentialIds = new HashSet<>();

        for (VerifiableCredential credential : walletCredentials) {
            VCCredentialResponse vcCredentialResponse = decryptAndParseCredential(credential, base64Key);
            processCredentialAgainstInputDescriptors(credential, vcCredentialResponse, presentationDefinition, availableCredentials, addedCredentialIds);
        }

        log.info("Completed credential matching process - found {} matching credentials", availableCredentials.size());
        return availableCredentials;
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

    private void processCredentialAgainstInputDescriptors(VerifiableCredential credential, VCCredentialResponse vcCredentialResponse, PresentationDefinitionDTO presentationDefinition, List<SelectableCredentialDTO> availableCredentials, Set<String> addedCredentialIds) {
        for (InputDescriptorDTO inputDescriptor : presentationDefinition.getInputDescriptors()) {
            if (matchesInputDescriptor(vcCredentialResponse, inputDescriptor, presentationDefinition)) {
                if (!addedCredentialIds.contains(credential.getId())) {
                    SelectableCredentialDTO availableCredential = buildAvailableCredential(credential, vcCredentialResponse);
                    availableCredentials.add(availableCredential);
                    addedCredentialIds.add(credential.getId());
                }
                break;
            }
        }
    }

    private List<String> extractMissingClaims(List<VerifiableCredential> walletCredentials, PresentationDefinitionDTO presentationDefinition, String base64Key) throws JsonProcessingException, IllegalArgumentException {
        log.info("Starting missing claims extraction for {} input descriptors", presentationDefinition.getInputDescriptors().size());

        List<String> missingClaims = new ArrayList<>();

        for (InputDescriptorDTO inputDescriptor : presentationDefinition.getInputDescriptors()) {
            if (!hasMatchingCredential(walletCredentials, inputDescriptor, presentationDefinition, base64Key)) {
                missingClaims.addAll(extractClaimsFromInputDescriptor(inputDescriptor));
            }
        }

        log.info("Completed missing claims extraction - found {} missing claims", missingClaims.size());
        return missingClaims;
    }

    private boolean hasMatchingCredential(List<VerifiableCredential> walletCredentials, InputDescriptorDTO inputDescriptor, PresentationDefinitionDTO presentationDefinition, String base64Key) throws JsonProcessingException, IllegalArgumentException {
        for (VerifiableCredential credential : walletCredentials) {
            try {
                VCCredentialResponse vcCredentialResponse = decryptAndParseCredential(credential, base64Key);
                if (matchesInputDescriptor(vcCredentialResponse, inputDescriptor, presentationDefinition)) {
                    return true;
                }
            } catch (IOException | IllegalArgumentException | DecryptionException e) {
                log.error("Failed to decrypt credential {} for missing claims check: {}", credential.getId(), e.getMessage());
            }
        }
        return false;
    }

    private List<String> extractClaimsFromInputDescriptor(InputDescriptorDTO inputDescriptor) {
        List<String> claims = new ArrayList<>();

        if (inputDescriptor.getConstraints() != null && inputDescriptor.getConstraints().getFields() != null) {
            for (FieldDTO field : inputDescriptor.getConstraints().getFields()) {
                if (field.getPath() != null && field.getPath().length > 0) {
                    for (String path : field.getPath()) {
                        String claim = extractClaimKeyFromPath(path);
                        if (claim != null && !claim.isBlank()) {
                            claims.add(claim);
                        }
                    }
                }
            }
        }

        return claims;
    }

    private boolean matchesInputDescriptor(VCCredentialResponse vc, InputDescriptorDTO inputDescriptor, PresentationDefinitionDTO presentationDefinition) {
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

        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(vcFormat)) {
            if (descriptorFormat.containsKey(LDP_VC_FORMAT)) {
                Map<String, List<String>> ldpVcFormat = descriptorFormat.get(LDP_VC_FORMAT);

                if (ldpVcFormat.containsKey(PROOF_TYPE_KEY)) {
                    VCCredentialProperties ldpCredential = objectMapper.convertValue(vc.getCredential(), VCCredentialProperties.class);
                    String vcProofType = ldpCredential.getProof() != null ? ldpCredential.getProof().getType() : null;
                    List<String> requiredProofTypes = ldpVcFormat.get(PROOF_TYPE_KEY);
                    boolean matches = vcProofType != null && requiredProofTypes.contains(vcProofType);

                    return matches;
                } else {
                    return true;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    private boolean matchesConstraints(VCCredentialResponse vc, ConstraintsDTO constraints) {
        if (constraints.getFields() == null) {
            return true;
        }

        for (int i = 0; i < constraints.getFields().length; i++) {
            FieldDTO field = constraints.getFields()[i];

            if (field.getPath() == null || field.getPath().length == 0) {
                continue;
            }

            boolean fieldMatches = false;
            for (String path : field.getPath()) {
                if (matchesFieldPath(vc, path, field.getFilter())) {
                    fieldMatches = true;
                    break;
                }
            }

            if (!fieldMatches) {
                return false;
            }
        }

        return true;
    }

    private boolean matchesFieldPath(VCCredentialResponse vc, String path, FilterDTO filter) {
        try {
            Object credentialData = getCredentialData(vc);

            List<Object> matches = evaluateJsonPath(path, credentialData);

            if (matches == null || matches.isEmpty()) {
                return false;
            }

            for (Object match : matches) {
                if (matchesFilter(match, filter)) {
                    return true;
                }
            }

            return false;
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
            } else if (current != null) {
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
            } else {
                return Collections.emptyList();
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
        Set<String> requiredClaims = new HashSet<>();

        if (presentationDefinition.getInputDescriptors() != null) {
            for (InputDescriptorDTO inputDescriptor : presentationDefinition.getInputDescriptors()) {
                if (inputDescriptor.getConstraints() != null && inputDescriptor.getConstraints().getFields() != null) {
                    for (FieldDTO field : inputDescriptor.getConstraints().getFields()) {
                        if (field.getPath() != null && field.getPath().length > 0) {
                            for (String path : field.getPath()) {
                                String claim = extractClaimKeyFromPath(path);
                                if (claim != null && !claim.isBlank()) {
                                    requiredClaims.add(claim);
                                }
                            }
                        }
                    }
                }
            }
        }
        return new ArrayList<>(requiredClaims);
    }

    private String extractClaimKeyFromPath(String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        // Expecting JSONPath like $.a.b.c – return c
        int lastDot = path.lastIndexOf('.');
        String tail = lastDot >= 0 ? path.substring(lastDot + 1) : path;
        // Strip leading $ if present (e.g., "$")
        if (tail.startsWith("$")) {
            tail = tail.substring(1);
        }
        return tail;
    }

    private SelectableCredentialDTO buildAvailableCredential(VerifiableCredential credential, VCCredentialResponse vcCredentialResponse) {
        String issuerId = credential.getCredentialMetadata().getIssuerId();
        String credentialType = credential.getCredentialMetadata().getCredentialType();

        String credentialTypeDisplayName = "Unknown Credential";
        String credentialTypeLogo = null;

        try {
            IssuerConfig issuerConfig = issuersService.getIssuerConfig(issuerId, credentialType);
            if (issuerConfig != null) {
                VerifiableCredentialResponseDTO credentialResponse = VerifiableCredentialResponseDTO.fromIssuerConfig(issuerConfig, "en", credential.getId());
                credentialTypeDisplayName = credentialResponse.getCredentialTypeDisplayName();
                credentialTypeLogo = credentialResponse.getCredentialTypeLogo();
            }
        } catch (InvalidIssuerIdException | ApiNotAccessibleException e) {
            log.warn("Failed to fetch issuer config for issuerId: {}, credentialType: {}", issuerId, credentialType, e);
        }

        return SelectableCredentialDTO.builder()
                .credentialId(credential.getId())
                .credentialTypeDisplayName(credentialTypeDisplayName)
                .credentialTypeLogo(credentialTypeLogo)
                .format(vcCredentialResponse.getFormat())
                .build();
    }
}


