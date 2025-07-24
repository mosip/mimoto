package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.model.ProofSigningKey;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.repository.ProofSigningKeyRepository;
import io.mosip.mimoto.service.CredentialFormatHandler;
import io.mosip.mimoto.service.CredentialFormatHandlerFactory;
import io.mosip.mimoto.service.CredentialRequestService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.JwtGeneratorUtil;
import io.mosip.mimoto.util.KeyGenerationUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class CredentialRequestServiceImpl implements CredentialRequestService {

    @Autowired
    private ProofSigningKeyRepository proofSigningKeyRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Value("${signing.algorithms.priority.order:ED25519,ES256K,ES256,RS256}")
    private String signingAlgorithmsPriorityOrder;

    private static final SigningAlgorithm FALLBACK_SIGNING_ALG = SigningAlgorithm.ED25519;

    public Set<String> getSigningAlgorithmsPriorityOrder() {
        return Arrays.stream(signingAlgorithmsPriorityOrder.split(","))
                .map(String::trim).collect(Collectors.toCollection(LinkedHashSet::new));
    }


    @Autowired
    private CredentialFormatHandlerFactory credentialFormatHandlerFactory;

    @Override
    public VCCredentialRequest buildRequest(IssuerDTO issuerDTO,
                                            String credentialType,
                                            CredentialIssuerWellKnownResponse wellKnownResponse,
                                            String cNonce,
                                            String walletId,
                                            String base64EncodedWalletKey,
                                            boolean isLoginFlow) throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = wellKnownResponse.getCredentialConfigurationsSupported().get(credentialType);

        SigningAlgorithm signingAlgorithm = resolveAlgorithm(credentialsSupportedResponse);

        String jwt;
        if (isLoginFlow) {
            jwt = generateJwtUsingDBKeys(walletId, base64EncodedWalletKey, signingAlgorithm, wellKnownResponse, issuerDTO, cNonce);
        } else {
            KeyPair keyPair = KeyGenerationUtil.generateKeyPair(signingAlgorithm);
            log.debug("Generated KeyPair for signing signingAlgorithm: {}", signingAlgorithm);
            jwt = JwtGeneratorUtil.generateJwt(signingAlgorithm, wellKnownResponse.getCredentialIssuer(), issuerDTO.getClient_id(), cNonce, keyPair);
        }

        String format = credentialsSupportedResponse.getFormat();
        String proofType = credentialsSupportedResponse.getProofTypesSupported()
                .keySet()
                .stream()
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No proof type available"));

        VCCredentialRequest.VCCredentialRequestBuilder builder = VCCredentialRequest.builder()
                .format(format)
                .proof(VCCredentialRequestProof.builder()
                        .proofType(proofType)
                        .jwt(jwt)
                        .build());

        // Use registry to get appropriate handler and configure format-specific fields
        CredentialFormatHandler handler = credentialFormatHandlerFactory.getHandler(format);
        handler.configureCredentialRequest(builder, credentialsSupportedResponse, credentialType);


        return builder.build();
    }

    private SigningAlgorithm resolveAlgorithm(CredentialsSupportedResponse credentialsSupportedResponse) {
        Map<String, ProofTypesSupported> proofTypesSupported = credentialsSupportedResponse.getProofTypesSupported();
        ProofTypesSupported proofSigningAlgValuesSupported = proofTypesSupported.get("jwt");
        Set<String> signingAlgoPriorityOrderSet = getSigningAlgorithmsPriorityOrder();


        return Optional
                .ofNullable(proofSigningAlgValuesSupported)
                .map(ProofTypesSupported::getProofSigningAlgValuesSupported)
                .flatMap(issuerSupportedAlgorithms -> signingAlgoPriorityOrderSet.stream()
                        .filter(priorityAlgorithm -> issuerSupportedAlgorithms.stream().
                                anyMatch(issuerSupportedAlgorithm -> issuerSupportedAlgorithm.equalsIgnoreCase(priorityAlgorithm)))
                        .findFirst())
                .map(SigningAlgorithm::fromString)
                .orElseGet(() -> {
                    if (proofSigningAlgValuesSupported == null) {
                        log.warn("JWT proof type is missing in proof_types_supported field of Issuer well-known so falling back to {}", FALLBACK_SIGNING_ALG);
                    } else {
                        log.warn("None of the Issuer Supported Algorithms: {} are found in the predefined signing algorithms priority order: {} so falling back to {}",
                                proofSigningAlgValuesSupported.getProofSigningAlgValuesSupported(), signingAlgoPriorityOrderSet, FALLBACK_SIGNING_ALG);
                    }
                    return FALLBACK_SIGNING_ALG;
                });
    }

    private String generateJwtUsingDBKeys(String walletId,
                                          String base64EncodedWalletKey,
                                          SigningAlgorithm signingAlgorithm,
                                          CredentialIssuerWellKnownResponse wellKnownResponse,
                                          IssuerDTO issuerDTO,
                                          String cNonce) throws Exception {

        Optional<ProofSigningKey> proofSigningKey = proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, signingAlgorithm.name());
        byte[] decodedWalletKey = Base64.getDecoder().decode(base64EncodedWalletKey);
        SecretKey walletKey = EncryptionDecryptionUtil.bytesToSecretKey(decodedWalletKey);
        byte[] publicKeyBytes = Base64.getDecoder().decode(proofSigningKey.get().getPublicKey());
        byte[] privateKeyInBytes = encryptionDecryptionUtil.decryptWithAES(walletKey, proofSigningKey.get().getEncryptedSecretKey());
        KeyPair keyPair = KeyGenerationUtil.getKeyPairFromDBStoredKeys(signingAlgorithm, publicKeyBytes, privateKeyInBytes);
        log.debug("Fetched KeyPair for signing signingAlgorithm: {} from database", signingAlgorithm);

        return JwtGeneratorUtil.generateJwt(signingAlgorithm,
                wellKnownResponse.getCredentialIssuer(),
                issuerDTO.getClient_id(),
                cNonce,
                keyPair);
    }
}
