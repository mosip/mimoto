package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.config.SigningAlgorithmConfig;
import io.mosip.mimoto.model.ProofSigningKey;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.repository.ProofSigningKeyRepository;
import io.mosip.mimoto.service.CredentialRequestService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.JwtGeneratorUtil;
import io.mosip.mimoto.util.KeyGenerationUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.*;

@Service
@Slf4j
public class CredentialRequestServiceImpl implements CredentialRequestService {

    @Autowired
    private JoseUtil joseUtil;

    @Autowired
    private ProofSigningKeyRepository proofSigningKeyRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Autowired
    private SigningAlgorithmConfig signingAlgorithmConfig;

    @Override
    public VCCredentialRequest buildRequest(IssuerDTO issuerDTO,
                                            CredentialIssuerWellKnownResponse wellKnownResponse,
                                            CredentialsSupportedResponse credentialsSupportedResponse,
                                            String cNonce,
                                            String walletId,
                                            String base64EncodedWalletKey,
                                            Boolean isLoginFlow) throws Exception {

        SigningAlgorithm algorithm = resolveAlgorithm(credentialsSupportedResponse);

        String jwt;
        if (isLoginFlow) {
            jwt = generateJwtFromDB(walletId, base64EncodedWalletKey, algorithm, wellKnownResponse, issuerDTO, cNonce);
        } else {
            KeyPair keyPair = KeyGenerationUtil.generateKeyPair(algorithm);
            jwt = JwtGeneratorUtil.generateJwt(algorithm, wellKnownResponse.getCredentialIssuer(), issuerDTO.getClient_id(), cNonce, keyPair);
        }

        List<String> credentialContext = credentialsSupportedResponse.getCredentialDefinition().getContext();
        if (credentialContext == null || credentialContext.isEmpty()) {
            credentialContext = List.of("https://www.w3.org/2018/credentials/v1");
        }

        return VCCredentialRequest.builder()
                .format(credentialsSupportedResponse.getFormat())
                .proof(VCCredentialRequestProof.builder()
                        .proofType(credentialsSupportedResponse.getProofTypesSupported().keySet().stream().findFirst().get())
                        .jwt(jwt)
                        .build())
                .credentialDefinition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponse.getCredentialDefinition().getType())
                        .context(credentialContext)
                        .build())
                .build();
    }

    private SigningAlgorithm resolveAlgorithm(CredentialsSupportedResponse credentialsSupportedResponse) {
        return Optional
                .ofNullable(credentialsSupportedResponse.getProofTypesSupported())
                .map(proofTypesSupported -> proofTypesSupported.get("jwt"))
                .map(ProofTypesSupported::getProofSigningAlgValuesSupported)
                .flatMap(issuerSupportedAlgorithms -> signingAlgorithmConfig.getSigningAlgorithmsPriorityOrder().stream()
                        .filter(priorityAlgorithm -> issuerSupportedAlgorithms.stream().
                                anyMatch(issuerSupportedAlgorithm -> issuerSupportedAlgorithm.equalsIgnoreCase(priorityAlgorithm)))
                        .findFirst())
                .map(SigningAlgorithm::fromString)
                .orElseGet(() -> {
                    log.warn("No matching algorithm found in priority order. Falling back to ED25519");
                    return SigningAlgorithm.ED25519;
                });
    }

    private String generateJwtFromDB(String walletId,
                                     String base64EncodedWalletKey,
                                     SigningAlgorithm algorithm,
                                     CredentialIssuerWellKnownResponse wellKnownResponse,
                                     IssuerDTO issuerDTO,
                                     String cNonce) throws Exception {

        Optional<ProofSigningKey> proofSigningKey = proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name());
        byte[] decodedWalletKey = Base64.getDecoder().decode(base64EncodedWalletKey);
        SecretKey walletKey = EncryptionDecryptionUtil.bytesToSecretKey(decodedWalletKey);
        byte[] publicKeyBytes = Base64.getDecoder().decode(proofSigningKey.get().getPublicKey());
        byte[] privateKeyInBytes = encryptionDecryptionUtil.decryptWithAES(walletKey, proofSigningKey.get().getEncryptedSecretKey());
        KeyPair keyPair = JwtGeneratorUtil.getKeyPairFromDBBasedOnAlgorithm(algorithm, publicKeyBytes, privateKeyInBytes);

        return JwtGeneratorUtil.generateJwt(algorithm,
                wellKnownResponse.getCredentialIssuer(),
                issuerDTO.getClient_id(),
                cNonce,
                keyPair);
    }


}
