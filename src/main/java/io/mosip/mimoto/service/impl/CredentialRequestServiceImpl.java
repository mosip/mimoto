package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dbentity.ProofSigningKey;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.model.SigningAlgorithm;
import io.mosip.mimoto.repository.ProofSigningKeyRepository;
import io.mosip.mimoto.service.CredentialRequestService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.JwtGeneratorUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class CredentialRequestServiceImpl implements CredentialRequestService {

    @Autowired
    private JoseUtil joseUtil;

    @Autowired
    private ProofSigningKeyRepository proofSigningKeyRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Override
    public VCCredentialRequest buildRequest(IssuerDTO issuerDTO,
                                            CredentialIssuerWellKnownResponse wellKnownResponse,
                                            CredentialsSupportedResponse credentialsSupportedResponse,
                                            String accessToken,
                                            String walletId,
                                            String base64EncodedWalletKey,
                                            Boolean isLoginFlow) throws Exception {

        SigningAlgorithm algorithm = resolveAlgorithm(credentialsSupportedResponse);

        String jwt;
        if (!isLoginFlow) {
            jwt = joseUtil.generateJwt(wellKnownResponse.getCredentialIssuer(), issuerDTO.getClient_id(), accessToken);
        } else {
            jwt = generateJwtFromDB(walletId, base64EncodedWalletKey, algorithm, wellKnownResponse, issuerDTO, accessToken);
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
        Map<String, ProofTypesSupported> proofTypesSupported = credentialsSupportedResponse.getProofTypesSupported();
        if (proofTypesSupported.containsKey("jwt")) {
            return SigningAlgorithm.fromString(proofTypesSupported.get("jwt").getProofSigningAlgValuesSupported().getFirst());
        }
        return SigningAlgorithm.RS256;
    }

    private String generateJwtFromDB(String walletId,
                                     String base64EncodedWalletKey,
                                     SigningAlgorithm algorithm,
                                     CredentialIssuerWellKnownResponse wellKnownResponse,
                                     IssuerDTO issuerDTO,
                                     String accessToken) throws Exception {

        Optional<ProofSigningKey> proofSigningKey = proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name());
        byte[] decodedWalletKey = Base64.getDecoder().decode(base64EncodedWalletKey);
        SecretKey walletKey = EncryptionDecryptionUtil.bytesToSecretKey(decodedWalletKey);
        byte[] publicKeyBytes = Base64.getDecoder().decode(proofSigningKey.get().getPublicKey());
        byte[] privateKeyInBytes = encryptionDecryptionUtil.decryptWithAES(walletKey, proofSigningKey.get().getEncryptedSecretKey());

        return JwtGeneratorUtil.generateJwtUsingDBKeys(algorithm,
                wellKnownResponse.getCredentialIssuer(),
                issuerDTO.getClient_id(),
                accessToken,
                publicKeyBytes,
                privateKeyInBytes);
    }


}
