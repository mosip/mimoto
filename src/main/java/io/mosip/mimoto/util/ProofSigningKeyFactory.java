package io.mosip.mimoto.util;

import io.mosip.mimoto.dbentity.KeyMetadata;
import io.mosip.mimoto.dbentity.ProofSigningKey;
import io.mosip.mimoto.model.SigningAlgorithm;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

public class ProofSigningKeyFactory {

    public static ProofSigningKey createProofSigningKey(SigningAlgorithm algorithm) throws Exception {
        KeyPair keyPair = KeyGenerationUtil.generateKeyPair(algorithm);

        KeyMetadata keyMetadata = new KeyMetadata();
        keyMetadata.setAlgorithmName(algorithm.name());

        ProofSigningKey proofSigningKey = new ProofSigningKey();
        proofSigningKey.setId(UUID.randomUUID().toString());
        proofSigningKey.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        proofSigningKey.setSecretKey(keyPair.getPrivate());
        proofSigningKey.setKeyMetadata(keyMetadata);
        proofSigningKey.setCreatedAt(Instant.now());
        proofSigningKey.setUpdatedAt(Instant.now());

        return proofSigningKey;
    }
}
